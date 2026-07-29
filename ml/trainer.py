"""
это все обучение автоэнкодера смысленое и пощадное
"""

import os
import sys
import glob
import json
import pickle
import argparse
from datetime import datetime
from scipy.stats import mstats

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from model import Autoencoder

# ==============
# 1. КОНФИГУРАЦИЯ
# ==============

# Числовые признаки, которые мы будем использовать для ML
# (отбрасываем timestamp и текстовые колонки)
NUMERIC_FEATURES = [
    'cpu_avg', 'cpu_max', 'ram_avg', 'ram_max',
    'bytes_sent_avg', 'bytes_recv_avg',
    'unique_dst_ips_count', 'unique_dst_ports_count',
    'active_connections_max', 'process_count_avg',
    'disk_read_bytes_total', 'disk_write_bytes_total',
    'failed_logins', 'successful_logins',
    'process_creations', 'service_installations',
    'unique_users_count', 'unique_processes_count'
]

# Гиперпараметры обучения
HYPERPARAMS = {
    'batch_size': 128,
    'learning_rate': 0.0005,
    'epochs': 1000,
    'early_stopping_patience': 50,
    'test_size': 0.2,
    'random_seed': 42,
    'threshold_percentile': 95,  # 95-й перцентиль MSE как порог аномалии
}


# =================
# 2. ЗАГРУЗКА И ПОДГОТОВКА ДАННЫХ
# ===================

# объединяет записанные файлы в один пд.датафрейм
def load_data(data_dir):

    csv_files = glob.glob(os.path.join(data_dir, '*.csv'))
    print(f'кол-во файлов: {len(csv_files)}')


    dfs = []

    for f in csv_files:
        df = pd.read_csv(f)
        dfs.append(df)
        print(f"   {os.path.basename(f)}: {len(df)} строк")

    data = pd.concat(dfs, ignore_index=True)
    data = data.sort_values('timestamp').reset_index(drop=True)

    print(f"\n Всего строк: {len(data)}")
    return data

# получает на вход объединенный датафрейм
# очищает его удаляет выбросы,
def preprocess_data(data):

    available_features = NUMERIC_FEATURES
    X = data[available_features].copy()
    X = X.fillna(0)
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    initial_rows = len(X)

    # УДАЛЕНИЕ ЭКСТРЕМАЛЬНЫХ ВЫБРОСОВ
    # Удаляем строки, где хотя бы один признак > 99.5 перцентиля
    mask = pd.Series([True] * len(X), index=X.index)
    for col in X.columns:
        threshold = np.percentile(X[col], 99.5)
        mask = mask & (X[col] <= threshold)

    X_clean = X[mask]
    removed = initial_rows - len(X_clean)

    print(f"Удалено {removed} строк с экстремальными значениями")
    print(f"Осталось: {len(X_clean)} строк")
    return X_clean, available_features


#на вход идет очищенный датафрейм
#тут происходит нормализация с помощью Robust Scaler, функция возвращает обученный
#нормализатор, и нормализванный датасет, разбитый на трейн и вал
def normalize_data(X, test_size=0.2, random_seed=42):


    X_train, X_val = train_test_split(
        X, test_size=test_size, random_state=random_seed, shuffle=True
    )

    print(f"\n Train: {len(X_train)} строк, Validation: {len(X_val)} строк")

    # Обучаем скейлер только на train чтобы, не подсматривать в validation
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    print("Нормализация сделана")

    return X_train_scaled, X_val_scaled, scaler


# ==========================================
# 3. ОБУЧЕНИЕ МОДЕЛИ
# ==========================================


#трейн луп и тд
def train_model(X_train, X_val, input_dim, hyperparams, device):

    print(f"\n НАЧИНАЕМ УЧЕБУ")
    print(f"   Размерность входа: {input_dim}")
    print(f"   Устройство: {device}")
    print(f"   Эпох: {hyperparams['epochs']}")
    print(f"   Learning rate: {hyperparams['learning_rate']}")
    print(f"   Batch size: {hyperparams['batch_size']}")

    # Создаем модель
    model = Autoencoder(input_dim).to(device)
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=hyperparams['learning_rate'])

    # DataLoader для батчевой загрузки
    train_dataset = TensorDataset(
        torch.FloatTensor(X_train).to(device)
    )
    train_loader = DataLoader(
        train_dataset,
        batch_size=hyperparams['batch_size'],
        shuffle=True
    )

    # Early stopping
    best_val_loss = 999999
    patience_counter = 0
    best_model_state = None

    train_losses = []
    val_losses = []

    for epoch in range(hyperparams['epochs']):

        model.train()
        epoch_train_loss = 0.0

        for batch in train_loader:
            x = batch[0]

            optimizer.zero_grad()
            output = model(x)
            loss = criterion(output, x)
            loss.backward()
            optimizer.step()

            epoch_train_loss += loss.item() * x.size(0)

        epoch_train_loss /= len(train_dataset)
        train_losses.append(epoch_train_loss)

        #валидация
        model.eval()
        with torch.no_grad():
            x_val = torch.FloatTensor(X_val).to(device)
            val_output = model(x_val)
            val_loss = criterion(val_output, x_val).item()

        val_losses.append(val_loss)

        # Early stopping
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            best_model_state = model.state_dict().copy()
        else:
            patience_counter += 1

        # каждые 10 эпох пишем текст
        if (epoch + 1) % 10 == 0 or epoch == 0:
            print(f"   Эпоха {epoch + 1:3d}/{hyperparams['epochs']} | "
                  f"Train Loss: {epoch_train_loss:.6f} | "
                  f"Val Loss: {val_loss:.6f} | "
                  f"Best: {best_val_loss:.6f}")

        if patience_counter >= hyperparams['early_stopping_patience']:
            print(f"\n⏹ Early stopping на эпохе {epoch + 1}")
            break

    # Восстанавливаем лучшую модель
    model.load_state_dict(best_model_state)

    print(f"\n Обучение завершено. Лучший Val Loss: {best_val_loss:.6f}")

    return model, train_losses, val_losses


# ==========================================
# 4. ВЫЧИСЛЕНИЕ ПОРОГА АНОМАЛЬНОСТИ
# ==========================================

def compute_threshold(model, X_val, device, percentile=95, scaler=None, features=None):
    model.eval()
    with torch.no_grad():
        x_val = torch.FloatTensor(X_val).to(device)
        output = model(x_val)
        mse_per_sample = ((x_val - output) ** 2).mean(dim=1).cpu().numpy()


    median_mse = np.median(mse_per_sample)
    threshold_percentile = np.percentile(mse_per_sample, percentile)

    print(f"\n Пороги аномальности:")
    print(f"   Median MSE: {median_mse:.4f}")
    print(f"   Percentile-based порог ({percentile}%): {threshold_percentile:.4f}")
    print(f"   Min MSE: {mse_per_sample.min():.4f}")
    print(f"   Max MSE: {mse_per_sample.max():.4f}")

    # Счетчик выбросов


    if scaler is not None and features is not None:
        extreme_mask = mse_per_sample > threshold_percentile
        extreme_indices = np.where(extreme_mask)[0]
        print(f"\n Примеров выше порога: {len(extreme_indices)}")

    return threshold_percentile, mse_per_sample

# ==========================================
# 5. ВИЗУАЛИЗАЦИЯ
# ==========================================

def plot_results(train_losses, val_losses, mse_per_sample, threshold, output_dir):

    #Рисуем картинки

    os.makedirs(output_dir, exist_ok=True)

    # График 1: Loss при обучении
    plt.figure(figsize=(12, 5))

    plt.subplot(1, 2, 1)
    plt.plot(train_losses, label='Train Loss', color='blue')
    plt.plot(val_losses, label='Validation Loss', color='orange')
    plt.xlabel('Epoch')
    plt.ylabel('MSE Loss')
    plt.title('Динамика обучения автоэнкодера')
    plt.legend()
    plt.grid(True, alpha=0.3)

    # График 2: Распределение MSE на валидации
    plt.subplot(1, 2, 2)
    plt.hist(mse_per_sample, bins=50, color='skyblue', edgecolor='black', alpha=0.7, log = True)
    plt.axvline(threshold, color='red', linestyle='--', linewidth=2,
                label=f'Threshold ({threshold:.4f})')
    plt.xlabel('MSE (ошибка реконструкции)')
    plt.ylabel('Количество примеров')
    plt.title('Распределение MSE на валидации')
    plt.legend()
    plt.grid(True, alpha=0.3)

    plt.tight_layout()
    plot_path = os.path.join(output_dir, 'training_results.png')
    plt.savefig(plot_path, dpi=150, bbox_inches='tight')
    plt.close()

    print(f"Графики сохранены: {plot_path}")


# ==========================================
# 6. СОХРАНЕНИЕ АРТЕФАКТОВ
# ==========================================

def save_artifacts(model, scaler, threshold, features, hyperparams,
                   artifacts_dir, p95_values):

    os.makedirs(artifacts_dir, exist_ok=True)

    # 1. Модель
    model_path = os.path.join(artifacts_dir, 'autoencoder.pth')
    torch.save(model.state_dict(), model_path)
    print(f"Модель сохранена: {model_path}")

    # 2. Скейлер
    scaler_path = os.path.join(artifacts_dir, 'scaler.pkl')
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"Скейлер сохранен: {scaler_path}")

    # 3. Метаданные (теперь с p95_values)
    metadata = {
        'threshold': float(threshold),
        'features': features,
        'input_dim': len(features),
        'hyperparams': hyperparams,
        'trained_at': datetime.now().isoformat(),
        'p95_values': p95_values,
    }
    metadata_path = os.path.join(artifacts_dir, 'metadata.json')
    with open(metadata_path, 'w', encoding='utf-8') as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)
    print(f"Метаданные сохранены: {metadata_path}")

    return metadata

# ==========================================
# 7. MAIN
# ==========================================

def main():

    # Определяем устройство
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f" Устройство: {device}")

    # Устанавливаем seed для воспроизводимости
    torch.manual_seed(HYPERPARAMS['random_seed'])
    np.random.seed(HYPERPARAMS['random_seed'])

    #  Загрузка данных
    print("\n" + "=" * 50)
    print("ШАГ 1: Загрузка данных")
    print("=" * 50)
    data = load_data('data_collection/data/aggregated')

    #  Предобработка
    print("\n" + "=" * 50)
    print("ШАГ 2: Предобработка")
    print("=" * 50)
    X, features = preprocess_data(data)


    # Нормализация
    print("\n" + "=" * 50)
    print("ШАГ 3: Нормализация")
    print("=" * 50)
    X_train, X_val, scaler = normalize_data(
        X,
        test_size=HYPERPARAMS['test_size'],
        random_seed=HYPERPARAMS['random_seed']
    )

    #Обучение
    print("\n" + "=" * 50)
    print("ШАГ 4: Обучение")
    print("=" * 50)
    model, train_losses, val_losses = train_model(
        X_train, X_val,
        input_dim=len(features),
        hyperparams=HYPERPARAMS,
        device=device
    )

    #  Вычисление порога
    print("\n" + "=" * 50)
    print("ШАГ 5: Вычисление порога аномальности")
    print("=" * 50)
    threshold, mse_per_sample = compute_threshold(
        model, X_val, device,
        percentile=HYPERPARAMS['threshold_percentile'],
        scaler=scaler,
        features=features
    )
    # ШАГ 5.5: Расчет P95 для классификатора
    print("\n" + "=" * 50)
    print("ШАГ 5.5: Расчет P95 для классификатора угроз")
    print("=" * 50)

    # Берем оригинальные данные
    X_val_original = scaler.inverse_transform(X_val)
    p95_values = {}

    for i, feat in enumerate(features):
        p95_val = float(np.percentile(X_val_original[:, i], 95))

        if p95_val <= 0:
            p95_val = 1.0
            print(f"   {feat:<30} : P95 был 0, установлен минимум = 1.0")
        else:
            print(f"   {feat:<30} : P95 = {p95_val:>15.2f}")

        p95_values[feat] = p95_val

    # Визуализация
    print("\n" + "=" * 50)
    print("ШАГ 6: Визуализация")
    print("=" * 50)
    plot_results(train_losses, val_losses, mse_per_sample, threshold, args.artifacts_dir)

    # Сохранение
    print("\n" + "=" * 50)
    print("ШАГ 7: Сохранение артефактов")
    print("=" * 50)
    save_artifacts(
        model, scaler, threshold, features, HYPERPARAMS,
        args.artifacts_dir,
        p95_values=p95_values
    )

    #ИТОГ
    print("\n" + "=" * 50)
    print("ОБУЧЕНИЕ ЗАВЕРШЕНО")
    print("=" * 50)
    print(f"   Порог аномальности: {threshold:.6f}")
    print(f"   Использовано признаков: {len(features)}")
    print(f"   Обучено на: {len(X_train)} примерах")
    print(f"   Артефакты сохранены в: {args.artifacts_dir}")


if __name__ == '__main__':
    main()