"""
calculate_thresholds.py — расчет 90-го перцентиля для признаков из собранных данных.
Эти значения будут использованы как пороги в ThreatClassifier.
"""

import pandas as pd
import glob
import os
import numpy as np

# Путь к папке с агрегированными данными
DATA_DIR = '../UEBA-N/data_collection/data/aggregated'


def main():
    csv_files = glob.glob(os.path.join(DATA_DIR, '*.csv'))

    print(f"Найдено файлов: {len(csv_files)}")

    # Загружаем все данные
    dfs = [pd.read_csv(f) for f in csv_files]
    df = pd.concat(dfs, ignore_index=True)

    print(f"Всего строк для анализа: {len(df)}\n")

    # Список признаков, которые мы используем в классификаторе
    features_to_check = [
        'cpu_avg', 'cpu_max', 'ram_avg', 'ram_max',
        'bytes_sent_avg', 'bytes_recv_avg',
        'unique_dst_ips_count', 'unique_dst_ports_count',
        'active_connections_max', 'process_count_avg',
        'disk_read_bytes_total', 'disk_write_bytes_total',
        'failed_logins', 'successful_logins',
        'process_creations', 'service_installations'
    ]

    # Фильтруем только те колонки, которые реально есть в данных
    available_features = [f for f in features_to_check if f in df.columns]

    print("Расчет 95-го перцентиля (P95) для признаков:")
    print("=" * 70)

    thresholds = {}
    for col in available_features:
        # Считаем 95-й перцентиль
        p90 = df[col].quantile(0.95)

        # Для счетчиков (где 0 - это норма) ставим минимальный порог 1, если 90-й перцентиль равен 0.
        if col in ['failed_logins', 'service_installations', 'process_creations']:
            p90 = max(p90, 1.0)

        thresholds[col] = round(float(p90), 2)
        print(f"{col:<30} : {thresholds[col]:>15.2f}")

    print("=" * 70)

if __name__ == '__main__':
    main()