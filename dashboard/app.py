"""
app.py — Streamlit Dashboard для UEBA-системы
Отображает алерты, графики MSE, статистику угроз.
"""

import os
import sys
import json
from datetime import datetime, timedelta
from pathlib import Path

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

# Добавляем корень проекта в путь
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'ml'))


ALERTS_FILE = PROJECT_ROOT / 'data' / 'alerts.json'
ARTIFACTS_DIR = PROJECT_ROOT / 'ml' / 'artifacts'
METADATA_FILE = ARTIFACTS_DIR / 'metadata.json'

# Цвета для типов угроз
THREAT_COLORS = {
    'Аномальная нагрузка на CPU': '#FF4B4B',
    'Аномальная дисковая активность': '#FFA500',
    'Сканирование портов': '#4B4BFF',
    'Подозрительная аутентификация': '#800080',
    'Массовое создание процессов': '#8B0000',
    'Аномальная исходящая сетевая активность': '#FF6347',
    'Аномальная входящая сетевая активность': '#DC143C',
    'Общая аномалия': '#808080',
}

# ==========================================
# НАСТРОЙКИ СТРАНИЦЫ
# ==========================================
st.set_page_config(
    page_title="UEBA Dashboard — Детектор аномалий",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ==========================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ==========================================

@st.cache_data(ttl=5)  # Кэшируем на 5 секунд
def load_alerts():
    if not ALERTS_FILE.exists():
        return pd.DataFrame()

    try:
        with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                return pd.DataFrame()
            alerts = json.loads(content)
            if not isinstance(alerts, list):
                return pd.DataFrame()

        if not alerts:
            return pd.DataFrame()

        df = pd.DataFrame(alerts)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp', ascending=False).reset_index(drop=True)
        return df

    except (json.JSONDecodeError, Exception) as e:
        st.warning(f"Ошибка чтения файла алертов: {e}")
        return pd.DataFrame()


@st.cache_data(ttl=60)
def load_model_metadata():
    if not METADATA_FILE.exists():
        return None

    try:
        with open(METADATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return None


def get_threat_color(threat_type):
    return THREAT_COLORS.get(threat_type, '#808080')


def format_bytes(bytes_value):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.1f} TB"


# ==========================================
# ЗАГОЛОВОК
# ==========================================

st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #666;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .alert-card {
        background: #fff3cd;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #ffc107;
        margin: 0.5rem 0;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        padding: 10px 20px;
        background-color: #f0f2f6;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="main-header">🛡️ UEBA Security Dashboard</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">User and Entity Behavior Analytics — Система детекции аномалий на основе AutoEncoder</div>',
    unsafe_allow_html=True)

# ==========================================
# БОКОВАЯ ПАНЕЛЬ
# ==========================================

with st.sidebar:
    st.header("⚙️ Управление")

    # Автообновление
    auto_refresh = st.toggle("🔄 Автообновление", value=True)
    refresh_interval = st.slider("Интервал обновления (сек)", 5, 60, 10)

    st.divider()

    # Информация о модели
    st.header("📦 Модель")
    metadata = load_model_metadata()

    if metadata:
        st.metric("Порог аномальности", f"{metadata.get('threshold', 0):.4f}")
        st.metric("Признаков", metadata.get('input_dim', 0))
        trained_at = metadata.get('trained_at', 'N/A')
        if trained_at != 'N/A':
            try:
                trained_dt = datetime.fromisoformat(trained_at)
                st.caption(f"Обучена: {trained_dt.strftime('%d.%m.%Y %H:%M')}")
            except:
                st.caption(f"Обучена: {trained_at}")
    else:
        st.warning("⚠️ Модель не найдена")
        st.caption(f"Ожидалась в: {ARTIFACTS_DIR}")

    st.divider()

    # Кнопка перезагрузки (требование задания!)
    if st.button("🔄 Перезагрузить модель", use_container_width=True):
        st.cache_data.clear()
        st.success("✅ Кэш очищен! Данные перезагружены.")
        st.rerun()

    st.divider()

    # Экспорт
    st.header("💾 Экспорт")
    alerts_df = load_alerts()
    if not alerts_df.empty:
        csv = alerts_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            "📥 Скачать алерты (CSV)",
            csv,
            "ueba_alerts.csv",
            "text/csv",
            use_container_width=True
        )

# ==========================================
# ЗАГРУЗКА ДАННЫХ
# ==========================================

alerts_df = load_alerts()

# ==========================================
# KPI-МЕТРИКИ
# ==========================================

st.subheader("📊 Ключевые показатели")

col1, col2, col3, col4 = st.columns(4)

with col1:
    total_alerts = len(alerts_df)
    st.metric(
        label="🚨 Всего алертов",
        value=total_alerts,
        delta=None
    )

with col2:
    # Алерты за последние 24 часа
    if not alerts_df.empty:
        now = datetime.now()
        alerts_24h = len(alerts_df[alerts_df['timestamp'] > now - timedelta(hours=24)])
    else:
        alerts_24h = 0
    st.metric(
        label="⏰ За последние 24ч",
        value=alerts_24h,
    )

with col3:
    # Самый частый тип угрозы
    if not alerts_df.empty and 'threat_type' in alerts_df.columns:
        top_threat = alerts_df['threat_type'].value_counts().index[0]
        top_count = alerts_df['threat_type'].value_counts().iloc[0]
        st.metric(
            label="🎯 Частая угроза",
            value=top_threat,
            delta=f"{top_count} раз"
        )
    else:
        st.metric(label="🎯 Частая угроза", value="—")

with col4:
    # Статус системы
    if metadata and not alerts_df.empty:
        last_alert = alerts_df['timestamp'].max()
        minutes_ago = (datetime.now() - last_alert).total_seconds() / 60
        if minutes_ago < 30:
            status = "🔴 Активные угрозы"
        elif minutes_ago < 1440:
            status = "🟡 Были угрозы"
        else:
            status = "🟢 Система чиста"
    elif metadata:
        status = "🟢 Мониторинг активен"
    else:
        status = "⚪ Модель не загружена"

    st.metric(label="📡 Статус", value=status)

st.divider()

# ==========================================
# ГРАФИКИ
# ==========================================

tab1, tab2, tab3 = st.tabs(["📈 Временная шкала", "🎯 Типы угроз", "📋 Таблица алертов"])

with tab1:
    st.subheader("Динамика MSE (ошибки реконструкции)")

    if not alerts_df.empty:
        fig = go.Figure()

        # Добавляем epsilon, чтобы избежать log(0)
        eps = 0.01

        # Точки алертов
        fig.add_trace(go.Scatter(
            x=alerts_df['timestamp'],
            y=alerts_df['mse_score'],
            mode='markers+lines',
            name='Алерты',
            marker=dict(
                size=10,
                color=alerts_df['threat_type'].map(get_threat_color),
                line=dict(width=1, color='DarkSlateGrey'),
                sizemode='diameter'
            ),
            text=alerts_df['threat_type'],
            hovertemplate=(
                '<b>%{text}</b><br>'
                'MSE: %{y:.4f}<br>'
                'Время: %{x|%d.%m.%Y %H:%M}'
                '<extra></extra>'
            )
        ))

        # Линия порога
        if metadata:
            threshold = metadata.get('threshold', 0)
            fig.add_hline(
                y=max(threshold, eps),  #Защита от log(0)
                line_dash="dash",
                line_color="red",
                line_width=2,
                annotation_text=f"Порог: {threshold:.4f}",
                annotation_position="top right"
            )

            # Добавляем линию медианного MSE для контекста
            median_mse = alerts_df['mse_score'].median()
            fig.add_hline(
                y=max(median_mse, eps),
                line_dash="dot",
                line_color="green",
                line_width=1,
                annotation_text=f"Медиана: {median_mse:.4f}",
                annotation_position="bottom right"
            )

        # ЛОГАРИФМИЧЕСКАЯ ШКАЛА + настройки осей
        fig.update_layout(
            xaxis_title="Время",
            yaxis_title="MSE (ошибка реконструкции) — лог. шкала",
            yaxis_type="log",
            yaxis_range=[
                np.log10(max(alerts_df['mse_score'].min(), eps)),
                np.log10(alerts_df['mse_score'].max() * 1.2)
            ],
            hovermode='x unified',
            height=450,
            template='plotly_white',
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )

        st.plotly_chart(fig, use_container_width=True)

        # Дополнительная статистика под графиком
        col_s1, col_s2, col_s3, col_s4 = st.columns(4)
        with col_s1:
            st.metric("Мин. MSE", f"{alerts_df['mse_score'].min():.4f}")
        with col_s2:
            st.metric("Медиана MSE", f"{alerts_df['mse_score'].median():.4f}")
        with col_s3:
            st.metric("Макс. MSE", f"{alerts_df['mse_score'].max():.2f}")
        with col_s4:
            if metadata:
                ratio = alerts_df['mse_score'].max() / metadata.get('threshold', 1)
                st.metric("Пиковое превышение порога", f"×{ratio:.0f}")

    else:
        st.info("📭 Алертов пока нет. Запустите monitor.py и дождитесь обнаружения аномалий.")


with tab2:
    st.subheader("Распределение типов угроз")

    if not alerts_df.empty and 'threat_type' in alerts_df.columns:
        col_left, col_right = st.columns([2, 1])

        with col_left:
            threat_counts = alerts_df['threat_type'].value_counts().reset_index()
            threat_counts.columns = ['Тип угрозы', 'Количество']

            fig_pie = px.pie(
                threat_counts,
                values='Количество',
                names='Тип угрозы',
                color='Тип угрозы',
                color_discrete_map=THREAT_COLORS,
                hole=0.4
            )
            fig_pie.update_layout(height=400)
            st.plotly_chart(fig_pie, use_container_width=True)

        with col_right:
            st.markdown("### 📋 Статистика")
            for threat_type, count in alerts_df['threat_type'].value_counts().items():
                color = get_threat_color(threat_type)
                st.markdown(
                    f"<div style='padding: 8px; margin: 4px 0; "
                    f"border-left: 4px solid {color}; "
                    f"background: #f8f9fa; border-radius: 4px;'>"
                    f"<b>{threat_type}</b><br>"
                    f"<span style='font-size: 1.5em; color: {color};'>{count}</span> "
                    f"<span style='color: #666;'>алертов</span></div>",
                    unsafe_allow_html=True
                )

            # Средняя уверенность
            if 'confidence' in alerts_df.columns:
                avg_conf = alerts_df['confidence'].mean()
                st.metric("Средняя уверенность", f"{avg_conf:.0%}")
    else:
        st.info("Нет данных для отображения.")

with tab3:
    st.subheader("Детальная таблица алертов")

    if not alerts_df.empty:
        # Фильтры
        col_f1, col_f2, col_f3 = st.columns(3)

        with col_f1:
            threat_types = ['Все'] + sorted(alerts_df['threat_type'].unique().tolist())
            selected_threat = st.selectbox("🎯 Тип угрозы", threat_types)

        with col_f2:
            min_confidence = st.slider("💯 Мин. уверенность", 0.0, 1.0, 0.0, 0.05)

        with col_f3:
            days_back = st.selectbox("📅 Период", [1, 7, 30, 90], index=1, format_func=lambda x: f"Последние {x} дн.")

        # Применяем фильтры
        filtered_df = alerts_df.copy()

        if selected_threat != 'Все':
            filtered_df = filtered_df[filtered_df['threat_type'] == selected_threat]

        filtered_df = filtered_df[filtered_df['confidence'] >= min_confidence]

        cutoff_date = datetime.now() - timedelta(days=days_back)
        filtered_df = filtered_df[filtered_df['timestamp'] >= cutoff_date]

        st.caption(f"Показано {len(filtered_df)} из {len(alerts_df)} алертов")

        if not filtered_df.empty:
            # Форматируем таблицу
            display_df = filtered_df[[
                'timestamp', 'threat_type', 'confidence', 'mse_score',
                 'description'
            ]].copy()

            display_df['timestamp'] = display_df['timestamp'].dt.strftime('%d.%m.%Y %H:%M')
            display_df['confidence'] = display_df['confidence'].apply(lambda x: f"{x:.0%}")
            display_df['mse_score'] = display_df['mse_score'].apply(lambda x: f"{x:.2f}")
            display_df.columns = ['Время', 'Тип угрозы', 'Уверенность', 'MSE', 'Описание']


            # Подсветка по типам угроз
            def highlight_threat(row):
                color = get_threat_color(row['Тип угрозы'])
                return [f'background-color: {color}20'] * len(row)


            st.dataframe(
                display_df.style.apply(highlight_threat, axis=1),
                use_container_width=True,
                height=400
            )

            # Детали выбранного алерта
            st.divider()
            st.subheader("🔍 Детали алерта")

            selected_idx = st.selectbox(
                "Выберите алерт для просмотра",
                range(len(filtered_df)),
                format_func=lambda
                    i: f"{filtered_df.iloc[i]['timestamp'].strftime('%d.%m %H:%M')} — {filtered_df.iloc[i]['threat_type']}"
            )

            selected_alert = filtered_df.iloc[selected_idx]

            col_d1, col_d2 = st.columns(2)

            with col_d1:
                st.markdown(f"**🎯 Тип угрозы:** {selected_alert['threat_type']}")
                st.markdown(f"**💯 Уверенность:** {selected_alert['confidence']:.0%}")
                st.markdown(f"**📊 MSE:** {selected_alert['mse_score']:.4f}")
                st.markdown(f"**🕐 Время:** {selected_alert['timestamp'].strftime('%d.%m.%Y %H:%M:%S')}")

            with col_d2:
                st.markdown("**📝 Описание:**")
                st.info(selected_alert['description'])

                st.markdown("**💡 Рекомендации:**")
                for rec in selected_alert.get('recommendations', []):
                    st.markdown(f"• {rec}")

            # Топ признаков
            if 'top_features' in selected_alert and selected_alert['top_features']:
                st.markdown("**📊 Значения признаков в момент аномалии:**")
                features = selected_alert['top_features']
                if isinstance(features, dict):
                    feat_df = pd.DataFrame({
                        'Признак': list(features.keys()),
                        'Значение': [f"{v:.2f}" if isinstance(v, (int, float)) else str(v)
                                     for v in features.values()]
                    })
                    st.dataframe(feat_df, use_container_width=True, hide_index=True)
    else:
        st.info("📭 Алертов пока нет.")

# ==========================================
# ФУТЕР
# ==========================================

st.divider()
st.markdown("""
<div style='text-align: center; color: #666; padding: 1rem;'>
    <b>UEBA Security Dashboard</b> 
</div>
""", unsafe_allow_html=True)

# ==========================================
# АВТООБНОВЛЕНИЕ
# ==========================================

if auto_refresh:
    import time

    time.sleep(refresh_interval)
    st.rerun()