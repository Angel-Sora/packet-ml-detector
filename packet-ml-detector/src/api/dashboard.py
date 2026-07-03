# Packet ML Detector - ML-based Network Anomaly Detection System
# Copyright (C) 2026 Angel-Sora
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import json
import os
import time

st.set_page_config(
    page_title="Packet ML Detector",
    page_icon="🛡️",
    layout="wide"
)

# Инициализация состояния
if 'last_update' not in st.session_state:
    st.session_state.last_update = time.time()

def load_alerts_from_log():
    """Загружает алерты из лог-файла"""
    try:
        if not os.path.exists('alerts.log'):
            return []
        with open('alerts.log', 'r', encoding='utf-8') as f:
            lines = f.readlines()
            alerts = []
            for line in lines[-200:]:
                try:
                    alerts.append(json.loads(line.strip()))
                except:
                    pass
            return alerts
    except Exception as e:
        return []

def get_packet_count():
    """Получает количество пакетов из лога"""
    alerts = load_alerts_from_log()
    if alerts:
        return max([a.get('anomaly_id', 0) for a in alerts])
    return 0

def main():
    st.title("🛡️ Packet Sniffer + ML Anomaly Detector")
    st.markdown("---")
    
    # Кнопка обновления
    col1, col2 = st.columns([1, 5])
    with col1:
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.session_state.last_update = time.time()
            st.experimental_rerun()  # ← ИСПРАВЛЕНО
    
    with col2:
        st.caption(f"🕐 Обновлено: {time.strftime('%H:%M:%S', time.localtime(st.session_state.last_update))}")
    
    # Загружаем данные
    alerts = load_alerts_from_log()
    total_alerts = len(alerts)
    packet_count = get_packet_count()
    
    # Статистика
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("📦 Всего пакетов", packet_count if packet_count > 0 else "0")
    col2.metric("🚨 Аномалий", total_alerts)
    col3.metric("⚠️ Алертов", total_alerts)
    col4.metric("🟢 Статус", "✅ Активен" if total_alerts > 0 else "⏳ Ожидание")
    
    st.subheader("📈 График аномалий")
    
    if alerts:
        # Создаем DataFrame
        df = pd.DataFrame(alerts)
        df['time'] = pd.to_datetime(df['timestamp'])
        df['packet_len'] = df['packet'].apply(lambda x: x.get('packet_len', 0))
        df['ttl'] = df['packet'].apply(lambda x: x.get('ttl', 0))
        df['protocol'] = df['packet'].apply(lambda x: x.get('protocol', 0))
        df['port'] = df['packet'].apply(lambda x: x.get('src_port', 'N/A'))
        
        # График
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=df['time'],
            y=df['packet_len'],
            mode='markers',
            name='Аномалии',
            marker=dict(
                size=15,
                color='red',
                symbol='x',
                line=dict(width=2, color='darkred')
            ),
            text=[
                f"<b>Пакет #{i+1}</b><br>"
                f"Размер: {row['packet_len']} байт<br>"
                f"TTL: {row['ttl']}<br>"
                f"Протокол: {row['protocol']}<br>"
                f"Порт: {row['port']}"
                for i, row in df.iterrows()
            ],
            hoverinfo='text'
        ))
        
        fig.update_layout(
            title="Обнаруженные аномалии во времени",
            xaxis_title="Время",
            yaxis_title="Размер пакета (байт)",
            height=450,
            hovermode='closest'
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        # Статистика по протоколам
        st.subheader("📊 Статистика по протоколам")
        protocol_counts = df['protocol'].value_counts()
        if not protocol_counts.empty:
            fig2 = go.Figure(data=[go.Pie(
                labels=protocol_counts.index.astype(str),
                values=protocol_counts.values,
                hole=0.3
            )])
            fig2.update_layout(height=300)
            st.plotly_chart(fig2, use_container_width=True)
        
        # Таблица аномалий
        st.subheader("📋 Последние аномалии")
        
        table_data = []
        for alert in alerts[-20:]:
            p = alert.get('packet', {})
            table_data.append({
                '🕐 Время': alert.get('timestamp', ''),
                '📏 Размер': p.get('packet_len', 0),
                '⏳ TTL': p.get('ttl', 0),
                '🔌 Протокол': p.get('protocol', 0),
                '🔢 Порт': p.get('src_port', 'N/A'),
                '# ID': alert.get('anomaly_id', 0)
            })
        
        if table_data:
            st.dataframe(
                pd.DataFrame(table_data),
                use_container_width=True,
                hide_index=True
            )
    else:
        st.info("ℹ️ Аномалий пока не обнаружено")
        st.markdown("""
        ### 📋 Как протестировать:
        1. **Запусти приложение** (кнопка "▶️ Запустить" в GUI)
        2. **Сгенерируй трафик**:
           - Открой сайты в браузере
           - Запусти ping: `ping 127.0.0.1 -n 20`
        3. **Подожди 10-30 секунд**
        4. **Обнови страницу** (F5 или кнопка "Refresh Data")
        
        💡 Аномалии появятся, когда ML-модель обнаружит подозрительный трафик.
        """)
    
    # Лог-файл
    with st.expander("📄 Последние записи из лог-файла"):
        try:
            if os.path.exists('alerts.log'):
                with open('alerts.log', 'r', encoding='utf-8') as f:
                    logs = f.readlines()[-30:]
                    if logs:
                        st.code(''.join(logs), language='json')
                    else:
                        st.info("📭 Лог-файл пуст")
            else:
                st.info("📭 Лог-файл ещё не создан")
        except Exception as e:
            st.error(f"Ошибка чтения лога: {e}")
    
    # Информация о системе
    with st.expander("ℹ️ Информация о системе"):
        st.markdown(f"""
        - **Версия Python**: {os.sys.version.split()[0]}
        - **Лог-файл**: `alerts.log` ({os.path.getsize('alerts.log') if os.path.exists('alerts.log') else 0} байт)
        - **Аномалий в логе**: {total_alerts}
        - **Обновление**: вручную (кнопка "Refresh Data")
        """)

if __name__ == "__main__":
    main()
