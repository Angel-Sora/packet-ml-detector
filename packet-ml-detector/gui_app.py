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
#!/usr/bin/env python3
"""
Packet ML Detector - GUI Application (Full Version with Cleanup)
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
import webbrowser

class PacketMLApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Packet ML Detector")
        self.root.geometry("950x750")
        self.root.resizable(True, True)
        
        self.running = False
        self.training = False
        self.packet_count = 0
        self.anomaly_count = 0
        self.start_time = None
        self.sniffer_thread = None
        self.training_thread = None
        self.dashboard_process = None
        self.update_id = None
        
        # Цвета
        self.colors = {
            'bg': '#1e1e2e',
            'fg': '#cdd6f4',
            'accent': '#89b4fa',
            'success': '#a6e3a1',
            'danger': '#f38ba8',
            'warning': '#f9e2af',
            'purple': '#cba6f7',
            'orange': '#fab387'
        }
        
        self.setup_ui()
        self.load_config()
        self.check_model()
        self.log("🔄 Приложение запущено")
        self.log("💡 Нажми 'Обучение' для создания модели, затем 'Запустить'")
        
    def setup_ui(self):
        # Стиль
        style = ttk.Style()
        style.theme_use('clam')
        
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Заголовок
        title = tk.Label(
            main_frame,
            text="🛡️ Packet ML Detector",
            font=('Arial', 22, 'bold'),
            fg=self.colors['accent']
        )
        title.pack(pady=10)
        
        # Статистика
        stats_frame = ttk.LabelFrame(main_frame, text="📊 Статистика", padding=10)
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.stats_vars = {}
        stats = [
            ("📦 Пакетов", "packets", "0"),
            ("🚨 Аномалий", "anomalies", "0"),
            ("⚠️ Алертов", "alerts", "0"),
            ("⏱️ Время", "time", "00:00:00"),
            ("🧠 Модель", "model_status", "❌ Не обучена")
        ]
        
        for i, (label, key, default) in enumerate(stats):
            frame = tk.Frame(stats_frame)
            row = i // 3
            col = i % 3
            frame.grid(row=row, column=col, padx=20, pady=5, sticky='w')
            
            tk.Label(frame, text=label, font=('Arial', 11)).pack(side=tk.LEFT)
            self.stats_vars[key] = tk.StringVar(value=default)
            tk.Label(
                frame,
                textvariable=self.stats_vars[key],
                font=('Arial', 13, 'bold'),
                fg=self.colors['accent']
            ).pack(side=tk.LEFT, padx=10)
        
        # Панель управления
        control_frame = ttk.LabelFrame(main_frame, text="🎮 Управление", padding=10)
        control_frame.pack(fill=tk.X, pady=10)
        
        # Верхний ряд кнопок
        btn_frame1 = tk.Frame(control_frame)
        btn_frame1.pack(fill=tk.X, pady=5)
        
        self.btn_train = tk.Button(
            btn_frame1,
            text="🧠 Обучение модели",
            command=self.start_training,
            bg=self.colors['purple'],
            font=('Arial', 11, 'bold'),
            padx=20,
            pady=8,
            width=18
        )
        self.btn_train.pack(side=tk.LEFT, padx=5)
        
        self.btn_start = tk.Button(
            btn_frame1,
            text="▶️ Запустить сниффер",
            command=self.start_app,
            bg=self.colors['success'],
            font=('Arial', 11, 'bold'),
            padx=20,
            pady=8,
            width=18
        )
        self.btn_start.pack(side=tk.LEFT, padx=5)
        
        self.btn_stop = tk.Button(
            btn_frame1,
            text="⏹️ Остановить",
            command=self.stop_app,
            bg=self.colors['danger'],
            font=('Arial', 11, 'bold'),
            padx=20,
            pady=8,
            width=18,
            state=tk.DISABLED
        )
        self.btn_stop.pack(side=tk.LEFT, padx=5)
        
        # Нижний ряд кнопок
        btn_frame2 = tk.Frame(control_frame)
        btn_frame2.pack(fill=tk.X, pady=5)
        
        tk.Button(
            btn_frame2,
            text="🧹 Очистить логи",
            command=self.clear_logs,
            bg=self.colors['warning'],
            font=('Arial', 10),
            padx=15,
            pady=6,
            width=18
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            btn_frame2,
            text="🧹 Полная очистка",
            command=self.clean_all,
            bg=self.colors['orange'],
            font=('Arial', 10),
            padx=15,
            pady=6,
            width=18
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            btn_frame2,
            text="🌐 Открыть дашборд",
            command=self.open_dashboard,
            bg=self.colors['accent'],
            font=('Arial', 10),
            padx=15,
            pady=6,
            width=18
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            btn_frame2,
            text="⚙️ Настройки интерфейса",
            command=self.show_interface_settings,
            bg='#a6adc8',
            font=('Arial', 10),
            padx=15,
            pady=6,
            width=18
        ).pack(side=tk.LEFT, padx=5)
        
        # Консоль
        log_frame = ttk.LabelFrame(main_frame, text="📝 Консоль", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=15,
            bg='#1a1a2e',
            fg=self.colors['fg'],
            font=('Consolas', 10),
            wrap=tk.WORD
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Статус бар
        self.status_var = tk.StringVar(value="✅ Готов к работе")
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W,
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            font=('Arial', 9)
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def load_config(self):
        try:
            with open('config.json', 'r', encoding='utf-8') as f:
                self.config = json.load(f)
            self.log("✅ Конфигурация загружена")
        except:
            self.log("⚠️ Конфиг не найден, создаю...")
            self.config = {
                "interface": "eth0",
                "packet_limit": 1000,
                "ml": {
                    "contamination": 0.01,
                    "features": ["packet_len", "ttl", "tcp_win", "payload_size", "ip_frag", "ip_len"]
                },
                "alerts": {
                    "log_file": "alerts.log"
                }
            }
            with open('config.json', 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4)
            self.log("✅ Создан config.json")
    
    def check_model(self):
        if os.path.exists("models/anomaly_detector.pkl"):
            self.stats_vars['model_status'].set("✅ Обучена")
            self.log("✅ Модель найдена")
            return True
        else:
            self.stats_vars['model_status'].set("❌ Не обучена")
            self.log("⚠️ Модель не найдена. Нажмите 'Обучение модели'")
            return False
    
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def clean_all(self):
        """Полная очистка проекта из интерфейса"""
        if not messagebox.askyesno(
            "Подтверждение",
            "Очистить все логи и кэш?\n\n"
            "Будут удалены:\n"
            "• Все __pycache__ папки\n"
            "• Все .pyc файлы\n"
            "• alerts.log\n"
            "• Кэш Streamlit\n\n"
            "Модель сохранится!"
        ):
            return
        
        self.log("🧹 Начинаю полную очистку...")
        self.status_var.set("🧹 Идёт очистка...")
        deleted = 0
        
        # 1. Удаляем __pycache__
        for root, dirs, files in os.walk('.'):
            if '__pycache__' in dirs:
                path = os.path.join(root, '__pycache__')
                try:
                    shutil.rmtree(path)
                    self.log(f"🗑️ Удалено: {path}")
                    deleted += 1
                except Exception as e:
                    self.log(f"❌ Ошибка: {path} - {e}")
        
        # 2. Удаляем .pyc файлы
        for root, dirs, files in os.walk('.'):
            for file in files:
                if file.endswith('.pyc') or file.endswith('.pyo'):
                    path = os.path.join(root, file)
                    try:
                        os.remove(path)
                        self.log(f"🗑️ Удалён: {path}")
                        deleted += 1
                    except Exception as e:
                        self.log(f"❌ Ошибка: {path} - {e}")
        
        # 3. Очищаем alerts.log
        try:
            with open('alerts.log', 'w', encoding='utf-8') as f:
                f.write('')
            self.log("🧹 Очищен alerts.log")
            self.stats_vars['alerts'].set("0")
            self.anomaly_count = 0
            self.stats_vars['anomalies'].set("0")
            deleted += 1
        except Exception as e:
            self.log(f"❌ Ошибка очистки alerts.log: {e}")
        
        # 4. Очищаем кэш Streamlit
        try:
            streamlit_cache = os.path.expanduser('~/.cache/streamlit')
            if os.path.exists(streamlit_cache):
                shutil.rmtree(streamlit_cache)
                self.log("🗑️ Удалён кэш Streamlit")
                deleted += 1
        except Exception as e:
            self.log(f"⚠️ Не удалось очистить кэш Streamlit: {e}")
        
        self.log(f"✅ Очистка завершена! Удалено/очищено объектов: {deleted}")
        self.status_var.set(f"🧹 Очищено {deleted} объектов")
        
        messagebox.showinfo(
            "✅ Готово",
            f"Очистка завершена!\n\nУдалено/очищено объектов: {deleted}\n\n"
            "Рекомендуется перезапустить приложение."
        )
    
    def start_training(self):
        if self.training:
            self.log("⚠️ Обучение уже запущено")
            return
        
        if not self.check_interface():
            return
        
        self.training = True
        self.btn_train.config(state=tk.DISABLED, text="⏳ Обучение...")
        self.status_var.set("🔄 Идёт обучение модели...")
        
        self.training_thread = threading.Thread(target=self.run_training, daemon=True)
        self.training_thread.start()
    
    def run_training(self):
        try:
            self.log("🧠 Начинаю сбор трафика для обучения...")
            self.log("💡 Пожалуйста, создайте активность в интернете (откройте сайты)")
            
            # Импортируем модули
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from src.sniffer.capture import PacketSniffer
            from src.ml.trainer import AnomalyDetector
            
            # Собираем трафик
            duration = 30
            interface = self.config.get('interface', 'eth0')
            
            sniffer = PacketSniffer(interface=interface)
            sniffer.start()
            
            for i in range(duration, 0, -1):
                self.log(f"⏳ Сбор трафика: {i} сек осталось")
                self.status_var.set(f"⏳ Сбор трафика: {i} сек")
                time.sleep(1)
            
            sniffer.stop()
            packets = sniffer.get_buffer()
            
            self.log(f"✅ Собрано {len(packets)} пакетов")
            
            if len(packets) < 100:
                self.log("❌ Слишком мало пакетов! Нужно минимум 100")
                self.log("💡 Увеличьте активность в интернете или duration в коде")
                self.training = False
                self.btn_train.config(state=tk.NORMAL, text="🧠 Обучение модели")
                self.status_var.set("❌ Мало данных")
                return
            
            # Обучаем модель
            self.log("🧠 Обучение модели...")
            detector = AnomalyDetector()
            detector.train(packets, contamination=self.config['ml']['contamination'])
            
            # Создаём папку если нет
            os.makedirs("models", exist_ok=True)
            detector.save("models/anomaly_detector.pkl")
            
            self.log("✅ Модель успешно сохранена в models/anomaly_detector.pkl")
            self.log(f"📊 Обучено на {len(packets)} пакетов")
            self.stats_vars['model_status'].set("✅ Обучена")
            self.status_var.set("✅ Модель обучена")
            
            messagebox.showinfo(
                "✅ Успех",
                f"Модель обучена на {len(packets)} пакетах!\n"
                f"Теперь можно запускать сниффер."
            )
            
        except Exception as e:
            self.log(f"❌ Ошибка обучения: {e}")
            self.status_var.set("❌ Ошибка обучения")
            messagebox.showerror("Ошибка", f"Не удалось обучить модель:\n{str(e)}")
        finally:
            self.training = False
            self.btn_train.config(state=tk.NORMAL, text="🧠 Обучение модели")
    
    def start_app(self):
        if self.running:
            self.log("⚠️ Сниффер уже запущен")
            return
        
        if not self.check_model():
            self.log("⚠️ Сначала обучите модель!")
            messagebox.showwarning(
                "Модель не найдена",
                "Сначала обучите модель, нажав кнопку 'Обучение модели'"
            )
            return
        
        if not self.check_interface():
            return
        
        self.log("🚀 Запуск сниффера...")
        self.running = True
        self.packet_count = 0
        self.anomaly_count = 0
        self.start_time = time.time()
        
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_train.config(state=tk.DISABLED)
        self.status_var.set("🔄 Запуск...")
        
        # Запуск сниффера
        self.sniffer_thread = threading.Thread(target=self.run_sniffer, daemon=True)
        self.sniffer_thread.start()
        
        # Обновление статистики
        self.update_stats()
        
        # Запуск дашборда
        self.start_dashboard()
        
        self.log("✅ Сниффер запущен")
        self.status_var.set("✅ Работает")
    
    def check_interface(self):
        interface = self.config.get('interface', 'eth0')
        if interface == 'eth0' and sys.platform == 'win32':
            self.log("⚠️ На Windows используйте интерфейс вида '\\Device\\NPF_{GUID}'")
            self.log("💡 Запустите 'ipconfig' чтобы узнать GUID")
            return False
        return True
    
    def run_sniffer(self):
        try:
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            from src.sniffer.capture import PacketSniffer
            from src.ml.trainer import AnomalyDetector
            
            detector = AnomalyDetector()
            detector.load("models/anomaly_detector.pkl")
            self.log("✅ Модель загружена")
            
            interface = self.config.get('interface', 'eth0')
            sniffer = PacketSniffer(interface=interface)
            
            def on_packet(packet):
                self.packet_count += 1
                if self.packet_count % 10 == 0:
                    self.stats_vars['packets'].set(str(self.packet_count))
                
                if detector.model is not None:
                    try:
                        pred = detector.predict(packet)
                        if pred == -1:
                            self.anomaly_count += 1
                            self.stats_vars['anomalies'].set(str(self.anomaly_count))
                            alert_data = {
                                'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                                'packet': packet,
                                'anomaly_id': self.anomaly_count
                            }
                            # Записываем в лог
                            with open('alerts.log', 'a', encoding='utf-8') as f:
                                f.write(json.dumps(alert_data) + '\n')
                            
                            # Показываем в консоли
                            self.log(f"🚨 Аномалия #{self.anomaly_count} | Размер: {packet.get('packet_len', 0)} байт")
                    except Exception as e:
                        pass  # Тихая обработка ошибок
            
            sniffer.register_callback(on_packet)
            sniffer.start()
            self.log(f"✅ Сниффер запущен на интерфейсе {interface}")
            
            while self.running:
                time.sleep(1)
                
            sniffer.stop()
            self.log("⏹️ Сниффер остановлен")
            
        except Exception as e:
            self.log(f"❌ Ошибка сниффера: {e}")
            self.running = False
            self.btn_start.config(state=tk.NORMAL)
            self.btn_stop.config(state=tk.DISABLED)
            self.btn_train.config(state=tk.NORMAL)
            self.status_var.set("❌ Ошибка")
    
    def start_dashboard(self):
        """Запуск дашборда в отдельном процессе"""
        try:
            # Закрываем старый процесс если есть
            if self.dashboard_process:
                try:
                    self.dashboard_process.terminate()
                except:
                    pass
                self.dashboard_process = None
            
            # Запускаем с параметрами для отдельного окна
            self.dashboard_process = subprocess.Popen(
                [sys.executable, "-m", "streamlit", "run", "src/api/dashboard.py", 
                 "--server.port=8501",
                 "--server.headless=true",
                 "--server.enableCORS=false",
                 "--browser.gatherUsageStats=false"],
                creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            self.log("✅ Дашборд запущен в отдельном окне")
            self.log("🌐 Откройте http://localhost:8501 в браузере")
            self.status_var.set("✅ Дашборд запущен")
            
            # Автоматически открываем в браузере через 2 секунды
            self.root.after(2000, self.open_dashboard)
            
        except Exception as e:
            self.log(f"⚠️ Ошибка запуска дашборда: {e}")
            self.status_var.set("❌ Ошибка дашборда")
    
    def open_dashboard(self):
        """Открывает дашборд в браузере"""
        try:
            webbrowser.open("http://localhost:8501")
            self.log("🌐 Открыт дашборд в браузере")
        except Exception as e:
            self.log(f"⚠️ Не удалось открыть браузер: {e}")
    
    def stop_app(self):
        if not self.running:
            self.log("⚠️ Сниффер уже остановлен")
            return
        
        self.log("⏹️ Остановка сниффера...")
        self.running = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.btn_train.config(state=tk.NORMAL)
        self.status_var.set("⏹️ Остановлен")
        
        if self.dashboard_process:
            try:
                self.dashboard_process.terminate()
                self.dashboard_process = None
            except:
                pass
        
        if self.update_id:
            self.root.after_cancel(self.update_id)
            self.update_id = None
        
        self.log("✅ Сниффер остановлен")
    
    def clear_logs(self):
        try:
            with open('alerts.log', 'w', encoding='utf-8') as f:
                f.write('')
            self.log("🧹 Логи очищены")
            self.stats_vars['alerts'].set("0")
            self.anomaly_count = 0
            self.stats_vars['anomalies'].set("0")
            messagebox.showinfo("Готово", "Логи очищены!")
        except Exception as e:
            self.log(f"⚠️ Не удалось очистить логи: {e}")
            messagebox.showerror("Ошибка", f"Не удалось очистить логи:\n{str(e)}")
    
    def show_interface_settings(self):
        """Диалог для изменения интерфейса"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Настройки интерфейса")
        dialog.geometry("450x250")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Заголовок
        tk.Label(
            dialog,
            text="Настройка сетевого интерфейса",
            font=('Arial', 13, 'bold'),
            fg=self.colors['accent']
        ).pack(pady=15)
        
        # Поле ввода
        tk.Label(dialog, text="Интерфейс для захвата:", font=('Arial', 11)).pack(pady=5)
        
        current_interface = self.config.get('interface', 'eth0')
        entry = tk.Entry(dialog, width=40, font=('Arial', 10))
        entry.insert(0, current_interface)
        entry.pack(pady=10)
        
        # Подсказка
        help_frame = tk.Frame(dialog, bg='#2a2a3e')
        help_frame.pack(pady=5, padx=20, fill=tk.X)
        
        tk.Label(
            help_frame, 
            text="💡 Подсказки:",
            font=('Arial', 9, 'bold'),
            bg='#2a2a3e',
            fg=self.colors['warning']
        ).pack(anchor=tk.W, padx=5, pady=2)
        
        tk.Label(
            help_frame,
            text="• Windows: \\Device\\NPF_{GUID}\n• Linux: eth0, wlan0, etc.\n• Mac: en0, en1, etc.",
            font=('Arial', 9),
            bg='#2a2a3e',
            fg=self.colors['fg'],
            justify=tk.LEFT
        ).pack(anchor=tk.W, padx=15, pady=5)
        
        # Кнопки
        btn_frame = tk.Frame(dialog)
        btn_frame.pack(pady=20)
        
        def save_interface():
            new_interface = entry.get().strip()
            if new_interface:
                self.config['interface'] = new_interface
                with open('config.json', 'w', encoding='utf-8') as f:
                    json.dump(self.config, f, indent=4)
                self.log(f"✅ Интерфейс изменён на: {new_interface}")
                self.status_var.set(f"✅ Интерфейс: {new_interface}")
                dialog.destroy()
                messagebox.showinfo("Готово", f"Интерфейс сохранён:\n{new_interface}")
        
        tk.Button(
            btn_frame,
            text="💾 Сохранить",
            command=save_interface,
            bg=self.colors['accent'],
            font=('Arial', 10, 'bold'),
            padx=20,
            pady=8
        ).pack(side=tk.LEFT, padx=10)
        
        tk.Button(
            btn_frame,
            text="❌ Отмена",
            command=dialog.destroy,
            bg='#6c7086',
            font=('Arial', 10),
            padx=20,
            pady=8
        ).pack(side=tk.LEFT, padx=10)
    
    def update_stats(self):
        if not self.running:
            return
        
        if self.start_time:
            elapsed = int(time.time() - self.start_time)
            hours = elapsed // 3600
            minutes = (elapsed % 3600) // 60
            seconds = elapsed % 60
            self.stats_vars['time'].set(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        
        try:
            with open('alerts.log', 'r', encoding='utf-8') as f:
                alerts = len(f.readlines())
                self.stats_vars['alerts'].set(str(alerts))
        except:
            pass
        
        self.update_id = self.root.after(1000, self.update_stats)
    
    def on_closing(self):
        """Обработка закрытия окна"""
        if self.running:
            if messagebox.askyesno("Подтверждение", "Остановить сниффер и выйти?"):
                self.stop_app()
                self.root.destroy()
        else:
            self.root.destroy()

def main():
    root = tk.Tk()
    app = PacketMLApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
