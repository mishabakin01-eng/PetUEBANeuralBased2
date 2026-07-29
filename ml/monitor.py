
#непрерывный мониторинг и детекция аномалий в реальном времени

import ctypes
import os
import sys
import json
import pickle
import time
from datetime import datetime

import numpy as np
import pandas as pd
import psutil
import torch


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from threat_classifier import ThreatClassifier

#  админский доступ для чтения журнала безопастности Windows
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        print("Запрашиваем права администратора...")
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()

class AnomalyMonitor:
    def __init__(self, artifacts_dir='ml/artifacts', alerts_dir='data',
                 monitoring_window_minutes=10, confirmation_windows=2,
                 cooldown_seconds=600):
        self.artifacts_dir = artifacts_dir                          #директория с артефактами
        self.alerts_dir = alerts_dir                                #директория с алертами
        self.monitoring_window_minutes = monitoring_window_minutes  #размер окна мониторинга
        self.confirmation_windows = confirmation_windows            #количество окон, с подозрительными данными необходимых для создания алерта
        self.cooldown_seconds = cooldown_seconds                    #алерт не чаще чем


        # Атрибуты модели
        self.model = None
        self.scaler = None
        self.threshold = None
        self.features = None
        self.device = None
        self.classifier = None


        self._load_artifacts()
        self.minute_aggregates = []

        # Буфер для сбора сырых данных
        self.buffer = {
            'cpu_percent': [],
            'ram_percent': [],
            'bytes_sent': [],
            'bytes_recv': [],
            'unique_dst_ips': set(),
            'unique_dst_ports': set(),
            'active_connections': 0,
            'process_count': 0,
            'disk_read_bytes': 0,
            'disk_write_bytes': 0,
            'failed_logins': 0,
            'successful_logins': 0,
            'process_creations': 0,
            'service_installations': 0,
            'timestamp': None
        }

        self.last_network_counters = psutil.net_io_counters()
        self.last_disk_counters = psutil.disk_io_counters()
        self.last_time = time.time()
        self.last_minute_aggregation = time.time()
        self.last_eventlog_read = time.time()
        # Атрибуты для подтверждения аномалии
        self.consecutive_anomalies = 0
        self.last_alert_time = 0
        self.mse_history = []

        # Создаем папку для алертов
        os.makedirs(self.alerts_dir, exist_ok=True)
        self.alerts_file = os.path.join(self.alerts_dir, 'alerts.json')

        if not os.path.exists(self.alerts_file):
            with open(self.alerts_file, 'w', encoding='utf-8') as f:
                json.dump([], f)

    #Загружает модель, скейлер и метаданные с диска
    def _load_artifacts(self):

        print("Загрузка артефактов...")

        model_path = os.path.join(self.artifacts_dir, 'autoencoder.pth')
        metadata_path = os.path.join(self.artifacts_dir, 'metadata.json')
        scaler_path = os.path.join(self.artifacts_dir, 'scaler.pkl')

        # Загружаем метаданные
        with open(metadata_path, 'r', encoding='utf-8') as f:
            metadata = json.load(f)

        self.threshold = metadata['threshold']
        self.features = metadata['features']
        input_dim = metadata['input_dim']


        p95_values = metadata.get('p95_values', {})

        print(f"   ✓ Порог аномальности: {self.threshold:.4f}")
        print(f"   ✓ Признаков: {len(self.features)}")
        print(f"   ✓ P95 значений загружено: {len(p95_values)}")

        # Загружаем модель
        from model import Autoencoder
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model = Autoencoder(input_dim).to(self.device)
        self.model.load_state_dict(torch.load(model_path, map_location=self.device))
        self.model.eval()
        print(f"   ✓ Модель загружена (устройство: {self.device})")

        # Загружаем скейлер
        with open(scaler_path, 'rb') as f:
            self.scaler = pickle.load(f)
        print(f"   ✓ Скейлер загружен")

        # Создаем классификатор С P95 И THRESHOLD
        self.classifier = ThreatClassifier(
            p95_values=p95_values,
            threshold=self.threshold
        )
        print(f"   ✓ Классификатор инициализирован с data-driven порогами")

    #функция обирает сырые данные один раз
    def collect_once(self):

        try:
            # тоже самое что и psutil colletor
            self.buffer['cpu_percent'].append(psutil.cpu_percent(interval=None))
            self.buffer['ram_percent'].append(psutil.virtual_memory().percent)


            current_net = psutil.net_io_counters()
            time_delta = time.time() - self.last_time
            if time_delta > 0:
                self.buffer['bytes_sent'].append(
                    (current_net.bytes_sent - self.last_network_counters.bytes_sent) / time_delta
                )
                self.buffer['bytes_recv'].append(
                    (current_net.bytes_recv - self.last_network_counters.bytes_recv) / time_delta
                )
            self.last_network_counters = current_net
            self.last_time = time.time()


            try:
                connections = psutil.net_connections(kind='inet')
                self.buffer['active_connections'] = len(connections)

                for conn in connections:
                    if conn.raddr:
                        self.buffer['unique_dst_ips'].add(conn.raddr.ip)
                        self.buffer['unique_dst_ports'].add(conn.raddr.port)
            except (psutil.AccessDenied, psutil.Error):
                pass


            processes = list(psutil.process_iter())
            self.buffer['process_count'] = len(processes)


            unique_procs = set()
            unique_users = set()
            for proc in processes:
                try:
                    unique_procs.add(proc.name())
                    username = proc.username()
                    if username:
                        unique_users.add(username)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            self.buffer['unique_processes_count'] = len(unique_procs)
            self.buffer['unique_users_count'] = len(unique_users)


            current_disk = psutil.disk_io_counters()
            self.buffer['disk_read_bytes'] += (current_disk.read_bytes - self.last_disk_counters.read_bytes)
            self.buffer['disk_write_bytes'] += (current_disk.write_bytes - self.last_disk_counters.write_bytes)
            self.last_disk_counters = current_disk

            # тоже самое что и eventlog collector
            try:
                import win32evtlog

                end_time = datetime.now()
                last_read = getattr(self, 'last_eventlog_read', time.time())
                start_time = datetime.fromtimestamp(last_read)


                channels_config = {
                    'Security': {
                        4625: 'failed_logins',
                        4624: 'successful_logins',
                        4688: 'process_creations',
                    },
                    'System': {
                        7045: 'service_installations',
                    },
                }

                for channel, event_mapping in channels_config.items():
                    if not event_mapping:
                        continue

                    try:
                        hand = win32evtlog.OpenEventLog('localhost', channel)
                        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                                 win32evtlog.EVENTLOG_SEQUENTIAL_READ)

                        events_read = 0
                        events_in_window = 0
                        events_matched = {}

                        while True:
                            events = win32evtlog.ReadEventLog(hand, flags, 0)
                            if not events:
                                break

                            for event in events:
                                events_read += 1
                                event_time = event.TimeGenerated

                                # Пропускаем старые события
                                if event_time < start_time:
                                    continue
                                if event_time > end_time:
                                    continue

                                events_in_window += 1
                                event_id = event.EventID

                                if event_id in event_mapping:
                                    counter_name = event_mapping[event_id]
                                    self.buffer[counter_name] += 1
                                    events_matched[event_id] = events_matched.get(event_id, 0) + 1

                        win32evtlog.CloseEventLog(hand)


                    except Exception as e:
                        print(f"   ОШИБКА чтения {channel}: {e}")

                self.last_eventlog_read = time.time()

            except ImportError:
                print("   pywin32 не установлен!")
            except Exception as e:
                print(f"    Общая ошибка Event Log: {e}")
            except ImportError:
                print("    pywin32 не установлен, Event Log не читается")
            except Exception as e:
                print(f"   Ошибка чтения Event Log: {e}")

            self.buffer['timestamp'] = datetime.now().isoformat()

        except Exception as e:
            print(f"Ошибка сбора данных: {e}")

#агрегирует собранные данные
    def aggregate_minute(self):
        if not self.buffer['cpu_percent']:
            return None



        aggregated = {
            'cpu_avg': sum(self.buffer['cpu_percent']) / len(self.buffer['cpu_percent']),
            'cpu_max': max(self.buffer['cpu_percent']),
            'ram_avg': sum(self.buffer['ram_percent']) / len(self.buffer['ram_percent']),
            'ram_max': max(self.buffer['ram_percent']),
            'bytes_sent_avg': sum(self.buffer['bytes_sent']) / len(self.buffer['bytes_sent']),
            'bytes_recv_avg': sum(self.buffer['bytes_recv']) / len(self.buffer['bytes_recv']),
            'unique_dst_ips_count': len(self.buffer['unique_dst_ips']),
            'unique_dst_ports_count': len(self.buffer['unique_dst_ports']),
            'active_connections_max': self.buffer['active_connections'],
            'process_count_avg': self.buffer['process_count'],
            'disk_read_bytes_total': self.buffer['disk_read_bytes'],
            'disk_write_bytes_total': self.buffer['disk_write_bytes'],
            'failed_logins': self.buffer['failed_logins'],
            'successful_logins': self.buffer['successful_logins'],
            'process_creations': self.buffer['process_creations'],
            'service_installations': self.buffer['service_installations'],
        }



        # Сбрасываем буфер
        self.buffer = {
            'cpu_percent': [],
            'ram_percent': [],
            'bytes_sent': [],
            'bytes_recv': [],
            'unique_dst_ips': set(),
            'unique_dst_ports': set(),
            'active_connections': 0,
            'process_count': 0,
            'disk_read_bytes': 0,
            'disk_write_bytes': 0,
            'failed_logins': 0,
            'successful_logins': 0,
            'process_creations': 0,
            'service_installations': 0,
            'timestamp': None
        }

        self.last_network_counters = psutil.net_io_counters()
        self.last_disk_counters = psutil.disk_io_counters()
        self.last_time = time.time()

        return aggregated

# усредняет последние аггрегированные данные за 10 мин
    def get_monitoring_window_features(self):
        if len(self.minute_aggregates) < self.monitoring_window_minutes:
            return None

        recent = self.minute_aggregates[-self.monitoring_window_minutes:]

        averaged = {}
        for key in recent[0].keys():
            values = [agg[key] for agg in recent]
            averaged[key] = sum(values) / len(values)

        return averaged


#считаем MSE и сравниваем с порогом
    def detect_anomaly(self, features_dict):

        # Извлекаем только нужные признаки в правильном порядке
        feature_values = [features_dict.get(f, 0) for f in self.features]

        # Оборачиваем в DataFrame с именами признаков
        X = pd.DataFrame([feature_values], columns=self.features)
        X_scaled = self.scaler.transform(X)

                # Прогоняем через модель
        self.model.eval()
        with torch.no_grad():
            x_tensor = torch.FloatTensor(X_scaled).to(self.device)
            output = self.model(x_tensor)
            mse = ((x_tensor - output) ** 2).mean().item()

        # Сравниваем с порогом
        is_anomaly = mse > self.threshold

        # Классифицируем угрозу
        threat_info = None
        if is_anomaly:
            threat_info = self.classifier.classify(features_dict, mse)

        return is_anomaly, mse, threat_info


# детектирует аномалию и проверят что выполняется условие на 2 аномальных окна подряд
    def detect_anomaly_with_confirmation(self, features_dict):

        # Базовая детекция ТЕКУЩЕГО окна
        is_anomaly, mse, threat_info = self.detect_anomaly(features_dict)

        # Обновляем счетчик подряд идущих аномалий
        current_time = time.time()

        if is_anomaly:
            self.consecutive_anomalies += 1
        else:
            self.consecutive_anomalies = 0

        # Решаем, алертить ли, или нет
        should_alert = (
                self.consecutive_anomalies >= self.confirmation_windows and
                (current_time - self.last_alert_time) > self.cooldown_seconds
        )

        if should_alert:
            self.last_alert_time = current_time
            self.consecutive_anomalies = 0
            return True, mse, threat_info

        return False, mse, threat_info

#для записи в JSON нашего аллерата
    def save_alert(self, mse_score, threat_info, features_dict):
        """Сохраняет алерт в JSON файл с защитой от повреждения"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'mse_score': float(mse_score),
            'threshold': float(self.threshold),
            'threat_type': threat_info['threat_type'],
            'confidence': threat_info['confidence'],
            'description': threat_info['description'],
            'recommendations': threat_info['recommendations'],
            'top_features': {
                'bytes_sent_avg': float(features_dict.get('bytes_sent_avg', 0)),
                'bytes_recv_avg': float(features_dict.get('bytes_recv_avg', 0)),
                'cpu_avg': float(features_dict.get('cpu_avg', 0)),
                'cpu_max': float(features_dict.get('cpu_max', 0)),
                'ram_avg': float(features_dict.get('ram_avg', 0)),
                'failed_logins': float(features_dict.get('failed_logins', 0)),
                'unique_dst_ips_count': float(features_dict.get('unique_dst_ips_count', 0)),
                'unique_dst_ports_count': float(features_dict.get('unique_dst_ports_count', 0)),
                'disk_write_bytes_total': float(features_dict.get('disk_write_bytes_total', 0)),
                'disk_read_bytes_total': float(features_dict.get('disk_read_bytes_total', 0)),
                'process_creations': float(features_dict.get('process_creations', 0)),
                'active_connections_max': float(features_dict.get('active_connections_max', 0)),
            }
        }


        alerts = []
        try:
            if os.path.exists(self.alerts_file) and os.path.getsize(self.alerts_file) > 0:
                with open(self.alerts_file, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if content:
                        try:
                            loaded = json.loads(content)
                            if isinstance(loaded, list):
                                alerts = loaded
                            else:
                                print(f"   Файл алертов имеет неверный формат, создаем новый")
                        except json.JSONDecodeError as e:
                            print(f"   Файл алертов поврежден ({e}), создаем новый")
                            # Создаем бэкап поврежденного файла
                            backup_path = self.alerts_file + '.corrupted'
                            try:
                                os.replace(self.alerts_file, backup_path)
                                print(f"  Поврежденный файл сохранен как: {backup_path}")
                            except:
                                pass
        except Exception as e:
            print(f"   Ошибка чтения файла алертов: {e}")

        alerts.append(alert)

        # запись через временный файл чтоб не повредить старый
        temp_path = self.alerts_file + '.tmp'
        try:
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(alerts, f, indent=2, ensure_ascii=False)
            os.replace(temp_path, self.alerts_file)
        except Exception as e:
            print(f"    Ошибка записи алерта: {e}")
            try:
                with open(self.alerts_file, 'w', encoding='utf-8') as f:
                    json.dump(alerts, f, indent=2, ensure_ascii=False)
            except Exception as e2:
                print(f"  Критическая ошибка записи: {e2}")

        return alert



        #Главный цикл мониторинга с неперекрывающимися окнами.
        #Каждые monitoring_window_minutes делается проверка, затем окно сбрасывается.

    def run(self, collection_interval=10):

        print("\n" + "=" * 60)
        print("ЗАПУСК МОНИТОРИНГА АНОМАЛИЙ")
        print("=" * 60)
        print(f"   Интервал сбора: {collection_interval}s")
        print(f"   Окно агрегации: {self.monitoring_window_minutes} минут")
        print(f"   Подтверждение аномалии: {self.confirmation_windows} окон подряд")
        print(f"   Cooldown между алертами: {self.cooldown_seconds}s")
        print(f"   Порог аномальности: {self.threshold:.4f}")
        print(f"   Алерты сохраняются в: {self.alerts_file}")
        print("=" * 60 + "\n")

        step = 0

        try:
            while True:
                current_time = time.time()

                # Собираем сырые данные
                self.collect_once()
                step += 1

                # Проверяем, прошла ли минута
                if (current_time - self.last_minute_aggregation) >= 60:


                    minute_agg = self.aggregate_minute()

                    if minute_agg:

                        # Добавляем в историю
                        self.minute_aggregates.append(minute_agg)


                        timestamp = datetime.now().strftime('%H:%M:%S')
                        window_progress = len(self.minute_aggregates)

                        # Проверяем, заполнено ли окно
                        if window_progress >= self.monitoring_window_minutes:
                            # Окно готово — делаем детекцию
                            features_dict = self.get_monitoring_window_features()


                            if features_dict:
                                is_anomaly, mse, threat_info = self.detect_anomaly_with_confirmation(features_dict)

                                if is_anomaly:
                                    print(f"\n🚨 [{timestamp}] ПОДТВЕРЖДЕННАЯ АНОМАЛИЯ!")
                                    print(f"   Скользящее MSE: {mse:.4f} (порог: {self.threshold:.4f})")
                                    print(f"   Тип угрозы: {threat_info['threat_type']}")
                                    print(f"   Уверенность: {threat_info['confidence']:.0%}")
                                    print(f"   Описание: {threat_info['description']}")



                                    print(f"   Значения признаков в момент аномалии:")
                                    for key in ['cpu_avg', 'cpu_max', 'ram_avg', 'bytes_sent_avg', 'bytes_recv_avg',
                                                'unique_dst_ips_count', 'unique_dst_ports_count',
                                                'active_connections_max',
                                                'disk_write_bytes_total', 'disk_read_bytes_total', 'process_creations',
                                                'failed_logins']:
                                        val = features_dict.get(key, 0)
                                        print(f"      • {key}: {val:.2f}")

                                    print(f"   Рекомендации:")
                                    for rec in threat_info['recommendations']:
                                        print(f"      • {rec}")

                                    self.save_alert(mse, threat_info, features_dict)
                                    print(f"   Алерт сохранен в {self.alerts_file}")

                                else:
                                    status = "🟡 Подозрение" if self.consecutive_anomalies > 0 else "✓"
                                    print(f"[{timestamp}] {status} Норма (MSE: {mse:.4f}, "
                                          f"подряд: {self.consecutive_anomalies}/{self.confirmation_windows}, "
                                          f"окно готово)")

                            # СБРАСЫВАЕМ окно — начинаем новое
                            self.minute_aggregates = []

                        else:
                            # Окно ещё накапливается
                            # Показываем MSE последнего 1-минутного среза
                            last_mse = self._quick_mse_estimate(minute_agg)
                            print(
                                f"[{timestamp}] 🔧 Накопление окна {window_progress}/{self.monitoring_window_minutes} мин "
                                f"(последний срез MSE: {last_mse:.2f})")

                    self.last_minute_aggregation = current_time

                time.sleep(collection_interval)

        except KeyboardInterrupt:
            print("\n\n Мониторинг остановлен пользователем")
            try:
                with open(self.alerts_file, 'r', encoding='utf-8') as f:
                    alerts_count = len(json.load(f))
                print(f"   Всего алертов: {alerts_count}")
            except:
                pass


    #Быстрая оценка MSE для одного 1-минутного среза (для вывода во время накопления).
    #Не используется для детекции — только для информации.

    def _quick_mse_estimate(self, features_dict):

        try:
            feature_values = [features_dict.get(f, 0) for f in self.features]
            X = pd.DataFrame([feature_values], columns=self.features)
            X_scaled = self.scaler.transform(X)

            self.model.eval()
            with torch.no_grad():
                x_tensor = torch.FloatTensor(X_scaled).to(self.device)
                output = self.model(x_tensor)
                mse = ((x_tensor - output) ** 2).mean().item()

            return mse
        except:
            return 0.0

def main():


    monitor = AnomalyMonitor(
        artifacts_dir='ml/artifacts',
        alerts_dir='data',
        monitoring_window_minutes=10,
        confirmation_windows=2,
        cooldown_seconds=600
    )

    monitor.run(collection_interval=args.collection_interval)


if __name__ == '__main__':
    run_as_admin()
    main()