import yaml
import time
import pandas as pd
from datetime import datetime
from collectors.psutil_collector import PsutilCollector
from collectors.eventlog_collector import EventLogCollector
import sys
import os
import ctypes



# функции необходимые для админского запуска
# (без него нельзя читать журнал событий безопастности windows)
def is_admin():
    """Проверяем, запущен ли скрипт с правами админа"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Перезапускаем скрипт с правами админа"""
    if not is_admin():
        print("Запрашиваем права администратора...")
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()

class DataCollector:
    def __init__(self, config_path='config.yaml'):
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        self.psutil_collector = PsutilCollector(self.config) if self.config['psutil']['enabled'] else None       # коллектор данных psutil /collecotors/psutil_collector.py
        self.eventlog_collector = EventLogCollector(self.config) if self.config['eventlog']['enabled'] else None # коллектор данных из журнала событий /collecotors/eventlog_collector.py

        self.aggregation_window = self.config['collection']['aggregation_window_seconds']  # как часто агрегировать собранные данные
        self.collection_interval = self.config['collection']['interval_seconds']           # как часто собирать данные
        self.output_dir = self.config['storage']['output_dir']                             # директория с файлами записи
        self.rotation_hours = self.config['storage']['rotation_hours']                     # число часов в течение которых данные пишутся в один файл

        os.makedirs(self.output_dir, exist_ok=True)

        self.current_file = None     # файл в который идет запись
        self.file_start_time = None  # время в которое началась запись в файл (нужно для ротации файлов)


#функция получает путь к текущему файлу записи данных
    def _get_output_file(self):

        now = datetime.now()

        # Проверяем, нужна ли ротация
        if self.current_file is None or \
                (now - self.file_start_time).total_seconds() > self.rotation_hours * 3600:
            filename = f"telemetry_{now.strftime('%Y%m%d_%H%M%S')}.csv"
            self.current_file = os.path.join(self.output_dir, filename)
            self.file_start_time = now

            # Создаем файл с заголовками
            pd.DataFrame(columns=self._get_columns()).to_csv(self.current_file, index=False)
            print(f"Created new output file: {self.current_file}")

        return self.current_file

# создает список колонок, нужна так как он может поменяться при отключении одного из коллекторов, или добавлении нового
    def _get_columns(self):

        columns = ['timestamp']

        if self.psutil_collector:
            columns.extend([
                'cpu_avg', 'cpu_max', 'ram_avg', 'ram_max',
                'bytes_sent_avg', 'bytes_recv_avg',
                'unique_dst_ips_count', 'unique_dst_ports_count',
                'active_connections_max', 'process_count_avg',
                'disk_read_bytes_total', 'disk_write_bytes_total',
                'top_cpu_processes', 'top_ram_processes'
            ])

        if self.eventlog_collector:
            columns.extend([
                'failed_logins', 'successful_logins',
                'process_creations', 'service_installations',
                'unique_users_count', 'unique_processes_count'
            ])

        return columns
# цикл сбора данных
    def run(self):

        print("Starting data collection...")
        i = 0
        print(f"Aggregation window: {self.aggregation_window}s")
        print(f"Collection interval: {self.collection_interval}s")

        last_aggregation_time = time.time()

        try:
            while True:

                current_time = time.time()
                print('процесс запущен, шаг:', i)
                i+=1

                # Собираем данные
                if self.psutil_collector:
                    self.psutil_collector.collect_once()

                if self.eventlog_collector:
                    self.eventlog_collector.collect_events()

                # Проверяем, пора ли агрегировать
                if (current_time - last_aggregation_time) >= self.aggregation_window:
                    print(f"\n[{datetime.now()}] Aggregating data...")

                    # Агрегируем
                    row = {'timestamp': datetime.now().isoformat()}

                    if self.psutil_collector:
                        psutil_data = self.psutil_collector.aggregate_and_reset()
                        if psutil_data:
                            row.update(psutil_data)

                    if self.eventlog_collector:
                        eventlog_data = self.eventlog_collector.aggregate_and_reset()
                        if eventlog_data:
                            row.update(eventlog_data)

                    # Записываем в файл
                    output_file = self._get_output_file()
                    df = pd.DataFrame([row])
                    df.to_csv(output_file, mode='a', header=False, index=False)

                    print(f"Записано: {row}")

                    last_aggregation_time = current_time

                # Спим до следующего тика
                time.sleep(self.collection_interval)

        except KeyboardInterrupt:
            print("\nCollection stopped by user")
        except Exception as e:
            print(f"Error in collection loop: {e}")
            raise


if __name__ == '__main__':
    run_as_admin()
    collector = DataCollector('data_collection/config.yaml')
    collector.run()