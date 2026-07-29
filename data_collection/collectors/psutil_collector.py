import psutil
import time
from collections import defaultdict
from datetime import datetime


class PsutilCollector:
    def __init__(self, config):
        self.config = config
        self.interval = config['collection']['interval_seconds']                     #как часто собирать данные
        self.aggregation_window = config['collection']['aggregation_window_seconds'] #как часто их аггрегировать
        self.top_n = config['psutil']['top_n_processes']                             #топ самых трудозатратных процессов

        # Буфер для агрегации
        self.buffer = {
            'cpu_percent': [],
            'ram_percent': [],
            'bytes_sent': [],
            'bytes_recv': [],
            'unique_dst_ips': set(),
            'unique_dst_ports': set(),
            'active_connections': 0,
            'process_count': 0,
            'top_cpu_processes': [],
            'top_ram_processes': [],
            'disk_read_bytes': 0,
            'disk_write_bytes': 0,
            'timestamp': None
        }

        self.last_network_counters = psutil.net_io_counters()
        self.last_disk_counters = psutil.disk_io_counters()
        self.last_time = time.time()


# функция для единоразового сбора данных
    def collect_once(self):

        try:
            # CPU и RAM
            self.buffer['cpu_percent'].append(psutil.cpu_percent(interval=None))
            self.buffer['ram_percent'].append(psutil.virtual_memory().percent)

            # Сеть
            current_net = psutil.net_io_counters()
            time_delta = time.time() - self.last_time
            self.buffer['bytes_sent'].append(
                (current_net.bytes_sent - self.last_network_counters.bytes_sent) / time_delta
            )
            self.buffer['bytes_recv'].append(
                (current_net.bytes_recv - self.last_network_counters.bytes_recv) / time_delta
            )
            self.last_network_counters = current_net
            self.last_time = time.time()

            # Сетевые соединения
            connections = psutil.net_connections(kind='inet')
            self.buffer['active_connections'] = len(connections)

            dst_ips = set()
            dst_ports = set()
            for conn in connections:
                if conn.raddr:
                    dst_ips.add(conn.raddr.ip)
                    dst_ports.add(conn.raddr.port)

            self.buffer['unique_dst_ips'].update(dst_ips)
            self.buffer['unique_dst_ports'].update(dst_ports)

            # Процессы
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            self.buffer['process_count'] = len(processes)

            # Топ процессов по CPU и RAM
            top_cpu = sorted(processes, key=lambda x: x['cpu_percent'] or 0, reverse=True)[:self.top_n]
            top_ram = sorted(processes, key=lambda x: x['memory_percent'] or 0, reverse=True)[:self.top_n]

            self.buffer['top_cpu_processes'] = [(p['name'], p['cpu_percent']) for p in top_cpu]
            self.buffer['top_ram_processes'] = [(p['name'], p['memory_percent']) for p in top_ram]

            # Диск (разность)
            current_disk = psutil.disk_io_counters()
            self.buffer['disk_read_bytes'] += (current_disk.read_bytes - self.last_disk_counters.read_bytes)
            self.buffer['disk_write_bytes'] += (current_disk.write_bytes - self.last_disk_counters.write_bytes)
            self.last_disk_counters = current_disk

            self.buffer['timestamp'] = datetime.now().isoformat()

        except Exception as e:
            print(f"Error collecting psutil data: {e}")

# аггрегация всего подряд
    def aggregate_and_reset(self):
        if not self.buffer['cpu_percent']:
            return None

        aggregated = {
            'timestamp': self.buffer['timestamp'],
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
            'top_cpu_processes': str(self.buffer['top_cpu_processes'][-1]),
            'top_ram_processes': str(self.buffer['top_ram_processes'][-1])
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
            'top_cpu_processes': [],
            'top_ram_processes': [],
            'disk_read_bytes': 0,
            'disk_write_bytes': 0,
            'timestamp': None
        }

        return aggregated
