import win32evtlog
import win32evtlogutil
import win32con
from datetime import datetime
import time


class EventLogCollector:
    def __init__(self, config):
        self.config = config
        self.channels = config['eventlog']['channels']      #список каналов
        self.event_ids = config['eventlog']['event_ids']    #номера считываемых событий

        # Запоминаем последнее прочитанное событие для каждого канала
        self.last_record_numbers = {}

        # Буфер для агрегации
        self.buffer = {
            'failed_logins': 0,
            'successful_logins': 0,
            'process_creations': 0,
            'service_installations': 0,
            'unique_users': set(),
            'unique_processes': set(),
            'timestamp': None
        }
# собираем события из всех каналов
    def collect_events(self):

        for channel in self.channels:
            try:
                self._read_channel(channel)
            except Exception as e:
                print(f"Error reading channel {channel}: {e}")

# собираем события из одного канала
    def _read_channel(self, channel):

        hand = win32evtlog.OpenEventLog(None, channel)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        last_record = self.last_record_numbers.get(channel, 0)

        while True:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break

            for event in events:
                # Пропускаем уже прочитанные
                if event.RecordNumber <= last_record:
                    continue

                # Фильтруем по Event ID
                target_ids = self.event_ids.get(channel, [])
                if target_ids and event.EventID not in target_ids:
                    continue

                # Обрабатываем событие
                self._process_event(channel, event)

                # Обновляем последний RecordNumber
                self.last_record_numbers[channel] = event.RecordNumber

        win32evtlog.CloseEventLog(hand)


# обработка события
    def _process_event(self, channel, event):

        event_id = event.EventID

        if channel == 'Security':
            if event_id == 4625:  # Неудачный вход
                self.buffer['failed_logins'] += 1
                if event.StringInserts and len(event.StringInserts) > 5:
                    self.buffer['unique_users'].add(event.StringInserts[5])

            elif event_id == 4624:  # Успешный вход
                self.buffer['successful_logins'] += 1
                if event.StringInserts and len(event.StringInserts) > 5:
                    self.buffer['unique_users'].add(event.StringInserts[5])

            elif event_id == 4688:  # Создание процесса
                self.buffer['process_creations'] += 1
                if event.StringInserts and len(event.StringInserts) > 1:
                    self.buffer['unique_processes'].add(event.StringInserts[1])

        elif channel == 'System':
            if event_id == 7045:  # Установка сервиса
                self.buffer['service_installations'] += 1

        self.buffer['timestamp'] = datetime.now().isoformat()



# функция для аггрегации уже собранного

    def aggregate_and_reset(self):

        aggregated = {
            'timestamp': self.buffer['timestamp'],
            'failed_logins': self.buffer['failed_logins'],
            'successful_logins': self.buffer['successful_logins'],
            'process_creations': self.buffer['process_creations'],
            'service_installations': self.buffer['service_installations'],
            'unique_users_count': len(self.buffer['unique_users']),
            'unique_processes_count': len(self.buffer['unique_processes'])
        }

        # Сбрасываем
        self.buffer = {
            'failed_logins': 0,
            'successful_logins': 0,
            'process_creations': 0,
            'service_installations': 0,
            'unique_users': set(),
            'unique_processes': set(),
            'timestamp': None
        }

        return aggregated