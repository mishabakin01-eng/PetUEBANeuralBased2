"""
threat_classifier.py — Классификация аномалий по типу аномального поведения.
"""

import numpy as np


class ThreatClassifier:

    def __init__(self, p95_values=None, threshold=None):
        self.p95 = p95_values or {}
        self.threshold = threshold or 1.0

        # Базовая уверенность для каждого ТИПА АНОМАЛИИ
        self.base_confidence = {
            'Аномальная нагрузка на CPU': 0.55,
            'Аномальная дисковая активность': 0.50,
            'Аномальная исходящая сетевая активность': 0.55,
            'Аномальная входящая сетевая активность': 0.50,
            'Множество сетевых соединений': 0.45,
            'Сканирование портов': 0.45,
            'Подозрительная аутентификация': 0.70,
            'Массовое создание процессов': 0.50,
            'Установка новых сервисов': 0.60,
            'Комбинированная аномалия': 0.60,
            'Общая аномалия': 0.30,
        }

    #Бонус за превышение MSE над порогом. [0, 0.15]
    def _mse_bonus(self, mse_score):

        if self.threshold <= 0:
            return 0.0
        ratio = mse_score / self.threshold
        return min(0.15, 0.05 * np.log2(max(1.0, ratio)))

    #Относительное превышение признака над P95.
    def _feature_deviation(self, feature_name, value):

        p95 = self.p95.get(feature_name)
        if p95 is None or p95 <= 0:
            return 0.0
        if value <= p95:
            return 0.0
        return (value - p95) / p95

    #Итоговый рассчет уверенности
    def _compute_confidence(self, anomaly_type, mse_score, features_dict,
                            relevant_features):

        base = self.base_confidence.get(anomaly_type, 0.30)

        # Бонус за MSE
        mse_b = self._mse_bonus(mse_score)

        # Бонус за силу отклонения признаков
        deviations = [self._feature_deviation(f, features_dict.get(f, 0))
                      for f in relevant_features]
        avg_deviation = np.mean(deviations) if deviations else 0
        feat_b = min(0.25, avg_deviation * 0.10)

        confidence = base + mse_b + feat_b
        return max(0.30, min(0.99, confidence))


    # для понятного вывода процентов и байт
    def _format_value(self, feature_name, value):
        if 'bytes' in feature_name:
            if value > 1024 * 1024:
                return f"{value / (1024*1024):.1f} MB"
            elif value > 1024:
                return f"{value / 1024:.1f} KB"
            return f"{value:.0f} B"
        elif 'percent' in feature_name or 'cpu' in feature_name or 'ram' in feature_name:
            return f"{value:.1f}%"
        else:
            return f"{value:.0f}"

    #классификатор, проверяет на соответсвие разным типам угроз,
    # затем выбирает ту у которой наибольшая уверенность
    def classify(self, features_dict, mse_score):

        candidates = []

        # 1. Аномальная нагрузка на CPU
        cpu_avg = features_dict.get('cpu_avg', 0)
        cpu_max = features_dict.get('cpu_max', 0)
        p95_cpu = self.p95.get('cpu_avg', float('inf'))

        if cpu_avg > p95_cpu or cpu_max > self.p95.get('cpu_max', float('inf')):
            conf = self._compute_confidence(
                'Аномальная нагрузка на CPU', mse_score, features_dict,
                relevant_features=['cpu_avg', 'cpu_max']
            )
            candidates.append({
                'threat_type': 'Аномальная нагрузка на CPU',
                'confidence': conf,
                'description': (
                    f"Загрузка процессора значительно выше обычного уровня. "
                    f"Средняя: {cpu_avg:.1f}% (P95: {p95_cpu:.1f}%), "
                    f"пиковая: {cpu_max:.1f}%. "
                    f"Это может указывать на работу ресурсоёмкого приложения, "
                    f"майнера или вредоносного ПО."
                ),

                'recommendations': [
                    'Открыть Диспетчер задач и проверить топ-процессы по CPU',
                    'Искать подозрительные процессы',
                    'Проверить автозагрузку на наличие вредоносных сервисов',

                ]
            })

        #  2. Аномальная дисковая активность
        disk_write = features_dict.get('disk_write_bytes_total', 0)
        disk_read = features_dict.get('disk_read_bytes_total', 0)
        p95_write = self.p95.get('disk_write_bytes_total', float('inf'))
        p95_read = self.p95.get('disk_read_bytes_total', float('inf'))

        if disk_write > p95_write or disk_read > p95_read:
            relevant = []
            if disk_write > p95_write:
                relevant.append('disk_write_bytes_total')
            if disk_read > p95_read:
                relevant.append('disk_read_bytes_total')

            conf = self._compute_confidence(
                'Аномальная дисковая активность', mse_score, features_dict,
                relevant_features=relevant
            )

            parts = []
            if disk_write > p95_write:
                parts.append(f"запись: {self._format_value('disk_write_bytes_total', disk_write)} (P95: {self._format_value('disk_write_bytes_total', p95_write)})")
            if disk_read > p95_read:
                parts.append(f"чтение: {self._format_value('disk_read_bytes_total', disk_read)} (P95: {self._format_value('disk_read_bytes_total', p95_read)})")

            candidates.append({
                'threat_type': 'Аномальная дисковая активность',
                'confidence': conf,
                'description': (
                    f"Дисковая активность значительно выше обычного уровня. "
                    f"{', '.join(parts)}. "
                    f"Это может указывать на шифрование файлов, "
                    f"резервное копирование, индексацию или работу вредоносного ПО."
                ),

                'recommendations': [
                    'Проверить процессы с высоким disk I/O ',
                    'Обратить внимание на подозрительные расширения файлов',
                    'Проверить недавние установки программ',
                    'При массовом шифровании — НЕМЕДЛЕННО отключить ПК от сети'
                ]
            })

        # 3. Аномальная исходящая сетевая активность
        bytes_sent = features_dict.get('bytes_sent_avg', 0)
        p95_sent = self.p95.get('bytes_sent_avg', float('inf'))

        if bytes_sent > p95_sent:
            conf = self._compute_confidence(
                'Аномальная исходящая сетевая активность', mse_score, features_dict,
                relevant_features=['bytes_sent_avg']
            )
            candidates.append({
                'threat_type': 'Аномальная исходящая сетевая активность',
                'confidence': conf,
                'description': (
                    f"Исходящий сетевой трафик значительно выше обычного: "
                    f"{self._format_value('bytes_sent_avg', bytes_sent)}/с "
                    f"(P95: {self._format_value('bytes_sent_avg', p95_sent)}/с). "
                    f"Это может указывать на эксфильтрацию данных, "
                    f"загрузку файлов в облако или работу C2-канала."
                ),
                'recommendations': [
                    'Проверить исходящие соединения',
                    'Проанализировать процессы с высоким сетевым трафиком',
                    'Проверить недавние загрузки в облачные сервисы',
                    'При необходимости — заблокировать подозрительные IP в firewall'
                ]
            })

        # 4. Аномальная входящая сетевая активность
        bytes_recv = features_dict.get('bytes_recv_avg', 0)
        p95_recv = self.p95.get('bytes_recv_avg', float('inf'))

        if bytes_recv > p95_recv:
            conf = self._compute_confidence(
                'Аномальная входящая сетевая активность', mse_score, features_dict,
                relevant_features=['bytes_recv_avg']
            )
            candidates.append({
                'threat_type': 'Аномальная входящая сетевая активность',
                'confidence': conf,
                'description': (
                    f"Входящий сетевой трафик значительно выше обычного: "
                    f"{self._format_value('bytes_recv_avg', bytes_recv)}/с "
                    f"(P95: {self._format_value('bytes_recv_avg', p95_recv)}/с). "
                    f"Это может указывать на загрузку вредоносного ПО, "
                    f"обновления или DDoS-атаку."
                ),
                'recommendations': [
                    'Проверить входящие соединения',
                    'Проанализировать процессы с высоким входящим трафиком',
                    'Проверить недавние загрузки и обновления'
                ]
            })

        # 5. Множество сетевых соединений
        active_conns = features_dict.get('active_connections_max', 0)
        p95_conns = self.p95.get('active_connections_max', float('inf'))

        if active_conns > p95_conns:
            conf = self._compute_confidence(
                'Множество сетевых соединений', mse_score, features_dict,
                relevant_features=['active_connections_max']
            )
            candidates.append({
                'threat_type': 'Множество сетевых соединений',
                'confidence': conf,
                'description': (
                    f"Количество активных сетевых соединений значительно выше обычного: "
                    f"{active_conns:.0f} (P95: {p95_conns:.0f}). "
                    f"Это может указывать на P2P-сети, торренты, C2-маячки или DDoS-активность."
                ),

                'recommendations': [
                    'Проверить список активных соединений',
                    'Обратить внимание на подозрительные удалённые IP',
                    'Проверить наличие P2P-клиентов и торрентов'
                ]
            })

        # 6. Сканирование портов
        unique_ports = features_dict.get('unique_dst_ports_count', 0)
        p95_ports = self.p95.get('unique_dst_ports_count', float('inf'))

        if unique_ports > p95_ports:
            conf = self._compute_confidence(
                'Сканирование портов', mse_score, features_dict,
                relevant_features=['unique_dst_ports_count']
            )
            candidates.append({
                'threat_type': 'Сканирование портов',
                'confidence': conf,
                'description': (
                    f"Количество уникальных портов назначения значительно выше обычного: "
                    f"{unique_ports:.0f} (P95: {p95_ports:.0f}). "
                    f"Это может указывать на сканирование сети, "
                    f"работу ботнета или активность вредоносного ПО."
                ),

                'recommendations': [
                    'Проверить процессы с сетевыми соединениями',
                    'Проанализировать firewall логи',
                    'Заблокировать подозрительные IP'
                ]
            })

        # 7. Подозрительная аутентификация
        failed_logins = features_dict.get('failed_logins', 0)
        p95_failed = self.p95.get('failed_logins', float('inf'))

        if failed_logins > p95_failed:
            conf = self._compute_confidence(
                'Подозрительная аутентификация', mse_score, features_dict,
                relevant_features=['failed_logins']
            )
            candidates.append({
                'threat_type': 'Подозрительная аутентификация',
                'confidence': conf,
                'description': (
                    f"Количество неудачных попыток входа значительно выше обычного: "
                    f"{failed_logins:.0f} (P95: {p95_failed:.0f}). "
                    f"Это может указывать на brute-force атаку "
                    f"или подбор учётных данных."
                ),
                'mitre_attack': 'T1110 - Brute Force',
                'recommendations': [
                    'Проверить журналы безопасности',
                    'Заблокировать подозрительные IP-адреса',
                    'Включить политику блокировки учётных записей',
                    'Проверить, не скомпрометированы ли учётные записи'
                ]
            })

        # 8. Массовое создание процессов
        proc_creations = features_dict.get('process_creations', 0)
        p95_proc = self.p95.get('process_creations', float('inf'))

        if proc_creations > p95_proc:
            conf = self._compute_confidence(
                'Массовое создание процессов', mse_score, features_dict,
                relevant_features=['process_creations']
            )
            candidates.append({
                'threat_type': 'Массовое создание процессов',
                'confidence': conf,
                'description': (
                    f"Количество созданных процессов значительно выше обычного: "
                    f"{proc_creations:.0f} (P95: {p95_proc:.0f}). "
                    f"Это может указывать на запуск вредоносного ПО, "
                    f"fork-бомбу или массовое выполнение скриптов."
                ),

                'recommendations': [
                    'Проверить родительские процессы в Event ID',
                    'Искать подозрительные цепочки процессов',
                    'Проверить наличие скриптов в автозагрузке'
                ]
            })

        # 9. Установка новых сервисов
        service_inst = features_dict.get('service_installations', 0)
        p95_service = self.p95.get('service_installations', float('inf'))

        if service_inst > p95_service:
            conf = self._compute_confidence(
                'Установка новых сервисов', mse_score, features_dict,
                relevant_features=['service_installations']
            )
            candidates.append({
                'threat_type': 'Установка новых сервисов',
                'confidence': conf,
                'description': (
                    f"Обнаружена установка новых системных сервисов: "
                    f"{service_inst:.0f} (P95: {p95_service:.0f}). "
                    f"Это может указывать на установку вредоносного ПО, "
                    f"закрепление в системе или бэкдор."
                ),

                'recommendations': [
                    'Проверить Event ID 7045 в журнале System',
                    'Обратить внимание на подозрительные пути к исполняемым файлам',
                    'Проверить цифровые подписи новых сервисов'
                ]
            })

        # Если не найдено специфических аномалий — общая
        if not candidates:
            conf = self._compute_confidence(
                'Общая аномалия', mse_score, features_dict,
                relevant_features=[]
            )
            candidates.append({
                'threat_type': 'Общая аномалия',
                'confidence': conf,
                'description': (
                    f'Обнаружена аномальная активность (MSE: {mse_score:.2f}). '
                    f'Специфический тип аномалии не определён, но поведение '
                    f'отклоняется от базового профиля пользователя.'
                ),
                'mitre_attack': 'Не определено',
                'recommendations': [
                    'Проанализировать телеметрию вручную',
                    'Проверить системные журналы',
                    'Сравнить с базовым профилем пользователя'
                ]
            })

        # Возвращаем аномалию с максимальной уверенностью
        best = max(candidates, key=lambda x: x['confidence'])

        # Если обнаружено несколько аномалий — добавляем информацию о них
        if len(candidates) > 1:
            others = [c['threat_type'] for c in candidates if c != best]
            best['description'] += (
                f"\n\n Дополнительно обнаружены аномалии: "
                f"{', '.join(others)}."
            )

        return best