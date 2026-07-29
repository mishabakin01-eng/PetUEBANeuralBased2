"""
Симуляция сканирования портов
Держит соединения открытыми, чтобы они попали в снимок psutil.
"""

import socket
import time
import sys
import threading


def scan_and_hold(host, port, hold_time=2.0):
    """Открывает соединение и держит его открытым"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            # Держим соединение открытым
            time.sleep(hold_time)
        sock.close()
        return result == 0
    except:
        return False


def main():
    host = '127.0.0.1'

    print("=" * 60)
    print("🔴 СИМУЛЯЦИЯ: Network Port Scanning (улучшенная)")
    print("=" * 60)
    print(f"Сканирование портов на {host} с удержанием соединений...")


    # Сканируем порты пакетами, держим каждое соединение 2 секунды
    batch_size = 50
    total_scanned = 0
    start_time = time.time()

    try:
        while True:
            # Сканируем порты пакетами
            for batch_start in range(1, 10000, batch_size):
                threads = []
                for port in range(batch_start, min(batch_start + batch_size, 10000)):
                    t = threading.Thread(
                        target=scan_and_hold,
                        args=(host, port, 2.0),
                        daemon=True
                    )
                    t.start()
                    threads.append(t)
                    total_scanned += 1

                # Ждем, пока все соединения в пакте закроются
                for t in threads:
                    t.join(timeout=3)

                # Небольшая пауза между пакетами
                time.sleep(0.5)

                if total_scanned % 500 == 0:
                    elapsed = time.time() - start_time
                    print(f"\r  Просканировано: {total_scanned} портов | "
                          f"Время: {elapsed:.0f} сек", end="", flush=True)

    except KeyboardInterrupt:
        print(f"\n\n⏹ Симуляция остановлена")
        print(f"   Всего просканировано: {total_scanned} портов")


if __name__ == '__main__':
    main()