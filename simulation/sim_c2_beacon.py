"""
Симуляция C2-маячков
Генерирует частые соединения и держит их открытыми.
"""

import socket
import time
import sys
import threading


def send_beacon(target_host, target_port, beacon_id, hold_time=10.0):
    """Отправляет beacon и держит соединение"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_host, target_port))

        beacon_data = f"BEACON|id={beacon_id}|host=PC-USER|user=admin|pid=1234"
        sock.sendall(beacon_data.encode())

        # Держим соединение открытым
        time.sleep(hold_time)
        sock.close()
    except (ConnectionRefusedError, socket.timeout, OSError):
        pass


def main():
    beacon_interval = 1
    target_host = '127.0.0.1'
    target_port = 8443
    hold_time = 15.0

    print("=" * 60)
    print("🔴 СИМУЛЯЦИЯ: C2 Beaconing (улучшенная)")
    print("=" * 60)
    print(f"Генерация beacon-соединений каждые {beacon_interval} сек")
    print(f"Каждое соединение держится {hold_time} сек")
    print(f"Цель: {target_host}:{target_port}")


    # Создаем сервер
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((target_host, target_port))
        server.listen(100)
        server.settimeout(1)
    except OSError:
        print("⚠️  Не удалось создать сервер")
        server = None

    def accept_connections():
        while True:
            try:
                if server:
                    conn, addr = server.accept()
                    conn.recv(4096)
                    conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    if server:
        accept_thread = threading.Thread(target=accept_connections, daemon=True)
        accept_thread.start()

    beacon_count = 0
    start_time = time.time()

    try:
        while True:
            beacon_count += 1

            # Запускаем beacon в отдельном потоке
            t = threading.Thread(
                target=send_beacon,
                args=(target_host, target_port, beacon_count, hold_time),
                daemon=True
            )
            t.start()

            elapsed = time.time() - start_time
            print(f"\r   [{elapsed:.0f}s] Beacon #{beacon_count} запущен "
                  f"(активных: ~{min(beacon_count, int(hold_time/beacon_interval))})",
                  end="", flush=True)

            time.sleep(beacon_interval)

    except KeyboardInterrupt:
        print(f"\n\n⏹ Симуляция остановлена")
        print(f"   Всего beacon-ов: {beacon_count}")
    finally:
        if server:
            server.close()


if __name__ == '__main__':
    main()