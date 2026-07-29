"""
Симуляция эксфильтрации данных.
создаёт сетевую нагрузку на localhost.
"""

import socket
import time
import threading
import sys


def server_worker(port, stop_event):
    """Сервер принимает данные"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', port))
    server.listen(1)
    server.settimeout(1)

    while not stop_event.is_set():
        try:
            conn, addr = server.accept()
            while not stop_event.is_set():
                data = conn.recv(65536)
                if not data:
                    break
        except socket.timeout:
            continue
        except OSError:
            break

    server.close()


def client_worker(port, chunk_size, interval, stop_event):
    """Клиент непрерывно отправляет данные"""
    data = b'X' * chunk_size
    sent_bytes = 0

    while not stop_event.is_set():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect(('127.0.0.1', port))

            while not stop_event.is_set():
                sock.sendall(data)
                sent_bytes += chunk_size
                time.sleep(interval)
        except Exception as e:
            time.sleep(0.5)

    return sent_bytes


def main():
    num_connections = 30
    base_port = 20000
    chunk_size = 1024 * 500
    interval = 0.01

    print("=" * 60)
    print("🔴 СИМУЛЯЦИЯ: Data Exfiltration v5")
    print("=" * 60)
    print(f"Создание {num_connections} TCP-соединений на порты {base_port}-{base_port+num_connections-1}")
    print(f"Каждое соединение отправляет {chunk_size/1024:.0f} KB каждые {interval*1000:.0f} мс")
    print(f"Ожидаемая скорость: ~{num_connections * chunk_size / interval / (1024*1024):.1f} MB/с")


    stop_event = threading.Event()

    # Запускаем серверы
    servers = []
    for i in range(num_connections):
        port = base_port + i
        t = threading.Thread(target=server_worker, args=(port, stop_event), daemon=True)
        t.start()
        servers.append(t)

    time.sleep(0.5)  # Даём серверам запуститься

    # Запускаем клиенты
    clients = []
    for i in range(num_connections):
        port = base_port + i
        t = threading.Thread(target=client_worker, args=(port, chunk_size, interval, stop_event), daemon=True)
        t.start()
        clients.append(t)

    print(f"   ✓ Запущено {num_connections} серверов и {num_connections} клиентов")
    print(f"   ✓ Ожидаемая нагрузка: ~{num_connections * chunk_size / interval / (1024*1024):.1f} MB/с\n")

    start_time = time.time()

    try:
        while True:
            elapsed = time.time() - start_time
            print(f"\r  📤 Активных соединений: {num_connections} | "
                  f"Время: {elapsed:.0f}с", end="", flush=True)
            time.sleep(1)

    except KeyboardInterrupt:
        print(f"\n\n⏹ Симуляция остановлена")
        print(f"   Длительность: {time.time() - start_time:.0f} сек")
    finally:
        stop_event.set()
        time.sleep(1)


if __name__ == '__main__':
    main()