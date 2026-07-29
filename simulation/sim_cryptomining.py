"""
Симуляция криптоджекинга (Cryptomining).
Загружает CPU на 100% математическими вычислениями.

Безопасность: только вычисления, никакого реального майнинга.
"""

import multiprocessing
import time
import math
import sys
import os


def cpu_stress_worker(worker_id):
    """Рабочий процесс, нагружающий одно ядро CPU"""
    while True:
        # Тяжелые математические вычисления
        result = 0
        for i in range(1, 10000):
            result += math.sin(i) * math.cos(i) * math.sqrt(i)


def main():
    # Количество потоков = количество ядер CPU
    num_workers = multiprocessing.cpu_count()

    print("=" * 60)
    print("🔴 СИМУЛЯЦИЯ: Cryptomining / Resource Hijacking")
    print("=" * 60)
    print(f"Запуск {num_workers} рабочих процессов (по числу ядер CPU)...")


    processes = []

    try:
        # Запускаем рабочие процессы
        for i in range(num_workers):
            p = multiprocessing.Process(target=cpu_stress_worker, args=(i,))
            p.daemon = True
            p.start()
            processes.append(p)
            print(f"   ✓ Рабочий процесс #{i + 1} запущен (PID: {p.pid})")

        print(f"\n   CPU загружен на ~100%. Ожидание...")

        # Ждем, пока пользователь не нажмет Ctrl+C
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print(f"\n\n⏹ Симуляция остановлена")
        print(f"   Завершение {len(processes)} процессов...")
    finally:
        for p in processes:
            p.terminate()
            p.join(timeout=2)
        print("   Все процессы завершены.")


if __name__ == '__main__':
    multiprocessing.freeze_support()
    main()