"""
Запуск всех симуляций по очереди.
Каждая симуляция длится 20 минут.
"""

import subprocess
import sys
import time
import os
from datetime import datetime

time_of_simulation = 20*60
time_of_rest = 20*60
SIMULATIONS = [
    ('sim_exfiltration.py', 'Data Exfiltration', time_of_simulation),
    ('sim_portscan.py', 'Port Scanning', time_of_simulation),
    ('sim_c2_beacon.py', 'C2 Beaconing', time_of_simulation),
    ('sim_ransomware.py', 'Ransomware Activity', time_of_simulation),
    ('sim_bruteforce.py', 'BRUTE FORCE', time_of_simulation),
    ('sim_cryptomining.py', 'Cryptomining / CPU Load', time_of_simulation)
]


def main():
    print("=" * 60)
    print("🎯 ЗАПУСК ВСЕХ СИМУЛЯЦИЙ УГРОЗ")
    print("=" * 60)
    print(f"Всего симуляций: {len(SIMULATIONS)}")
    print(f"Длительность каждой: {SIMULATIONS[0][2]} сек")
    print(f"Общее время: ~{(len(SIMULATIONS) * time_of_simulation + (len(SIMULATIONS) - 1) * time_of_rest) // 60} минут")


    sim_dir = os.path.dirname(os.path.abspath(__file__))

    for i, (script, name, duration) in enumerate(SIMULATIONS, 1):
        print(f"\n{'=' * 60}")
        print(datetime.now().strftime('%H:%M:%S'))
        print(f"📌 Симуляция {i}/{len(SIMULATIONS)}: {name}")
        print(f"   Длительность: {duration} сек")
        print(f"{'=' * 60}\n")

        script_path = os.path.join(sim_dir, script)

        try:
            # Запускаем симуляцию как отдельный процесс
            proc = subprocess.Popen(
                [sys.executable, script_path],
                cwd=sim_dir
            )

            # Ждем указанное время
            try:
                proc.wait(timeout=duration)
            except subprocess.TimeoutExpired:
                # Время вышло — останавливаем
                proc.terminate()
                proc.wait(timeout=5)
                print(f"\n   ⏹ Время вышло, симуляция остановлена")

            print(f"\n   ✅ Симуляция '{name}' завершена")
            print(datetime.now().strftime('%H:%M:%S'))
            print(f"перерыв {time_of_rest//60} мин")
            time.sleep(time_of_rest)  # Пауза между симуляциями

        except KeyboardInterrupt:
            print(f"\n\n⏹ Все симуляции остановлены пользователем")
            proc.terminate()
            break

    print(f"\n{'=' * 60}")
    print("🎉 ВСЕ СИМУЛЯЦИИ ЗАВЕРШЕНЫ")
    print("=" * 60)




if __name__ == '__main__':
    main()