"""
Симуляция атаки Brute-Force (Подбор пароля).
Генерирует события Windows Event ID 4625 (Failed Logon) через системный API.

Безопасность:
- Используется заведомо несуществующий пользователь (FakeHackerUser).
- Реальный пользователь не будет заблокирован.
- Не требует прав администратора для запуска самой симуляции.

"""

import ctypes
import time
import sys


def simulate_bruteforce():
    print("=" * 60)
    print("🔴 СИМУЛЯЦИЯ: Brute-Force Attack")
    print("=" * 60)
    print("Генерация событий Event ID 4625 (Failed Logon)...")
    print("Используется фиктивный пользователь: 'FakeHackerUser'")


    #ненастоящие данные
    username = "FakeHackerUser_999"
    password = "WrongPassword123!"
    domain = "."

    # Константы для API LogonUser
    LOGON32_LOGON_NETWORK = 3
    LOGON32_PROVIDER_DEFAULT = 0

    token = ctypes.c_void_p()
    attempts = 0
    start_time = time.time()

    try:
        while True:
            # Пытаемся выполнить вход с неверными данными
            # Это гарантированно завершится ошибкой и создаст Event ID 4625
            result = ctypes.windll.advapi32.LogonUserW(
                username, domain, password,
                LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT,
                ctypes.byref(token)
            )

            attempts += 1

            # Выводим прогресс каждые 100 попыток
            if attempts % 100 == 0:
                elapsed = time.time() - start_time
                rate = attempts / elapsed if elapsed > 0 else 0
                print(f"\r  📤 Попыток входа: {attempts} | "
                      f"Скорость: {rate:.1f} попыток/сек", end="", flush=True)

            # Небольшая задержка, чтобы:
            # 1. Не перегрузить систему
            # 2. Дать collector.py время собрать данные за 1-минутное окно
            time.sleep(0.05)

    except KeyboardInterrupt:
        print(f"\n\n⏹ Симуляция остановлена")
        print(f"   Всего попыток: {attempts}")
        print(f"   Длительность: {time.time() - start_time:.0f} сек")



if __name__ == '__main__':
    simulate_bruteforce()