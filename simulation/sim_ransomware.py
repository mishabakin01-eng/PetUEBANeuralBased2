"""
Симуляция активности шифровальщика
Генерирует массовую запись файлов на диск.

Безопасность: файлы создаются во временной папке и удаляются после остановки.
"""

import os
import time
import tempfile
import shutil
import sys


def main():
    # Создаем временную папку для "зашифрованных" файлов
    temp_dir = tempfile.mkdtemp(prefix='ransomware_sim_')

    print("=" * 60)
    print("🔴 СИМУЛЯЦИЯ: Ransomware Activity")
    print("=" * 60)
    print(f"Временная папка: {temp_dir}")
    print("Генерация массовой записи файлов...")
    print("Нажмите Ctrl+C для остановки\n")

    files_created = 0
    total_bytes = 0
    start_time = time.time()

    try:
        while True:
            # Создаем "зашифрованный" файл
            filename = f"document_{files_created:06d}.encrypted"
            filepath = os.path.join(temp_dir, filename)

            # Записываем 1 MB "зашифрованных" данных
            chunk_size = 1024 * 1024
            with open(filepath, 'wb') as f:
                f.write(os.urandom(chunk_size))

            files_created += 1
            total_bytes += chunk_size

            elapsed = time.time() - start_time
            rate_mb = (total_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0

            print(f"\r  Файлов: {files_created} | "
                  f"Записано: {total_bytes / (1024 * 1024):.0f} MB | "
                  f"Скорость: {rate_mb:.1f} MB/s", end="", flush=True)

            # Небольшая задержка
            time.sleep(0.1)

    except KeyboardInterrupt:
        print(f"\n\n⏹ Симуляция остановлена")
        print(f"   Файлов создано: {files_created}")
        print(f"   Всего записано: {total_bytes / (1024 * 1024):.0f} MB")
        print(f"   Длительность: {time.time() - start_time:.0f} сек")
    finally:
        # ОЧИСТКА: удаляем все временные файлы
        print(f"\n   Очистка временной папки...")
        try:
            shutil.rmtree(temp_dir)
            print(f"   ✅ Временные файлы удалены")
        except Exception as e:
            print(f"   ⚠️  Ошибка очистки: {e}")



if __name__ == '__main__':
    main()