import os
import shutil
import datetime

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKUP_DIR = os.path.join(PROJECT_DIR, "backups")
FILES_TO_BACKUP = ["security.log", "users.json"]

MAX_BACKUPS = 5  # Максимальное количество хранящихся бэкапов

def create_backup():
    # Создаем папку backups
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

    # Формируем имя подпапки с текущей датой и временем
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_subdir = os.path.join(BACKUP_DIR, timestamp)
    os.makedirs(backup_subdir)

    # Копируем нужные файлы
    for filename in FILES_TO_BACKUP:
        src_path = os.path.join(PROJECT_DIR, filename)
        if os.path.exists(src_path):
            shutil.copy2(src_path, backup_subdir)
            print(f"{filename} — сохранён в {backup_subdir}")
        else:
            print(f"{filename} — не найден")

    # Удаляем старые бэкапы, если их больше MAX_BACKUPS
    backups = sorted(
        [f for f in os.listdir(BACKUP_DIR) if os.path.isdir(os.path.join(BACKUP_DIR, f))],
        reverse=True
    )

    for old_backup in backups[MAX_BACKUPS:]:
        old_backup_path = os.path.join(BACKUP_DIR, old_backup)
        try:
            shutil.rmtree(old_backup_path)
            print(f"Удалён устаревший бэкап: {old_backup}")
        except Exception as e:
            print(f"Не удалось удалить {old_backup}: {e}")

if __name__ == "__main__":
    print(f"\nCоздание бэкапа... {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    create_backup()
    print("Бэкап успешно завершён.\n")