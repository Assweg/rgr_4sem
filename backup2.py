import os
import shutil
import datetime
import json
import zipfile
import hashlib
import psycopg2
from typing import List, Dict
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('backup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Конфигурация
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKUP_DIR = os.path.join(PROJECT_DIR, "backups")
DATABASE_CONFIG = {
    "dbname": "security_db",
    "user": "user",
    "password": "password",
    "host": "localhost",
    "port": "5433"
}

# Файлы и директории для резервного копирования
FILES_TO_BACKUP = [
    "security.log",
    "users.json",
    "app.py",
    "init.sql",
    "requirements.txt",
    "docker-compose.yml",
    "docker-compose.attack.yml",
    "nginx.conf"
]

DIRS_TO_BACKUP = [
    "templates",
    "docker"
]

MAX_BACKUPS = 5  # Максимальное количество хранящихся бэкапов

def calculate_file_hash(file_path: str) -> str:
    """Вычисляет SHA-256 хеш файла"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def backup_database() -> str:
    """Создает резервную копию базы данных"""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"db_backup_{timestamp}.sql")
    
    try:
        # Создаем дамп базы данных
        os.system(f'docker exec rgr-db-1 pg_dump -U user security_db > {backup_file}')
        logger.info(f"База данных успешно сохранена в {backup_file}")
        return backup_file
    except Exception as e:
        logger.error(f"Ошибка при создании резервной копии базы данных: {e}")
        return None

def create_backup_info(backup_dir: str, files_backed_up: List[str]) -> Dict:
    """Создает информационный файл о резервной копии"""
    info = {
        "timestamp": datetime.datetime.now().isoformat(),
        "files": {},
        "total_size": 0
    }
    
    for file_path in files_backed_up:
        if os.path.exists(file_path):
            file_info = {
                "size": os.path.getsize(file_path),
                "hash": calculate_file_hash(file_path)
            }
            info["files"][file_path] = file_info
            info["total_size"] += file_info["size"]
    
    return info

def create_backup():
    """Создает полную резервную копию проекта"""
    try:
        # Создаем папку backups если её нет
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)
            logger.info(f"Создана директория для резервных копий: {BACKUP_DIR}")

        # Создаем подпапку с временной меткой
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_subdir = os.path.join(BACKUP_DIR, timestamp)
        os.makedirs(backup_subdir)
        logger.info(f"Создана директория для текущей резервной копии: {backup_subdir}")

        # Список всех скопированных файлов
        backed_up_files = []

        # Копируем отдельные файлы
        for filename in FILES_TO_BACKUP:
            src_path = os.path.join(PROJECT_DIR, filename)
            if os.path.exists(src_path):
                dst_path = os.path.join(backup_subdir, filename)
                shutil.copy2(src_path, dst_path)
                backed_up_files.append(src_path)
                logger.info(f"Скопирован файл: {filename}")
            else:
                logger.warning(f"Файл не найден: {filename}")

        # Копируем директории
        for dirname in DIRS_TO_BACKUP:
            src_path = os.path.join(PROJECT_DIR, dirname)
            if os.path.exists(src_path):
                dst_path = os.path.join(backup_subdir, dirname)
                shutil.copytree(src_path, dst_path)
                backed_up_files.append(src_path)
                logger.info(f"Скопирована директория: {dirname}")
            else:
                logger.warning(f"Директория не найдена: {dirname}")

        # Создаем резервную копию базы данных
        db_backup = backup_database()
        if db_backup:
            backed_up_files.append(db_backup)

        # Создаем информационный файл о резервной копии
        backup_info = create_backup_info(backup_subdir, backed_up_files)
        with open(os.path.join(backup_subdir, "backup_info.json"), "w") as f:
            json.dump(backup_info, f, indent=2)
        logger.info("Создан информационный файл о резервной копии")

        # Создаем ZIP-архив
        zip_path = f"{backup_subdir}.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(backup_subdir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, backup_subdir)
                    zipf.write(file_path, arcname)
        logger.info(f"Создан ZIP-архив: {zip_path}")

        # Удаляем распакованную версию
        shutil.rmtree(backup_subdir)
        logger.info("Удалена распакованная версия резервной копии")

        # Удаляем старые бэкапы
        backups = sorted(
            [f for f in os.listdir(BACKUP_DIR) if f.endswith('.zip')],
            reverse=True
        )

        for old_backup in backups[MAX_BACKUPS:]:
            old_backup_path = os.path.join(BACKUP_DIR, old_backup)
            try:
                os.remove(old_backup_path)
                logger.info(f"Удален устаревший бэкап: {old_backup}")
            except Exception as e:
                logger.error(f"Не удалось удалить {old_backup}: {e}")

        logger.info("Резервное копирование успешно завершено")
        return True

    except Exception as e:
        logger.error(f"Ошибка при создании резервной копии: {e}")
        return False

def restore_backup(backup_path: str) -> bool:
    """Восстанавливает проект из резервной копии"""
    try:
        # Создаем временную директорию для распаковки
        temp_dir = os.path.join(BACKUP_DIR, "temp_restore")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        os.makedirs(temp_dir)

        # Распаковываем архив
        with zipfile.ZipFile(backup_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)

        # Проверяем информацию о бэкапе
        with open(os.path.join(temp_dir, "backup_info.json"), "r") as f:
            backup_info = json.load(f)

        # Восстанавливаем файлы
        for filename in FILES_TO_BACKUP:
            src_path = os.path.join(temp_dir, filename)
            if os.path.exists(src_path):
                dst_path = os.path.join(PROJECT_DIR, filename)
                shutil.copy2(src_path, dst_path)
                logger.info(f"Восстановлен файл: {filename}")

        # Восстанавливаем директории
        for dirname in DIRS_TO_BACKUP:
            src_path = os.path.join(temp_dir, dirname)
            if os.path.exists(src_path):
                dst_path = os.path.join(PROJECT_DIR, dirname)
                if os.path.exists(dst_path):
                    shutil.rmtree(dst_path)
                shutil.copytree(src_path, dst_path)
                logger.info(f"Восстановлена директория: {dirname}")

        # Восстанавливаем базу данных
        db_backup = os.path.join(temp_dir, "db_backup_*.sql")
        if os.path.exists(db_backup):
            os.system(f'docker exec -i rgr-db-1 psql -U user security_db < {db_backup}')
            logger.info("База данных восстановлена")

        # Удаляем временную директорию
        shutil.rmtree(temp_dir)
        logger.info("Восстановление успешно завершено")
        return True

    except Exception as e:
        logger.error(f"Ошибка при восстановлении из резервной копии: {e}")
        return False

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Утилита для резервного копирования и восстановления проекта")
    parser.add_argument('--action', choices=['backup', 'restore'], default='backup', help='Действие: backup или restore')
    parser.add_argument('--backup-path', help='Путь к файлу резервной копии для восстановления')
    
    args = parser.parse_args()
    
    if args.action == 'backup':
        logger.info("Начало создания резервной копии...")
        success = create_backup()
        if success:
            logger.info("Резервное копирование успешно завершено")
        else:
            logger.error("Ошибка при создании резервной копии")
    else:
        if not args.backup_path:
            logger.error("Не указан путь к файлу резервной копии")
        else:
            logger.info(f"Начало восстановления из резервной копии: {args.backup_path}")
            success = restore_backup(args.backup_path)
            if success:
                logger.info("Восстановление успешно завершено")
            else:
                logger.error("Ошибка при восстановлении") 