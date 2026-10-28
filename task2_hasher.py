import hashlib
import json
import logging
import os

logging.basicConfig(
    filename='hash_generation.log',
    level=logging.INFO,
    format='%(asctime)s - [TASK 2] - %(levelname)s - %(message)s',
    encoding='utf-8'
)


def calculate_sha256(filepath, block_size=4096):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(block_size), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except PermissionError:
        logging.error(f"Отказано в доступе: {filepath}")
        return None
    except FileNotFoundError:
        logging.error(f"Файл не существует: {filepath}")
        return None
    except Exception as e:
        logging.error(f"Ошибка при чтении {filepath}: {e}")
        return None


def build_baseline_db(input_list_path, output_db_path):
    if not os.path.exists(input_list_path):
        print(f"Ошибка: Файл со списком путей '{input_list_path}' не найден!")
        return

    baseline_data = {}

    print(f"[*] Чтение списка файлов из: {input_list_path}")
    with open(input_list_path, 'r', encoding='utf-8') as f:
        files_to_hash = [line.strip() for line in f if line.strip()]

    print(f"[*] Начат расчет хеш-сумм SHA-256 (всего файлов: {len(files_to_hash)})...")

    for filepath in files_to_hash:
        file_hash = calculate_sha256(filepath)
        if file_hash:
            baseline_data[filepath] = file_hash
            print(f"  [+] Обработан: {filepath}")
        else:
            print(f"  [-] Пропущен: {filepath}")

    try:
        with open(output_db_path, 'w', encoding='utf-8') as db_file:
            json.dump(baseline_data, db_file, indent=4)
        print(f"\n[OK] Задача 2 выполнена. База сохранена в: {output_db_path}")
        logging.info(f"База успешно сформирована. Хешировано файлов: {len(baseline_data)}")
    except Exception as e:
        print(f"[!] Ошибка сохранения базы: {e}")
        logging.critical(f"Сбой записи JSON: {e}")


if __name__ == "__main__":
    # Настраиваем пути специально для тестирования на Windows
    INPUT_FILE = os.path.join('test_data', 'critical_files.txt')
    OUTPUT_FILE = os.path.join('test_data', 'hashes_baseline.json')

    build_baseline_db(INPUT_FILE, OUTPUT_FILE)