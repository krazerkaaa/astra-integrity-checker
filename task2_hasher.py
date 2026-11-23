#!/usr/bin/env python3
"""
Модуль расчёта контрольных сумм SHA-256, сбора метаданных и резервного кэширования.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import stat
import tempfile
from typing import Any

logging.basicConfig(
    filename="hash_generation.log",
    level=logging.INFO,
    format="%(asctime)s - [TASK 2] - %(levelname)s - %(message)s",
    encoding="utf-8",
)

DEFAULT_CACHE_DIR = ".baseline_cache"
MAX_CACHE_FILE_SIZE = 5 * 1024 * 1024  # 5 МБ
SNIFF_SIZE = 8192
CHUNK_SIZE = 1024 * 1024


def _atomic_write(path: str, data: bytes, mode: int = 0o600) -> None:
    """Атомарная запись: сначала во временный файл, затем os.replace."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def get_cache_path(filepath: str, cache_dir: str = DEFAULT_CACHE_DIR) -> str:
    """Детерминированный путь к сжатой копии эталонного файла в кэше."""
    abs_path = os.path.abspath(filepath)
    digest = hashlib.sha256(abs_path.encode("utf-8")).hexdigest()[:16]
    name = os.path.basename(abs_path)[:100]
    return os.path.join(cache_dir, f"{digest}_{name}.gz")


def _ensure_cache_dir(cache_dir: str) -> None:
    os.makedirs(cache_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(cache_dir, 0o700)
    except OSError:
        pass


def _store_backup(filepath: str, data: bytes, cache_dir: str) -> str:
    _ensure_cache_dir(cache_dir)
    cache_path = get_cache_path(filepath, cache_dir)
    _atomic_write(cache_path, gzip.compress(data), mode=0o600)
    logging.info(f"Резервная копия сохранена: {filepath} -> {cache_path}")
    return cache_path


def remove_backup(filepath: str, cache_dir: str = DEFAULT_CACHE_DIR, explicit_cache_path: str | None = None) -> bool:
    """Удаляет резервную копию файла из кэша."""
    removed = False
    candidates = [explicit_cache_path, get_cache_path(filepath, cache_dir)]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            try:
                os.unlink(candidate)
                removed = True
            except OSError as e:
                logging.warning(f"Не удалось удалить копию {candidate}: {e}")
    return removed


def calculate_sha256(filepath: str, block_size: int = 4096) -> str | None:
    """Потоковый расчёт SHA-256 файла."""
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


def build_baseline_record(
    filepath: str,
    cache_dir: str = DEFAULT_CACHE_DIR,
    use_cache: bool = True,
) -> dict[str, Any] | None:
    """
    Формирует единую запись эталона: SHA-256, метаданные (st_size, st_mode, st_mtime)
    и путь к сжатой резервной копии в .baseline_cache/ (только для текстовых файлов <= 5 МБ).
    """
    try:
        st = os.stat(filepath)
        is_regular = stat.S_ISREG(st.st_mode)
        cache_file: str | None = None

        with open(filepath, "rb") as f:
            sample = f.read(SNIFF_SIZE)
            is_text = b"\0" not in sample

            if use_cache and is_regular and is_text and st.st_size <= MAX_CACHE_FILE_SIZE:
                data = sample + f.read()
                digest = hashlib.sha256(data).hexdigest()
                try:
                    cache_file = _store_backup(filepath, data, cache_dir)
                except Exception as e:
                    logging.warning(f"Не удалось сохранить копию {filepath}: {e}")
            else:
                sha256_hash = hashlib.sha256()
                sha256_hash.update(sample)
                for block in iter(lambda: f.read(CHUNK_SIZE), b""):
                    sha256_hash.update(block)
                digest = sha256_hash.hexdigest()
                if use_cache:
                    remove_backup(filepath, cache_dir)

        return {
            "sha256": digest,
            "st_size": st.st_size,
            "st_mode": st.st_mode,
            "st_mtime": st.st_mtime,
            "cache_file": cache_file,
        }
    except PermissionError:
        logging.error(f"Отказано в доступе: {filepath}")
    except FileNotFoundError:
        logging.error(f"Файл не существует: {filepath}")
    except Exception as e:
        logging.error(f"Ошибка при обработке {filepath}: {e}")
    return None


def load_baseline_file(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_baseline_file(path: str, data: dict[str, Any]) -> None:
    payload = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    _atomic_write(path, payload, mode=0o600)


def _read_file_list(list_path: str) -> list[str]:
    with open(list_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def build_baseline_db(
    input_list_path: str,
    output_db_path: str,
    cache_dir: str = DEFAULT_CACHE_DIR,
    use_cache: bool = True,
    extra_records: dict[str, dict[str, Any]] | None = None,
) -> bool:
    """Полная сборка эталонной базы по списку файлов и дополнительным записям (MBR/PBR)."""
    if not os.path.exists(input_list_path):
        print(f"[!] Ошибка: Файл со списком путей '{input_list_path}' не найден!")
        return False

    print(f"[*] Чтение списка файлов из: {input_list_path}")
    files_to_hash = _read_file_list(input_list_path)
    print(f"[*] Начат расчёт хеш-сумм SHA-256 (файлов в списке: {len(files_to_hash)})...")

    baseline_data: dict[str, Any] = {}
    for filepath in files_to_hash:
        record = build_baseline_record(filepath, cache_dir, use_cache)
        if record:
            baseline_data[filepath] = record
            print(f"  [+] Обработан: {filepath}")
        else:
            print(f"  [-] Пропущен: {filepath}")

    if extra_records:
        for sector_key, record in extra_records.items():
            baseline_data[sector_key] = record
            print(f"  [+] Обработан загрузочный сектор: {sector_key}")

    try:
        save_baseline_file(output_db_path, baseline_data)
        print(f"\n[OK] База эталонов сохранена в: {output_db_path} (всего записей: {len(baseline_data)})")
        if use_cache:
            print(f"[OK] Резервные копии текстовых конфигов сохранены в: {cache_dir}/")
        logging.info(f"База успешно сформирована. Записей: {len(baseline_data)}")
        return True
    except Exception as e:
        print(f"[!] Ошибка сохранения базы: {e}")
        logging.critical(f"Сбой записи JSON: {e}")
        return False


def update_baseline(
    baseline_path: str,
    target: str | None = None,
    list_path: str = "critical_files_list.txt",
    cache_dir: str = DEFAULT_CACHE_DIR,
    use_cache: bool = True,
) -> bool:
    """
    Обновляет эталон:
    - если указан target: обновляет хеш, метаданные и копию в кэше только для этого файла;
    - если target не указан: пересчитывает всю базу по списку list_path.
    """
    if target is None:
        print("[*] Путь не указан: пересчёт всего эталона по текущему списку.")
        logging.info("update: полный пересчёт эталона")
        sector_records: dict[str, dict[str, Any]] = {}
        try:
            import task1_scanner
            _, sector_records = task1_scanner.scan_boot_sectors()
        except Exception:
            pass
        return build_baseline_db(list_path, baseline_path, cache_dir, use_cache, extra_records=sector_records)

    if not os.path.exists(baseline_path):
        print(f"[!] Эталон '{baseline_path}' не найден. Сначала выполните build-baseline.")
        return False

    target_path = os.path.abspath(target)
    if not os.path.isfile(target_path):
        print(f"[!] Файл не найден или не является обычным файлом: {target_path}")
        return False

    try:
        baseline_data = load_baseline_file(baseline_path)
    except Exception as e:
        print(f"[!] Не удалось прочитать эталон '{baseline_path}': {e}")
        return False

    old_entry = baseline_data.get(target_path)
    old_hash = old_entry["sha256"] if isinstance(old_entry, dict) else old_entry

    new_record = build_baseline_record(target_path, cache_dir, use_cache)
    if new_record is None:
        print(f"[!] Не удалось вычислить хеш (проверьте права доступа): {target_path}")
        return False

    baseline_data[target_path] = new_record
    try:
        save_baseline_file(baseline_path, baseline_data)
    except Exception as e:
        print(f"[!] Ошибка сохранения базы: {e}")
        logging.critical(f"Сбой записи JSON при обновлении: {e}")
        return False

    if old_hash is None:
        print(f"[+] Файл добавлен в эталон: {target_path}")
        print("    (Рекомендуется также добавить путь через команду 'add', чтобы он сохранился в списке контроля)")
        logging.info(f"update: файл добавлен в эталон: {target_path}")
    elif old_hash == new_record["sha256"]:
        print(f"[=] Хеш не изменился, метаданные и кэш актуализированы: {target_path}")
    else:
        print(f"[OK] Эталон обновлён: {target_path}")
        print(f"     было:  {old_hash}")
        print(f"     стало: {new_record['sha256']}")
        logging.info(f"update: хеш обновлён: {target_path} {old_hash} -> {new_record['sha256']}")
    return True