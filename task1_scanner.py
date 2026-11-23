#!/usr/bin/env python3
"""
Модуль формирования и управления перечнем критически важных файлов ОС Astra Linux.
Поддерживает автоматическое сканирование (конфиги, модули PARSEC, EFI, MBR/PBR)
и ручное управление списком (команды add / remove).
"""
from __future__ import annotations

import glob
import hashlib
import os
from typing import Any

import task2_hasher

LIST_FILE = "critical_files_list.txt"
BASELINE_FILE = "hashes_baseline.json"

WILDCARD_PATHS = (
    "/boot/vmlinuz-*",
    "/boot/initrd.img-*",
    "/boot/grub/*",
    "/lib/modules/*/misc/digsig_verif.ko",
    "/lib/modules/*/misc/parsec.ko",
    "/lib/modules/*/misc/parsec-cifs.ko",
)

DIRECTORY_GLOBAL = [
    "/boot/grub/grub.cfg",
    "/boot/grub/grub.conf",
    "/etc/astra_license",
    "/etc/nsswitch.conf",
    "/etc/pam.d/fly-dm",
    "/etc/pam.d/fly-dm-np",
    "/etc/pam.d/login",
    "/etc/pam.d/passwd",
    "/etc/pam.d/su",
    "/etc/pam.d/sumac.xauth",
    "/etc/pam.d/xrdp-sesman",
    "/etc/resolv.conf",
    "/etc/hosts.allow",
    "/etc/hosts.deny",
    "/etc/network/interfaces",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
    "/etc/samba/smb.conf",
    "/etc/apache2/apache2.conf",
]


def scan_boot_sectors() -> tuple[list[str], dict[str, dict[str, Any]]]:
    """
    Сканирует подключённые блочные устройства и вычисляет хеши MBR (512 байт),
    секторов 1-63 и загрузочных секторов разделов PBR (512 байт).
    """
    sector_records: dict[str, dict[str, Any]] = {}
    scanned_info: list[str] = []

    directory_mbr: list[str] = []
    directory_pbr: list[str] = []

    for pattern in ("/dev/sd?", "/dev/vd?", "/dev/nvme?n?", "/dev/mmcblk?"):
        directory_mbr.extend(glob.glob(pattern))

    for disk in directory_mbr:
        part_pattern = f"{disk}p*" if ("nvme" in disk or "mmcblk" in disk) else f"{disk}[0-9]*"
        directory_pbr.extend(glob.glob(part_pattern))

    for disk in directory_mbr:
        if os.path.exists(disk):
            try:
                with open(disk, "rb") as f:
                    f.seek(0)
                    mbr_bytes = f.read(512)
                    if mbr_bytes:
                        key_mbr = f"{disk}_MBR"
                        sector_records[key_mbr] = {
                            "sha256": hashlib.sha256(mbr_bytes).hexdigest(),
                            "is_boot_sector": True,
                            "device": disk,
                            "sector_type": "MBR",
                        }
                        scanned_info.append(key_mbr)

                    f.seek(512)
                    sectors_1_63 = f.read(512 * 63)
                    if sectors_1_63:
                        key_sec = f"{disk}_1_to_63_sectors"
                        sector_records[key_sec] = {
                            "sha256": hashlib.sha256(sectors_1_63).hexdigest(),
                            "is_boot_sector": True,
                            "device": disk,
                            "sector_type": "1_to_63_sectors",
                        }
                        scanned_info.append(key_sec)
            except PermissionError:
                print(f"[!] Нет доступа к диску {disk} для чтения MBR (требуется root)")
            except Exception as exc:
                print(f"[!] Ошибка чтения MBR/секторов ({disk}): {exc}")

    for part in directory_pbr:
        if os.path.exists(part):
            try:
                with open(part, "rb") as f:
                    f.seek(0)
                    pbr_bytes = f.read(512)
                    if pbr_bytes:
                        key_pbr = f"{part}_PBR"
                        sector_records[key_pbr] = {
                            "sha256": hashlib.sha256(pbr_bytes).hexdigest(),
                            "is_boot_sector": True,
                            "device": part,
                            "sector_type": "PBR",
                        }
                        scanned_info.append(key_pbr)
            except PermissionError:
                print(f"[!] Нет доступа к разделу {part} для чтения PBR (требуется root)")
            except Exception as exc:
                print(f"[!] Ошибка чтения PBR ({part}): {exc}")

    return scanned_info, sector_records


def generate_file_list(list_file: str = LIST_FILE) -> tuple[list[str], dict[str, dict[str, Any]]]:
    """
    Формирует перечень критически важных файлов ОС (конфиги, ядро, PARSEC, EFI),
    сохраняет его в critical_files_list.txt и возвращает (список_файлов, записи_секторов).
    """
    candidates = list(DIRECTORY_GLOBAL)

    for pattern in WILDCARD_PATHS:
        for path in glob.glob(pattern):
            if path not in candidates:
                candidates.append(path)

    for esp in glob.glob("/boot/efi/**/*", recursive=True):
        if os.path.isfile(esp) and esp not in candidates:
            candidates.append(esp)

    # Сохраняем уже добавленные вручную пользовательские пути, если список существовал
    existing_paths = read_list(list_file)
    for custom_path in existing_paths:
        if custom_path not in candidates and os.path.isfile(custom_path):
            candidates.append(custom_path)

    valid_files: list[str] = []
    for path in candidates:
        if os.path.isfile(path):
            if os.access(path, os.R_OK):
                abs_path = os.path.abspath(path)
                if abs_path not in valid_files:
                    valid_files.append(abs_path)
            else:
                print(f"[!] Нет прав на чтение (пропущен): {path}")

    write_list(list_file, valid_files)
    _, sector_records = scan_boot_sectors()
    return valid_files, sector_records


def read_list(list_file: str = LIST_FILE) -> list[str]:
    if not os.path.exists(list_file):
        return []
    with open(list_file, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def write_list(list_file: str, paths: list[str]) -> None:
    with open(list_file, "w", encoding="utf-8") as f:
        for p in paths:
            f.write(p + "\n")


def add_file(
    path: str,
    list_file: str = LIST_FILE,
    baseline_file: str = BASELINE_FILE,
    cache_dir: str = task2_hasher.DEFAULT_CACHE_DIR,
) -> int:
    """Добавляет новый файл в список контроля, эталонную базу (с метаданными) и кэш."""
    abs_path = os.path.abspath(path)

    if not os.path.exists(abs_path):
        print(f"[!] Файл не существует: {abs_path}")
        return 1
    if not os.path.isfile(abs_path):
        print(f"[!] Объект не является обычным файлом: {abs_path}")
        return 1
    if not os.access(abs_path, os.R_OK):
        print(f"[!] Нет прав на чтение файла: {abs_path}")
        return 1

    record = task2_hasher.build_baseline_record(abs_path, cache_dir=cache_dir, use_cache=True)
    if record is None:
        print(f"[!] Не удалось вычислить хеш и создать запись эталона для: {abs_path}")
        return 1

    paths = read_list(list_file)
    if abs_path not in paths:
        paths.append(abs_path)
        write_list(list_file, paths)

    baseline: dict[str, Any] = {}
    if os.path.exists(baseline_file):
        try:
            baseline = task2_hasher.load_baseline_file(baseline_file)
        except Exception as exc:
            print(f"[!] Ошибка чтения базы '{baseline_file}': {exc}")
            return 2

    baseline[abs_path] = record
    task2_hasher.save_baseline_file(baseline_file, baseline)

    print(f"[OK] Файл добавлен под контроль: {abs_path}")
    print(f"     SHA-256: {record['sha256']}")
    if record.get("cache_file"):
        print(f"     Резервная копия: {record['cache_file']}")
    return 0


def remove_file(
    path: str,
    list_file: str = LIST_FILE,
    baseline_file: str = BASELINE_FILE,
    cache_dir: str = task2_hasher.DEFAULT_CACHE_DIR,
) -> int:
    """Удаляет файл из списка контроля, эталонной базы и кэша."""
    abs_path = os.path.abspath(path)
    found = False
    explicit_cache: str | None = None

    paths = read_list(list_file)
    if abs_path in paths:
        paths.remove(abs_path)
        write_list(list_file, paths)
        found = True

    if os.path.exists(baseline_file):
        try:
            baseline = task2_hasher.load_baseline_file(baseline_file)
            if abs_path in baseline:
                entry = baseline[abs_path]
                if isinstance(entry, dict):
                    explicit_cache = entry.get("cache_file")
                del baseline[abs_path]
                task2_hasher.save_baseline_file(baseline_file, baseline)
                found = True
        except Exception as exc:
            print(f"[!] Ошибка обновления базы '{baseline_file}': {exc}")
            return 2

    if task2_hasher.remove_backup(abs_path, cache_dir=cache_dir, explicit_cache_path=explicit_cache):
        found = True

    if not found:
        print(f"[!] Объект {abs_path} не найден ни в списке контроля, ни в эталонной базе.")
        return 1

    print(f"[OK] Объект удалён из контроля и базы: {abs_path}")
    return 0


if __name__ == "__main__":
    files, sectors = generate_file_list(LIST_FILE)
    print(f"[OK] Найдено файлов: {len(files)}, загрузочных секторов: {len(sectors)}")