#!/usr/bin/env python3
"""
Модуль проверки целостности файлов и загрузочных секторов по эталонным SHA-256 хешам,
метаданным и резервному кэшу с построчной детализацией изменений (difflib).
"""
from __future__ import annotations

import argparse
import difflib
import gzip
import hashlib
import json
import os
import shutil
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CHUNK_SIZE = 1024 * 1024
DEFAULT_CACHE_DIR = ".baseline_cache"
DEFAULT_REPORT_PATH = "integrity_report.json"


def sha256_file(path: str) -> str:
    """Вычисляет SHA-256 файла потоково, не загружая его целиком в память."""
    digest = hashlib.sha256()
    with open(path, "rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_file_metadata(path: str) -> dict[str, Any]:
    """Собирает метаданные файла (размер, права доступа, время модификации)."""
    st = os.stat(path)
    return {
        "st_size": st.st_size,
        "st_mode": st.st_mode,
        "st_mtime": st.st_mtime,
    }


def is_text_file(path: str) -> bool:
    """Проверяет, является ли файл текстовым (UTF-8 без нулевых байтов)."""
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rb") as f:
                sample = f.read(8192)
        else:
            with open(path, "rb") as f:
                sample = f.read(8192)
        if b"\x00" in sample:
            return False
        sample.decode("utf-8")
        return True
    except (OSError, UnicodeDecodeError):
        return False


def get_cache_path(file_path: str, cache_dir: str = DEFAULT_CACHE_DIR) -> str:
    """Формирует путь для сжатой резервной копии файла в директории .baseline_cache/."""
    abs_path = os.path.abspath(file_path)
    path_hash = hashlib.sha256(abs_path.encode("utf-8")).hexdigest()[:16]
    safe_name = Path(abs_path).name[:100]
    return str(Path(cache_dir) / f"{path_hash}_{safe_name}.gz")


def save_to_cache(file_path: str, cache_dir: str = DEFAULT_CACHE_DIR) -> str:
    """Копирует эталонный файл в .baseline_cache/ в сжатом виде (.gz) с правами 0600."""
    cache_path = Path(get_cache_path(file_path, cache_dir))
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(cache_path.parent, 0o700)
    except OSError:
        pass
    with open(file_path, "rb") as src, gzip.open(cache_path, "wb") as dst:
        shutil.copyfileobj(src, dst)
    try:
        os.chmod(cache_path, 0o600)
    except OSError:
        pass
    return str(cache_path)


def _read_lines_any(path: str) -> list[str]:
    """Читает строки из обычного или gzip-сжатого файла."""
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.readlines()


def format_timestamp(ts: float | None) -> str:
    """Переводит UNIX-время в читаемый ISO-формат UTC."""
    if ts is None:
        return "неизвестно"
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def analyze_text_diff(baseline_path: str, current_path: str) -> dict[str, Any]:
    """
    Сравнивает эталонный (из кэша) и текущий текстовые файлы с помощью difflib.
    Возвращает список изменений по строкам (удалено, добавлено, переписано) и unified_diff.
    """
    old_lines = _read_lines_any(baseline_path)
    new_lines = _read_lines_any(current_path)

    matcher = difflib.SequenceMatcher(None, old_lines, new_lines)
    changes: list[dict[str, Any]] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        elif tag == "delete":
            changes.append({
                "action": "удалено",
                "baseline_lines": f"{i1 + 1}-{i2}" if i2 - i1 > 1 else f"{i1 + 1}",
                "removed_content": [line.rstrip("\r\n") for line in old_lines[i1:i2]],
            })
        elif tag == "insert":
            changes.append({
                "action": "добавлено",
                "current_lines": f"{j1 + 1}-{j2}" if j2 - j1 > 1 else f"{j1 + 1}",
                "added_content": [line.rstrip("\r\n") for line in new_lines[j1:j2]],
            })
        elif tag == "replace":
            changes.append({
                "action": "переписано",
                "baseline_lines": f"{i1 + 1}-{i2}" if i2 - i1 > 1 else f"{i1 + 1}",
                "current_lines": f"{j1 + 1}-{j2}" if j2 - j1 > 1 else f"{j1 + 1}",
                "removed_content": [line.rstrip("\r\n") for line in old_lines[i1:i2]],
                "added_content": [line.rstrip("\r\n") for line in new_lines[j1:j2]],
            })

    unified = list(
        difflib.unified_diff(
            [line.rstrip("\r\n") for line in old_lines],
            [line.rstrip("\r\n") for line in new_lines],
            fromfile=f"baseline ({baseline_path})",
            tofile=f"current ({current_path})",
            lineterm="",
        )
    )

    return {
        "file_type": "text",
        "changes": changes,
        "unified_diff": unified,
    }


def load_baseline(path: str) -> dict[str, dict[str, Any]]:
    """Загружает и валидирует структуру эталонного JSON-файла."""
    with open(path, "r", encoding="utf-8") as file_obj:
        data = json.load(file_obj)

    if not isinstance(data, dict):
        raise ValueError("Корневой элемент baseline JSON должен быть объектом.")

    baseline: dict[str, dict[str, Any]] = {}
    for file_path, entry in data.items():
        if not isinstance(file_path, str):
            raise ValueError("Ключ записи должен быть строкой.")

        if isinstance(entry, str):
            expected_hash = entry.strip().lower()
            entry_dict: dict[str, Any] = {"sha256": expected_hash}
        elif isinstance(entry, dict) and isinstance(entry.get("sha256"), str):
            expected_hash = entry["sha256"].strip().lower()
            entry_dict = dict(entry)
            entry_dict["sha256"] = expected_hash
        else:
            raise ValueError(f"Некорректный формат записи для {file_path!r}.")

        if len(expected_hash) != 64 or any(c not in "0123456789abcdef" for c in expected_hash):
            raise ValueError(f"Некорректный SHA-256 для {file_path!r}.")

        baseline[file_path] = entry_dict
    return baseline


def save_json(path: str, data: Any) -> None:
    """Атомарно сохраняет JSON-отчёт или базу."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    with open(temporary, "w", encoding="utf-8") as file_obj:
        json.dump(data, file_obj, ensure_ascii=False, indent=2)
        file_obj.write("\n")
    os.replace(temporary, target)


def build_baseline_record(file_path: str, cache_dir: str = DEFAULT_CACHE_DIR) -> dict[str, Any]:
    """Формирует запись эталона (совместимо с task2_hasher)."""
    meta = get_file_metadata(file_path)
    is_regular = stat.S_ISREG(meta["st_mode"])
    cache_path = save_to_cache(file_path, cache_dir) if (is_regular and is_text_file(file_path)) else None
    return {
        "sha256": sha256_file(file_path),
        "st_size": meta["st_size"],
        "st_mode": meta["st_mode"],
        "st_mtime": meta["st_mtime"],
        "cache_file": cache_path,
    }


def _check_boot_sector(sector_key: str, entry: dict[str, Any]) -> dict[str, Any]:
    """Проверяет целостность загрузочного сектора (MBR / 1-63 / PBR) по блочному устройству."""
    device = entry.get("device")
    sector_type = entry.get("sector_type")
    expected_hash = entry["sha256"]

    if not device or not sector_type:
        if sector_key.endswith("_MBR"):
            device = sector_key[:-4]
            sector_type = "MBR"
        elif sector_key.endswith("_1_to_63_sectors"):
            device = sector_key[:-16]
            sector_type = "1_to_63_sectors"
        elif sector_key.endswith("_PBR"):
            device = sector_key[:-4]
            sector_type = "PBR"

    try:
        with open(device, "rb") as f:
            if sector_type in ("MBR", "PBR"):
                f.seek(0)
                raw = f.read(512)
            else:
                f.seek(512)
                raw = f.read(512 * 63)
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash == expected_hash:
            print(f"[OK] {sector_key}")
            return {
                "path": sector_key,
                "status": "OK",
                "expected_sha256": expected_hash,
                "actual_sha256": actual_hash,
            }
        print(f"[ИЗМЕНЁН] {sector_key} (нарушена целостность загрузочного сектора!)")
        return {
            "path": sector_key,
            "status": "CHANGED",
            "expected_sha256": expected_hash,
            "actual_sha256": actual_hash,
            "content_diff": {"file_type": "boot_sector", "sector_type": sector_type, "device": device},
        }
    except FileNotFoundError:
        print(f"[ОТСУТСТВУЕТ] {sector_key}")
        return {"path": sector_key, "status": "MISSING", "message": "Блочное устройство не найдено"}
    except PermissionError:
        print(f"[НЕТ ДОСТУПА] {sector_key}: требуется запуск от root")
        return {"path": sector_key, "status": "UNREADABLE", "message": "Недостаточно прав (нужен root)"}
    except OSError as exc:
        return {"path": sector_key, "status": "ERROR", "message": str(exc)}


def print_change_details(file_path: str, details: dict[str, Any]) -> None:
    """Выводит в консоль подробную информацию об изменениях файла."""
    meta_diff = details.get("metadata_diff", {})
    if meta_diff:
        print("  Изменения метаданных:")
        if "st_size" in meta_diff:
            sz = meta_diff["st_size"]
            print(f"    - Размер (st_size): {sz['expected']} -> {sz['actual']} байт (разница: {sz['delta']:+d} байт)")
        if "st_mode" in meta_diff:
            md = meta_diff["st_mode"]
            print(f"    - Права доступа (st_mode): {oct(md['expected'])} -> {oct(md['actual'])}")
        if "st_mtime" in meta_diff:
            mt = meta_diff["st_mtime"]
            print(
                f"    - Время модификации (st_mtime): {format_timestamp(mt['expected'])} -> "
                f"{format_timestamp(mt['actual'])} (разница: {mt['delta']:+.2f} сек)"
            )

    content_diff = details.get("content_diff")
    if not content_diff:
        return

    if content_diff.get("file_type") == "text":
        changes = content_diff.get("changes", [])
        if not changes:
            print("  Содержимое текста идентично (изменились только метаданные или символы конца строки).")
            return
        print("  Детализация изменений в тексте:")
        for item in changes:
            action = item["action"]
            if action == "удалено":
                print(f"    * [УДАЛЕНО] Строка(и) в эталоне {item['baseline_lines']}:")
                for line in item["removed_content"]:
                    print(f"        - {line}")
            elif action == "добавлено":
                print(f"    * [ДОБАВЛЕНО] Строка(и) в текущем файле {item['current_lines']}:")
                for line in item["added_content"]:
                    print(f"        + {line}")
            elif action == "переписано":
                print(
                    f"    * [ПЕРЕПИСАНО] Эталон стр. {item['baseline_lines']} -> Текущий стр. {item['current_lines']}:"
                )
                for line in item["removed_content"]:
                    print(f"        - {line}")
                for line in item["added_content"]:
                    print(f"        + {line}")
    elif content_diff.get("file_type") == "binary":
        print("  Бинарный файл изменён:")
        print(f"    * Разница в размере: {content_diff['size_delta_bytes']:+d} байт")
        print(f"    * Разница во времени модификации: {content_diff['mtime_delta_seconds']:+.2f} сек")
    elif content_diff.get("error"):
        print(f"  [!] Не удалось построить diff: {content_diff['error']}")


def check_integrity(
    baseline: dict[str, dict[str, Any]],
    cache_dir: str = DEFAULT_CACHE_DIR,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Проверяет целостность хешей, метаданных и загрузочных секторов."""
    results: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []

    for file_path, entry in baseline.items():
        if entry.get("is_boot_sector") or file_path.endswith(("_MBR", "_PBR", "_1_to_63_sectors")):
            res = _check_boot_sector(file_path, entry)
            results.append(res)
            if res["status"] != "OK":
                issues.append(res)
            continue

        expected_hash = entry["sha256"]
        try:
            actual_hash = sha256_file(file_path)
            actual_meta = get_file_metadata(file_path)

            metadata_diff: dict[str, Any] = {}
            for key in ("st_size", "st_mode", "st_mtime"):
                if key in entry and entry[key] != actual_meta[key]:
                    diff_item: dict[str, Any] = {
                        "expected": entry[key],
                        "actual": actual_meta[key],
                    }
                    if key in ("st_size", "st_mtime"):
                        diff_item["delta"] = actual_meta[key] - entry[key]
                    metadata_diff[key] = diff_item

            hash_changed = actual_hash != expected_hash
            meta_changed = bool(metadata_diff)

            if not hash_changed and not meta_changed:
                print(f"[OK] {file_path}")
                results.append({
                    "path": file_path,
                    "status": "OK",
                    "expected_sha256": expected_hash,
                    "actual_sha256": actual_hash,
                    "metadata": actual_meta,
                })
            else:
                print(f"[ИЗМЕНЁН] {file_path}")
                result_entry: dict[str, Any] = {
                    "path": file_path,
                    "status": "CHANGED",
                    "expected_sha256": expected_hash,
                    "actual_sha256": actual_hash,
                    "expected_metadata": {
                        k: entry.get(k) for k in ("st_size", "st_mode", "st_mtime") if k in entry
                    },
                    "actual_metadata": actual_meta,
                    "metadata_diff": metadata_diff,
                }

                cached_file = entry.get("cache_file") or get_cache_path(file_path, cache_dir)
                if is_text_file(file_path) and Path(cached_file).is_file() and is_text_file(cached_file):
                    result_entry["content_diff"] = analyze_text_diff(cached_file, file_path)
                elif not is_text_file(file_path):
                    size_delta = actual_meta["st_size"] - entry["st_size"] if "st_size" in entry else 0
                    mtime_delta = actual_meta["st_mtime"] - entry["st_mtime"] if "st_mtime" in entry else 0.0
                    result_entry["content_diff"] = {
                        "file_type": "binary",
                        "size_delta_bytes": size_delta,
                        "mtime_delta_seconds": mtime_delta,
                    }
                else:
                    result_entry["content_diff"] = {
                        "error": f"Эталонная копия в кэше не найдена ({cached_file})."
                    }

                print_change_details(file_path, result_entry)
                results.append(result_entry)
                issues.append(result_entry)

        except FileNotFoundError:
            print(f"[ОТСУТСТВУЕТ] {file_path}")
            result = {"path": file_path, "status": "MISSING", "message": "Файл отсутствует"}
            results.append(result)
            issues.append(result)
        except PermissionError:
            print(f"[НЕТ ДОСТУПА] {file_path}: Недостаточно прав для чтения")
            result = {"path": file_path, "status": "UNREADABLE", "message": "Недостаточно прав для чтения"}
            results.append(result)
            issues.append(result)
        except OSError as exc:
            print(f"[ОШИБКА] {file_path}: {exc}", file=sys.stderr)
            result = {"path": file_path, "status": "ERROR", "message": str(exc)}
            results.append(result)
            issues.append(result)

    return results, issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Сравнение SHA-256 хешей и содержимого файлов с эталоном.")
    parser.add_argument("--baseline", default="hashes_baseline.json", help="Путь к эталонному JSON-файлу.")
    parser.add_argument("--json-report", default=DEFAULT_REPORT_PATH, help="Путь для JSON-отчёта.")
    parser.add_argument("--cache-dir", default=DEFAULT_CACHE_DIR, help="Директория кэша эталонных копий.")
    args = parser.parse_args()

    try:
        baseline = load_baseline(args.baseline)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Не удалось загрузить эталон: {exc}", file=sys.stderr)
        return 2

    started = datetime.now(timezone.utc).isoformat()
    results, issues = check_integrity(baseline, args.cache_dir)
    summary = {
        "started_at_utc": started,
        "baseline": str(Path(args.baseline).resolve()),
        "cache_dir": str(Path(args.cache_dir).resolve()),
        "total": len(results),
        "ok": sum(1 for item in results if item["status"] == "OK"),
        "issues": len(issues),
        "results": results,
    }
    if args.json_report:
        save_json(args.json_report, summary)
        print(f"Отчёт сохранён: {args.json_report}")
    print(f"\nИтог: проверено {summary['total']}, без отклонений {summary['ok']}, проблем {summary['issues']}.")
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())