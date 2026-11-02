#!/usr/bin/env python3
"""
Проверка целостности файлов по эталонным SHA-256 хешам из JSON.

Формат baseline JSON:
{
  "/etc/passwd": "<sha256>",
  "/etc/group": "<sha256>"
}

Примеры:
  python3 task3_auditor.py --baseline hashes_baseline.json
  python3 task3_auditor.py --baseline hashes_baseline.json --json-report report.json
  python3 task3_auditor.py --baseline hashes_baseline.json --update-baseline

Для создания эталона используйте --create-baseline и перечислите пути:
  sudo python3 task3_auditor.py --create-baseline hashes_baseline.json /etc/passwd /etc/group
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CHUNK_SIZE = 1024 * 1024


def sha256_file(path: str) -> str:
    """Вычисляет SHA-256 файла потоково, не загружая его целиком в память."""
    digest = hashlib.sha256()
    with open(path, "rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_baseline(path: str) -> dict[str, str]:
    """Загружает и проверяет структуру эталонного JSON-файла."""
    with open(path, "r", encoding="utf-8") as file_obj:
        data = json.load(file_obj)

    if not isinstance(data, dict):
        raise ValueError("Корневой элемент baseline JSON должен быть объектом.")

    baseline: dict[str, str] = {}
    for file_path, expected_hash in data.items():
        if not isinstance(file_path, str) or not isinstance(expected_hash, str):
            raise ValueError("Каждая запись должна иметь вид: путь (строка) -> хеш (строка).")
        expected_hash = expected_hash.strip().lower()
        if len(expected_hash) != 64 or any(c not in "0123456789abcdef" for c in expected_hash):
            raise ValueError(f"Некорректный SHA-256 для файла {file_path!r}.")
        baseline[file_path] = expected_hash
    return baseline


def save_json(path: str, data: Any) -> None:
    """Безопасно сохраняет JSON через временный файл и атомарное переименование."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    with open(temporary, "w", encoding="utf-8") as file_obj:
        json.dump(data, file_obj, ensure_ascii=False, indent=2)
        file_obj.write("\n")
    os.replace(temporary, target)


def create_baseline(paths: list[str], output_path: str) -> int:
    """Создаёт эталон для доступных файлов."""
    baseline: dict[str, str] = {}
    errors: list[dict[str, str]] = []

    for file_path in paths:
        try:
            baseline[file_path] = sha256_file(file_path)
            print(f"[OK] Эталон создан: {file_path}")
        except OSError as exc:
            errors.append({"path": file_path, "error": str(exc)})
            print(f"[ERROR] Не удалось прочитать {file_path}: {exc}", file=sys.stderr)

    if not baseline:
        print("Не удалось вычислить ни одного хеша; baseline не создан.", file=sys.stderr)
        return 2

    save_json(output_path, baseline)
    print(f"Эталон сохранён: {output_path} (файлов: {len(baseline)})")
    return 1 if errors else 0


def check_integrity(baseline: dict[str, str]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Возвращает список результатов проверки и список обнаруженных отклонений."""
    results: list[dict[str, str]] = []
    issues: list[dict[str, str]] = []

    for file_path, expected_hash in baseline.items():
        try:
            actual_hash = sha256_file(file_path)
            if actual_hash == expected_hash:
                status = "OK"
                print(f"[OK] {file_path}")
            else:
                status = "CHANGED"
                print(f"[ИЗМЕНЁН] {file_path}")
                issues.append({
                    "path": file_path,
                    "status": status,
                    "expected_sha256": expected_hash,
                    "actual_sha256": actual_hash,
                })
            results.append({
                "path": file_path,
                "status": status,
                "expected_sha256": expected_hash,
                "actual_sha256": actual_hash,
            })
        except FileNotFoundError:
            status = "MISSING"
            message = "Файл отсутствует"
            print(f"[ОТСУТСТВУЕТ] {file_path}")
            result = {"path": file_path, "status": status, "message": message}
            results.append(result)
            issues.append(result)
        except PermissionError:
            status = "UNREADABLE"
            message = "Недостаточно прав для чтения"
            print(f"[НЕТ ДОСТУПА] {file_path}: {message}")
            result = {"path": file_path, "status": status, "message": message}
            results.append(result)
            issues.append(result)
        except OSError as exc:
            status = "ERROR"
            result = {"path": file_path, "status": status, "message": str(exc)}
            print(f"[ОШИБКА] {file_path}: {exc}", file=sys.stderr)
            results.append(result)
            issues.append(result)

    return results, issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Сравнение SHA-256 хешей файлов с эталоном JSON.")
    parser.add_argument("--baseline", help="Путь к эталонному JSON-файлу.")
    parser.add_argument("--json-report", help="Сохранить подробный отчёт проверки в JSON.")
    parser.add_argument("--create-baseline", metavar="OUTPUT", help="Создать эталонный JSON для перечисленных файлов.")
    parser.add_argument("--update-baseline", action="store_true", help="Перезаписать эталон текущими хешами после подтверждённой проверки.")
    parser.add_argument("--confirm-update", action="store_true", help="Подтвердить обновление эталона при использовании --update-baseline.")
    parser.add_argument("paths", nargs="*", help="Пути файлов для режима --create-baseline.")
    args = parser.parse_args()

    if args.create_baseline:
        if not args.paths:
            parser.error("Для --create-baseline нужно указать хотя бы один путь.")
        return create_baseline(args.paths, args.create_baseline)

    if not args.baseline:
        parser.error("Укажите --baseline или используйте --create-baseline.")

    try:
        baseline = load_baseline(args.baseline)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Не удалось загрузить эталон: {exc}", file=sys.stderr)
        return 2

    if args.update_baseline:
        if not args.confirm_update:
            print("Обновление эталона может закрепить нежелательные изменения. "
                  "Для подтверждения добавьте --confirm-update.", file=sys.stderr)
            return 2
        updated: dict[str, str] = {}
        failures = 0
        for file_path in baseline:
            try:
                updated[file_path] = sha256_file(file_path)
            except OSError as exc:
                failures += 1
                print(f"[ERROR] {file_path}: {exc}", file=sys.stderr)
        if updated:
            save_json(args.baseline, updated)
            print(f"Эталон обновлён: {args.baseline} (файлов: {len(updated)})")
        return 1 if failures else 0

    started = datetime.now(timezone.utc).isoformat()
    results, issues = check_integrity(baseline)
    summary = {
        "started_at_utc": started,
        "baseline": str(Path(args.baseline).resolve()),
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
