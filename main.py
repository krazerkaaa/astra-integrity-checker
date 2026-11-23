#!/usr/bin/env python3
"""
Главный управляющий скрипт (Main Pipeline) для автоматизации контроля целостности
критически важных файлов ОС Astra Linux Special Edition.

Примеры использования:
  sudo python3 main.py build-baseline
  sudo python3 main.py audit
  sudo python3 main.py add /etc/ssh/sshd_config
  sudo python3 main.py remove /etc/ssh/sshd_config
  sudo python3 main.py update /etc/ssh/sshd_config
  sudo python3 main.py full-check
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import task1_scanner
import task2_hasher
import task3_auditor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Утилита автоматизации контроля целостности критически важных файлов ОС Astra Linux.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Примеры запуска:\n"
            "  sudo python3 main.py build-baseline          # Первичное сканирование и создание эталона\n"
            "  sudo python3 main.py audit                   # Проверка целостности с выводом diff\n"
            "  sudo python3 main.py add /etc/hosts.allow    # Добавить файл под контроль\n"
            "  sudo python3 main.py remove /etc/hosts.allow # Удалить файл из списка контроля\n"
            "  sudo python3 main.py update /etc/passwd      # Обновить эталон после легитимных правок\n"
            "  sudo python3 main.py full-check              # Полный цикл: сканирование + эталон + аудит"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", title="Доступные команды управления")

    # 1. build-baseline
    p_build = subparsers.add_parser(
        "build-baseline",
        help="Сформировать список критических файлов ОС и создать эталонную базу SHA-256.",
    )
    p_build.add_argument("--list", default=task1_scanner.LIST_FILE, help="Файл перечня контролируемых путей.")
    p_build.add_argument("--output", default=task1_scanner.BASELINE_FILE, help="Путь к файлу эталонной базы JSON.")
    p_build.add_argument("--cache-dir", default=task2_hasher.DEFAULT_CACHE_DIR, help="Папка резервного кэша.")

    # 2. audit
    p_audit = subparsers.add_parser(
        "audit",
        help="Выполнить аудит целостности: сравнить хеши, метаданные и показать изменённые строки.",
    )
    p_audit.add_argument("--baseline", default=task1_scanner.BASELINE_FILE, help="Путь к файлу эталона JSON.")
    p_audit.add_argument("--report", default=task3_auditor.DEFAULT_REPORT_PATH, help="Путь для JSON-отчёта.")
    p_audit.add_argument("--cache-dir", default=task2_hasher.DEFAULT_CACHE_DIR, help="Папка резервного кэша.")

    # 3. add
    p_add = subparsers.add_parser(
        "add",
        help="Добавить новый файл в список контроля, эталонную базу и кэш.",
    )
    p_add.add_argument("path", help="Путь к добавляемому файлу (например, /etc/ssh/sshd_config).")
    p_add.add_argument("--list", default=task1_scanner.LIST_FILE, help="Файл перечня контролируемых путей.")
    p_add.add_argument("--baseline", default=task1_scanner.BASELINE_FILE, help="Путь к файлу эталона JSON.")
    p_add.add_argument("--cache-dir", default=task2_hasher.DEFAULT_CACHE_DIR, help="Папка резервного кэша.")

    # 4. remove
    p_remove = subparsers.add_parser(
        "remove",
        help="Удалить файл из списка контроля, эталонной базы и кэша.",
    )
    p_remove.add_argument("path", help="Путь к удаляемому из контроля файлу.")
    p_remove.add_argument("--list", default=task1_scanner.LIST_FILE, help="Файл перечня контролируемых путей.")
    p_remove.add_argument("--baseline", default=task1_scanner.BASELINE_FILE, help="Путь к файлу эталона JSON.")
    p_remove.add_argument("--cache-dir", default=task2_hasher.DEFAULT_CACHE_DIR, help="Папка резервного кэша.")

    # 5. update
    p_update = subparsers.add_parser(
        "update",
        help="Обновить эталонный хеш и кэш для одного файла или всей базы.",
    )
    p_update.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Путь к файлу для точечного обновления (если не указан — пересчёт всей базы).",
    )
    p_update.add_argument("--baseline", default=task1_scanner.BASELINE_FILE, help="Путь к файлу эталона JSON.")
    p_update.add_argument("--list", default=task1_scanner.LIST_FILE, help="Список файлов для полного пересчёта.")
    p_update.add_argument("--cache-dir", default=task2_hasher.DEFAULT_CACHE_DIR, help="Папка резервного кэша.")

    # 6. full-check
    p_full = subparsers.add_parser(
        "full-check",
        help="Запустить полный цикл: сканирование, построение эталона и проверку целостности.",
    )
    p_full.add_argument("--list", default=task1_scanner.LIST_FILE, help="Файл перечня контролируемых путей.")
    p_full.add_argument("--baseline", default=task1_scanner.BASELINE_FILE, help="Путь к файлу эталона JSON.")
    p_full.add_argument("--report", default=task3_auditor.DEFAULT_REPORT_PATH, help="Путь для JSON-отчёта.")
    p_full.add_argument("--cache-dir", default=task2_hasher.DEFAULT_CACHE_DIR, help="Папка резервного кэша.")

    return parser


def run_pipeline() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "add":
        return task1_scanner.add_file(
            path=args.path,
            list_file=args.list,
            baseline_file=args.baseline,
            cache_dir=args.cache_dir,
        )

    if args.command == "remove":
        return task1_scanner.remove_file(
            path=args.path,
            list_file=args.list,
            baseline_file=args.baseline,
            cache_dir=args.cache_dir,
        )

    if args.command == "update":
        print("=== Обновление эталона контрольных сумм ===")
        try:
            ok = task2_hasher.update_baseline(
                baseline_path=args.baseline,
                target=args.path,
                list_path=args.list,
                cache_dir=args.cache_dir,
            )
        except Exception as exc:
            print(f"[!] Ошибка при обновлении эталона: {exc}", file=sys.stderr)
            return 2
        return 0 if ok else 2

    if args.command in ("build-baseline", "full-check"):
        print("=== [ЭТАП 1/3] Запуск сканирования критически важных файлов и секторов ===")
        try:
            valid_files, sector_records = task1_scanner.generate_file_list(args.list)
            print(f"[OK] Перечень путей записан в {args.list} (файлов: {len(valid_files)}, секторов: {len(sector_records)})")
        except Exception as exc:
            print(f"[!] Ошибка на этапе сканирования: {exc}", file=sys.stderr)
            return 2

        print("\n=== [ЭТАП 2/3] Расчёт контрольных сумм, метаданных и кэширование эталона ===")
        output_db = args.output if args.command == "build-baseline" else args.baseline
        if not task2_hasher.build_baseline_db(
            input_list_path=args.list,
            output_db_path=output_db,
            cache_dir=args.cache_dir,
            extra_records=sector_records,
        ):
            return 2

    if args.command in ("audit", "full-check"):
        print("\n=== [ЭТАП 3/3] Аудит безопасности и сверка с эталонной базой ===")
        b_path = args.baseline
        r_path = args.report

        if not os.path.exists(b_path):
            print(
                f"[!] Ошибка: Эталонный файл '{b_path}' не найден. "
                "Сначала создайте его командой 'build-baseline'.",
                file=sys.stderr,
            )
            return 2

        try:
            started = datetime.now(timezone.utc).isoformat()
            baseline_data = task3_auditor.load_baseline(b_path)
            results, issues = task3_auditor.check_integrity(baseline_data, cache_dir=args.cache_dir)

            summary = {
                "started_at_utc": started,
                "baseline": str(Path(b_path).resolve()),
                "cache_dir": str(Path(args.cache_dir).resolve()),
                "total": len(results),
                "ok": sum(1 for item in results if item["status"] == "OK"),
                "issues": len(issues),
                "results": results,
            }
            task3_auditor.save_json(r_path, summary)
            print(f"\n[OK] Детальный отчёт сохранён в: {r_path}")
            print(f"Итог: проверено {summary['total']}, без отклонений {summary['ok']}, проблем {summary['issues']}.")

            return 1 if issues else 0
        except Exception as exc:
            print(f"[!] Ошибка при выполнении аудита: {exc}", file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(run_pipeline())