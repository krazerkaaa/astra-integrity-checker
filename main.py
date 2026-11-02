#!/usr/bin/env python3
"""
Главный управляющий скрипт (Main Pipeline) для проекта контроля целостности ОС Astra Linux.
"""

import argparse
import os
import sys

import task1_scanner
import task2_hasher
import task3_auditor


def run_pipeline() -> int:
    parser = argparse.ArgumentParser(
        description="Комплексный инструмент автоматизации контроля целостности файлов Astra Linux."
    )
    subparsers = parser.add_subparsers(dest="command", help="Доступные команды пайплайна")

    subparsers.add_parser("full-check", help="Запустить полный цикл обновления и проверки.")

    audit_parser = subparsers.add_parser("audit", help="Запустить проверку целостности по существующему эталону.")
    audit_parser.add_argument("--baseline", default="hashes_baseline.json", help="Путь к файлу эталона.")
    audit_parser.add_argument("--report", default="integrity_report.json", help="Путь для сохранения JSON-отчёта.")

    baseline_parser = subparsers.add_parser("build-baseline",
                                            help="Сформировать список файлов и создать эталонную базу.")
    baseline_parser.add_argument("--output", default="hashes_baseline.json", help="Путь к файлу создаваемого эталона.")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    list_file = "critical_files_list.txt"
    baseline_file = "hashes_baseline.json"

    if args.command == "build-baseline" or args.command == "full-check":
        print("=== [ЭТАП 1/3] Запуск сканирования критически важных файлов и секторов ===")

        # РЕАЛЬНЫЙ ВЫЗОВ СКАНИРОВАНИЯ ИЗ task1_scanner
        # Убедитесь, что в task1_scanner.py есть этот блок или функция генерации списка
        try:
            # Если в task1_scanner вся логика выполняется при импорте или оформлена в функцию:
            # Например, если у вас там список файлов собирается в переменную valid_files:
            if hasattr(task1_scanner, 'generate_file_list'):
                task1_scanner.generate_file_list(list_file)
            else:
                # Альтернативный вариант: запускаем логику сканирования и принудительно сохраняем список
                # (код ниже повторяет логику вашего сканера для надежности)
                import glob
                wildcard_paths = (
                    "/boot/vmlinuz-*", "/boot/initrd.img-*", "/boot/grub/*",
                    "/lib/modules/*/misc/digsig_verif.ko", "/lib/modules/*/misc/parsec.ko",
                    "/lib/modules/*/misc/parsec-cifs.ko"
                )
                directory_global = [
                    "/boot/grub/grub.cfg", "/boot/grub/grub.conf", "/etc/astra_license",
                    "/etc/nsswitch.conf", "/etc/pam.d/fly-dm", "/etc/pam.d/fly-dm-np",
                    "/etc/pam.d/login", "/etc/pam.d/passwd", "/etc/pam.d/su",
                    "/etc/pam.d/sumac.xauth", "/etc/pam.d/xrdp-sesman", "/etc/resolv.conf",
                    "/etc/hosts.allow", "/etc/hosts.deny", "/etc/network/interfaces",
                    "/etc/ssh/sshd_config", "/etc/hosts", "/etc/samba/smb.conf", "/etc/apache2/apache2.conf"
                ]
                for pattern in wildcard_paths:
                    for path in glob.glob(pattern):
                        if os.path.isfile(path) and path not in directory_global:
                            directory_global.append(path)

                valid_files = [p for p in directory_global if os.path.isfile(p)]
                with open(list_file, "w", encoding="utf-8") as out_f:
                    for vf in valid_files:
                        out_f.write(f"{vf}\n")

            print(f"[OK] Перечень путей успешно записан в {list_file}")
        except Exception as e:
            print(f"[!] Ошибка на этапе сканирования: {e}", file=sys.stderr)
            return 2

        print("\n=== [ЭТАП 2/3] Расчёт контрольных сумм и формирование эталона ===")
        output_db = args.output if hasattr(args, "output") else baseline_file
        task2_hasher.build_baseline_db(list_file, output_db)

    if args.command == "audit" or args.command == "full-check":
        print("\n=== [ЭТАП 3/3] Аудит безопасности и сверка с эталонной базой ===")
        b_path = args.baseline if hasattr(args, "baseline") else baseline_file
        r_path = args.report if hasattr(args, "report") else "integrity_report.json"

        if not os.path.exists(b_path):
            print(
                f"[!] Ошибка: Эталонный файл '{b_path}' не найден. Сначала создайте его через команду build-baseline.",
                file=sys.stderr)
            return 2

        try:
            baseline_data = task3_auditor.load_baseline(b_path)
            results, issues = task3_auditor.check_integrity(baseline_data)

            summary = {
                "total": len(results),
                "ok": sum(1 for item in results if item["status"] == "OK"),
                "issues": len(issues),
                "results": results,
            }
            task3_auditor.save_json(r_path, summary)
            print(f"\n[OK] Отчёт сохранён в: {r_path}")
            print(f"Итог: проверено {summary['total']}, без отклонений {summary['ok']}, проблем {summary['issues']}.")

            return 1 if issues else 0
        except Exception as exc:
            print(f"[!] Ошибка при выполнении аудита: {exc}", file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(run_pipeline())