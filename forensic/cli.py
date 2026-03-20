#!/usr/bin/env python3
import os
import sys
import argparse
import traceback
import json
from pathlib import Path
import pwd

from forensic.core.logger import get_logger
from forensic.core.settings import get_settings, get_settings_manager
from forensic.system.system_info import SystemInfoCollector
from forensic.scanners import BashScanner
from forensic.report import ReportGenerator
from forensic import __version__


def check_root():
    return os.geteuid() == 0


def print_root_warning():
    print("""
╔════════════════════════════════════════════════════════════╗
║  ОШИБКА: Требуются права root                          ║
╠════════════════════════════════════════════════════════════╣
║  Запустите утилиту заново с sudo:                         ║
║  $ sudo python -m forensic                                ║
╚════════════════════════════════════════════════════════════╝
    """, file=sys.stderr)


def get_current_username():
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except:
        return 'unknown'


def parse_arguments():
    parser = argparse.ArgumentParser(description='Forensic Tool - поиск удаленных пользователей')
    parser.add_argument('--log-level', '-l', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                       help='Уровень логирования')
    parser.add_argument('--session-dir', '-s', type=str, help='Директория для сессий')
    parser.add_argument('--version', action='version', version=f'Forensic Tool v{__version__}')
    return parser.parse_args()


def override_settings_with_args(args):
    try:
        settings = get_settings_manager().get()
        if args.log_level:
            settings.log_level = args.log_level
        if args.session_dir:
            settings.session_dir = args.session_dir
    except Exception as e:
        raise RuntimeError(f"Не удалось применить настройки: {e}")


def validate_session_directory(session_dir: Path):
    try:
        parent = session_dir.parent if str(session_dir) != '/' else session_dir
        if not parent.exists():
            raise RuntimeError(f"Директория не существует: {parent}")
        if not os.access(str(parent), os.W_OK):
            raise RuntimeError(f"Нет прав на запись: {parent}")
        session_dir.mkdir(parents=True, exist_ok=True)
        test_file = session_dir / '.write_test'
        test_file.touch()
        test_file.unlink()
    except PermissionError:
        raise RuntimeError(f"Нет прав на запись: {session_dir}")
    except Exception as e:
        raise RuntimeError(f"Ошибка проверки: {e}")


def print_system_info(system_info: dict, username: str):
    os_info = system_info.get('os', {})
    print("\n" + "═" * 60)
    print(" ИНФОРМАЦИЯ О СИСТЕМЕ")
    print("═" * 60)
    print(f" Хост:       {system_info.get('hostname', 'unknown')}")
    print(f" ОС:         {os_info.get('name', 'unknown')}")
    print(f" Ядро:       {system_info.get('kernel', 'unknown')}")
    print(f" Архитектура: {system_info.get('architecture', 'unknown')}")
    print(f" Пользователь: {username}")
    print("═" * 60)


def show_main_menu():
    print("\n" + "═" * 60)
    print(" Forensic Tool - Главное меню")
    print("═" * 60)
    print(" 1. Сканировать систему")
    print(" 2. Конвертировать отчет")
    print(" 3. Распарсить отчет")
    print(" 4. Выход")
    print("═" * 60)
    
    while True:
        try:
            choice = input("\n Выберите действие [1-4]: ").strip()
            if choice in ['1', '2', '3', '4']:
                return choice
        except KeyboardInterrupt:
            return '4'


def run_scan(logger, username):
    print("\n" + "═" * 60)
    print(" ЗАПУСК СКАНИРОВАНИЯ")
    print("═" * 60)
    
    scanner = BashScanner(logger)
    report_data = scanner.scan()
    
    system_collector = SystemInfoCollector(logger)
    system_info = system_collector.collect_all_info()
    report_data.system_info.hostname = system_info.get('hostname', 'unknown')
    report_data.system_info.os_name = system_info.get('os', {}).get('name', 'unknown')
    report_data.system_info.os_version = system_info.get('os', {}).get('version', 'unknown')
    report_data.system_info.kernel = system_info.get('kernel', 'unknown')
    report_data.system_info.architecture = system_info.get('architecture', 'unknown')
    
    print("\n" + "═" * 60)
    print(" СОХРАНЕНИЕ ОТЧЕТА")
    print("═" * 60)
    
    json_path = logger.get_session_path() / "report.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report_data.to_dict(), f, indent=2, ensure_ascii=False, default=str)
    print(f"  ✓ JSON: {json_path}")
    
    print("\n" + "═" * 60)
    print(" СКАНИРОВАНИЕ ЗАВЕРШЕНО")
    print("═" * 60)
    print(f" Удаленных пользователей: {report_data.deleted_users_count}")
    print(f" Время: {report_data.scan_duration:.2f} сек")
    print("═" * 60)
    
    if report_data.deleted_users:
        print("\n Найденные пользователи:")
        for user in report_data.deleted_users:
            print(f"  • UID {user.uid}")
        print("═" * 60)


def show_convert_menu(logger):
    print("\n" + "═" * 60)
    print(" Конвертация отчетов")
    print("═" * 60)
    print(" json → html, pdf")
    print(" html → pdf")
    print("═" * 60)
    
    while True:
        try:
            path = input("\n Путь до файла (Enter для возврата): ").strip()
            if not path:
                return
            
            src = Path(path)
            if not src.exists():
                print(f" Файл не найден: {path}")
                continue
            
            fmt = src.suffix.lower().replace('.', '')
            if fmt not in ['json', 'html']:
                print(" Поддерживаются только json, html")
                continue
            
            targets = ['html', 'pdf'] if fmt == 'json' else ['pdf']
            print(f"\n Доступно: {', '.join(targets)}")
            
            target = input(" Целевой формат: ").strip().lower()
            if target not in targets:
                continue
            
            print(f"\n Конвертация...")
            gen = ReportGenerator(src.parent)
            
            if fmt == 'json':
                if not gen.load_data(src):
                    print(" Ошибка загрузки JSON")
                    continue
                out = gen.generate_html() if target == 'html' else gen.generate_pdf()
            else:
                print(" Конвертация HTML→PDF в разработке")
                continue
            
            if out:
                print(f" Готово: {out}")
                logger.info(f"Конвертирован: {src} → {out}")
            
            if input("\n Продолжить? (y/n): ").lower() != 'y':
                return
        except Exception as e:
            print(f" Ошибка: {e}")


def show_extract_menu(logger):
    print("\n" + "═" * 60)
    print(" Распарсивание отчета")
    print("═" * 60)
    print(" Для каждого UID создается папка с:")
    print("   personal_report.json + artifacts.zip")
    print("═" * 60)
    
    while True:
        try:
            path = input("\n Путь до JSON (Enter для возврата): ").strip()
            if not path:
                return
            
            report = Path(path)
            if not report.exists():
                print(f" Файл не найден: {path}")
                continue
            
            if report.suffix.lower() != '.json':
                print(" Файл должен быть JSON")
                continue
            
            with open(report, 'r') as f:
                data = json.load(f)
            users = data.get('deleted_users', [])
            if not users:
                print(" Нет удаленных пользователей")
                continue
            
            print(f"\n 📊 Найдено пользователей: {len(users)}")
            
            dest = input("\n Целевая директория (Enter - текущая): ").strip()
            dest_dir = (report.parent if not dest else Path(dest)) / f"parsed_{report.stem}"
            print(f" Директория: {dest_dir}")
            
            if input("\n Продолжить? (y/n): ").lower() != 'y':
                continue
            
            from forensic.utils.extractor import ArtifactExtractor
            extractor = ArtifactExtractor(logger)
            if extractor.parse_report(report, dest_dir):
                print("\n" + "═" * 60)
                print(" ГОТОВО")
                print("═" * 60)
                for d in sorted(dest_dir.glob("uid_*")):
                    if d.is_dir():
                        arch = d / "artifacts.zip"
                        size = arch.stat().st_size / 1024 if arch.exists() else 0
                        if size == 0:
                            print(f"   • {d.name}/ (нет файлов)")
                        else:
                            print(f"   • {d.name}/ ({size:.1f} KB)")
                print("═" * 60)
            
            if input("\n Продолжить? (y/n): ").lower() != 'y':
                return
        except Exception as e:
            print(f" Ошибка: {e}")


def main():
    try:
        if not check_root():
            print_root_warning()
            sys.exit(1)
        
        args = parse_arguments()
        username = get_current_username()
        
        settings = get_settings()
        settings_manager = get_settings_manager()
        override_settings_with_args(args)
        
        session_dir = Path(settings.session_dir)
        validate_session_directory(session_dir)
        
        logger = get_logger("ForensicTool")
        
        print("\n" + "═" * 60)
        print(f" Forensic Tool v{__version__}")
        print("═" * 60)
        print(f" Сессия: {logger.get_session_path()}")
        print(f" Лог: {logger.get_log_file_path()}")
        if settings_manager.get_config_path():
            print(f" ⚙️ Конфиг: {settings_manager.get_config_path()}")
        print(f" Уровень: {settings.log_level}")
        print(f" Хранение: {settings.session_retention_days} дней")
        print("═" * 60)
        
        system_collector = SystemInfoCollector(logger)
        system_info = system_collector.collect_all_info()
        print_system_info(system_info, username)
        
        while True:
            choice = show_main_menu()
            if choice == '1':
                run_scan(logger, username)
            elif choice == '2':
                show_convert_menu(logger)
            elif choice == '3':
                show_extract_menu(logger)
            else:
                print("\n 👋 Выход...")
                sys.exit(0)
                
    except RuntimeError as e:
        print(f"\nОШИБКА: {e}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        print("\n\nПрерывание", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"\nОШИБКА: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(3)


if __name__ == '__main__':
    main()