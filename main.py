"""
Главный файл сетевого сканера
Точка входа приложения
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from scanner.network_scanner import NetworkScanner
from scanner.exporters import Exporter
from utils.helpers import get_local_network, is_admin
from config.settings import EXPORT_FORMATS

FORMAT_CHOICES = {
    "1": "json",
    "2": "csv",
    "3": "txt"
}


def configure_output_encoding():
    """Включает вывод UTF-8 в консоли Windows"""
    for stream_name in ("stdout", "stderr"):
        handle = getattr(sys, stream_name, None)
        if handle and hasattr(handle, "reconfigure"):
            try:
                handle.reconfigure(encoding="utf-8")
            except Exception:
                pass


def resolve_export_format(user_value: str | None) -> str:
    """Определяет формат экспорта через аргумент или интерактивный выбор"""
    if user_value:
        candidate = FORMAT_CHOICES.get(user_value.lower(), user_value.lower())
        if candidate in EXPORT_FORMATS:
            return candidate
        raise ValueError(f"Unsupported format: {user_value}. Supported: {', '.join(EXPORT_FORMATS)}")
    
    print("\nSelect export format:")
    print("  1) JSON (default)")
    print("  2) CSV")
    print("  3) TXT")
    
    while True:
        choice = input("Enter choice [1-3] (default 1): ").strip() or "1"
        candidate = FORMAT_CHOICES.get(choice.lower(), choice.lower())
        if candidate in EXPORT_FORMATS:
            return candidate
        print("Invalid choice, please enter 1, 2 or 3.")


def print_banner():
    """Выводит баннер приложения"""
    banner = """
    +--------------------------------------------------------------+
    |           Network Scanner v1.0.0                             |
    |           Автоматический сканер сети                         |
    +--------------------------------------------------------------+
    """
    print(banner)


def main():
    """Главная функция"""
    configure_output_encoding()
    
    parser = argparse.ArgumentParser(
        description="Автоматический сканер сети для обнаружения устройств и определения ОС",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python main.py --range 192.168.1.0/24 --format json
  python main.py --range 192.168.1.0/24 --format csv --output scan_results
  python main.py --auto --format txt
        """
    )
    
    parser.add_argument(
        '--range', '-r',
        type=str,
        help='Диапазон сети для сканирования (например, 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '--auto', '-a',
        action='store_true',
        help='Автоматическое определение локальной сети'
    )
    
    parser.add_argument(
        '--format', '-f',
        type=str,
        help='Формат экспорта результатов (json, csv, txt) или цифра 1-3'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='network_scan',
        help='Имя файла для сохранения результатов (без расширения)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Подробный вывод прогресса сканирования'
    )
    
    parser.add_argument(
        '--timeout', '-t',
        type=float,
        default=2.0,
        help='Таймаут для сетевых операций в секундах (по умолчанию: 2.0)'
    )
    
    args = parser.parse_args()
    
    try:
        export_format = resolve_export_format(args.format)
    except ValueError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)
    
    print_banner()
    
    # Проверка прав администратора
    if not is_admin():
        print("WARNING: Running without administrator privileges.")
        print("   Some features may be limited (ARP scanning, etc.)")
        print("   For full functionality, run as administrator.\n")
    else:
        print("OK: Running with administrator privileges\n")
    
    # Определение диапазона сети
    network_range = args.range
    
    if args.auto or not network_range:
        print("Detecting local network...")
        network_info = get_local_network()
        
        if not network_info:
            print("ERROR: Could not detect local network.")
            print("   Please specify network range manually with --range option")
            sys.exit(1)
        
        network_addr, netmask = network_info
        # Преобразуем в CIDR
        import ipaddress
        network = ipaddress.IPv4Network(f"{network_addr}/{netmask}", strict=False)
        network_range = str(network)
        print(f"Detected network: {network_range}\n")
    
    if not network_range:
        print("ERROR: Network range not specified")
        parser.print_help()
        sys.exit(1)
    
    # Создание сканера
    try:
        scanner = NetworkScanner(network_range, timeout=args.timeout, verbose=args.verbose)
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    
    # Запуск сканирования
    print(f"Starting scan of {network_range}...")
    print("This may take a few minutes...\n")
    
    try:
        devices = scanner.scan_network()
    except KeyboardInterrupt:
        print("\n\nWARNING: Scan interrupted by user")
        devices = list(scanner.devices.values())
    except Exception as e:
        print(f"\nERROR during scanning: {e}")
        sys.exit(1)
    
    # Вывод результатов
    print(f"\n{'=' * 80}")
    print(f"Scan completed! Found {len(devices)} device(s)")
    print(f"{'=' * 80}\n")
    
    if devices:
        print("Discovered devices:")
        print("-" * 80)
        for device in devices:
            print(f"  - {device.ip:15} | {device.hostname or 'Unknown':20} | "
                  f"{device.os_type:10} | {device.mac or 'Unknown'}")
        print()
        
        # Экспорт результатов
        exporter = Exporter(devices, network_range)
        
        try:
            output_path = exporter.export(args.output, export_format)
            print(f"Results exported to: {output_path}")
        except Exception as e:
            print(f"ERROR exporting results: {e}")
            sys.exit(1)
    else:
        print("No devices found in the specified network range.")
        print("Possible reasons:")
        print("  - All devices are offline")
        print("  - Firewall blocking ICMP/ARP requests")
        print("  - Network range is incorrect")
        print("  - Insufficient permissions")


if __name__ == "__main__":
    main()

