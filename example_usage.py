"""
Пример использования сетевого сканера
"""

from scanner.network_scanner import NetworkScanner
from scanner.exporters import Exporter
from utils.helpers import get_local_network

def example_scan():
    """Пример сканирования сети"""
    
    # Автоматическое определение сети
    network_info = get_local_network()
    if network_info:
        network_addr, netmask = network_info
        import ipaddress
        network = ipaddress.IPv4Network(f"{network_addr}/{netmask}", strict=False)
        network_range = str(network)
        print(f"Detected network: {network_range}")
    else:
        # Или укажите вручную
        network_range = "192.168.1.0/24"
        print(f"Using network: {network_range}")
    
    # Создание сканера
    scanner = NetworkScanner(network_range, timeout=2.0)
    
    # Запуск сканирования
    print("Starting scan...")
    devices = scanner.scan_network()
    
    # Вывод результатов
    print(f"\nFound {len(devices)} device(s):")
    for device in devices:
        print(f"  - {device.ip}: {device.hostname or 'Unknown'} ({device.os_type})")
    
    # Экспорт результатов
    if devices:
        exporter = Exporter(devices, network_range)
        
        # Экспорт в разные форматы
        json_file = exporter.export("example_scan", "json")
        csv_file = exporter.export("example_scan", "csv")
        txt_file = exporter.export("example_scan", "txt")
        
        print(f"\nResults exported:")
        print(f"  - JSON: {json_file}")
        print(f"  - CSV: {csv_file}")
        print(f"  - TXT: {txt_file}")

if __name__ == "__main__":
    example_scan()

