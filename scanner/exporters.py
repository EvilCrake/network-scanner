"""
Модуль экспорта результатов сканирования
"""

import json
import csv
from typing import List, Dict
from datetime import datetime
from pathlib import Path
from scanner.device_info import DeviceInfo
from config.settings import SCANNER_VERSION


class Exporter:
    """Класс для экспорта результатов сканирования"""
    
    def __init__(self, devices: List[DeviceInfo], network_range: str):
        """
        Инициализация экспортера
        
        Args:
            devices: Список найденных устройств
            network_range: Диапазон сканируемой сети
        """
        self.devices = devices
        self.network_range = network_range
        self.timestamp = datetime.now().isoformat()
    
    def export_json(self, filename: str) -> str:
        """
        Экспорт в JSON формат
        
        Args:
            filename: Имя файла для сохранения
            
        Returns:
            Путь к сохраненному файлу
        """
        data = {
            "scan_metadata": {
                "timestamp": self.timestamp,
                "scanner_version": SCANNER_VERSION,
                "network_range": self.network_range,
                "devices_count": len(self.devices)
            },
            "devices": [device.to_dict() for device in self.devices]
        }
        
        filepath = Path(filename)
        if not filepath.suffix:
            filepath = filepath.with_suffix('.json')
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return str(filepath.absolute())
    
    def export_csv(self, filename: str) -> str:
        """
        Экспорт в CSV формат
        
        Args:
            filename: Имя файла для сохранения
            
        Returns:
            Путь к сохраненному файлу
        """
        filepath = Path(filename)
        if not filepath.suffix:
            filepath = filepath.with_suffix('.csv')
        
        # Стандартизированные колонки согласно ТЗ
        fieldnames = [
            'ip_address',
            'mac_address',
            'hostname',
            'os_type',
            'os_version',
            'os_confidence',
            'vendor',
            'open_ports',
            'services',
            'first_seen',
            'last_seen',
            'status'
        ]
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for device in self.devices:
                writer.writerow({
                    'ip_address': device.ip,
                    'mac_address': device.mac or 'Unknown',
                    'hostname': device.hostname or 'Unknown',
                    'os_type': device.os_type,
                    'os_version': device.os_version,
                    'os_confidence': device.os_confidence,
                    'vendor': device.vendor or 'Unknown',
                    'open_ports': ','.join(map(str, device.open_ports)) if device.open_ports else 'None',
                    'services': ','.join(device.services) if device.services else 'None',
                    'first_seen': device.first_seen,
                    'last_seen': device.last_seen,
                    'status': device.status
                })
        
        return str(filepath.absolute())
    
    def export_txt(self, filename: str) -> str:
        """
        Экспорт в TXT формат (человекочитаемый)
        
        Args:
            filename: Имя файла для сохранения
            
        Returns:
            Путь к сохраненному файлу
        """
        filepath = Path(filename)
        if not filepath.suffix:
            filepath = filepath.with_suffix('.txt')
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("NETWORK SCAN REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Scan Date: {self.timestamp}\n")
            f.write(f"Network Range: {self.network_range}\n")
            f.write(f"Scanner Version: {SCANNER_VERSION}\n")
            f.write(f"Devices Found: {len(self.devices)}\n")
            f.write("=" * 80 + "\n\n")
            
            for i, device in enumerate(self.devices, 1):
                f.write(f"\n[Device {i}]\n")
                f.write("-" * 80 + "\n")
                f.write(f"IP Address:      {device.ip}\n")
                f.write(f"MAC Address:     {device.mac or 'Unknown'}\n")
                f.write(f"Hostname:        {device.hostname or 'Unknown'}\n")
                f.write(f"Vendor:          {device.vendor or 'Unknown'}\n")
                f.write(f"OS Type:         {device.os_type}\n")
                f.write(f"OS Version:      {device.os_version}\n")
                f.write(f"OS Confidence:   {device.os_confidence:.2%}\n")
                f.write(f"Status:          {device.status}\n")
                
                if device.open_ports:
                    f.write(f"Open Ports:      {', '.join(map(str, device.open_ports))}\n")
                else:
                    f.write(f"Open Ports:      None\n")
                
                if device.services:
                    f.write(f"Services:        {', '.join(device.services)}\n")
                else:
                    f.write(f"Services:        None\n")
                
                f.write(f"First Seen:      {device.first_seen}\n")
                f.write(f"Last Seen:       {device.last_seen}\n")
                f.write("\n")
        
        return str(filepath.absolute())
    
    def export(self, filename: str, format_type: str = "json") -> str:
        """
        Экспорт в указанном формате
        
        Args:
            filename: Имя файла (без расширения или с расширением)
            format_type: Формат экспорта (json, csv, txt)
            
        Returns:
            Путь к сохраненному файлу
        """
        format_type = format_type.lower()
        
        if format_type == "json":
            return self.export_json(filename)
        elif format_type == "csv":
            return self.export_csv(filename)
        elif format_type == "txt":
            return self.export_txt(filename)
        else:
            raise ValueError(f"Unsupported format: {format_type}. Use: json, csv, txt")

