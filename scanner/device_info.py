"""
Модуль сбора информации об устройстве
"""

from typing import Dict, List, Optional
from datetime import datetime
from utils.helpers import get_hostname, get_mac_vendor, format_mac
from config.settings import PORT_SERVICES


class DeviceInfo:
    """Класс для хранения информации об устройстве"""
    
    def __init__(self, ip: str):
        self.ip = ip
        self.mac = None
        self.hostname = None
        self.os_type = "Unknown"
        self.os_version = "Unknown"
        self.os_confidence = 0.0
        self.vendor = None
        self.open_ports = []
        self.services = []
        self.status = "unknown"
        self.first_seen = datetime.now().isoformat()
        self.last_seen = datetime.now().isoformat()
        self.ttl = None
        self.window_size = None
    
    def add_port(self, port: int):
        """Добавляет открытый порт"""
        if port not in self.open_ports:
            self.open_ports.append(port)
            self.open_ports.sort()
            
            # Добавляем сервис если известен
            service = PORT_SERVICES.get(port)
            if service and service not in self.services:
                self.services.append(service)
    
    def set_mac(self, mac: str):
        """Устанавливает MAC адрес и определяет производителя"""
        self.mac = format_mac(mac)
        if self.mac:
            self.vendor = get_mac_vendor(self.mac)
    
    def set_os_info(self, os_info: Dict):
        """Устанавливает информацию об ОС"""
        self.os_type = os_info.get("type", "Unknown")
        self.os_version = os_info.get("version", "Unknown")
        self.os_confidence = os_info.get("confidence", 0.0)
    
    def update_hostname(self):
        """Обновляет hostname устройства"""
        self.hostname = get_hostname(self.ip)
    
    def to_dict(self) -> Dict:
        """Преобразует информацию об устройстве в словарь"""
        return {
            "ip": self.ip,
            "mac": self.mac or "Unknown",
            "hostname": self.hostname or "Unknown",
            "os": {
                "type": self.os_type,
                "version": self.os_version,
                "confidence": self.os_confidence
            },
            "network": {
                "vendor": self.vendor or "Unknown",
                "ports": self.open_ports,
                "services": self.services
            },
            "timestamps": {
                "first_seen": self.first_seen,
                "last_seen": self.last_seen
            },
            "status": self.status
        }
    
    def __repr__(self):
        return f"Device(ip={self.ip}, mac={self.mac}, hostname={self.hostname}, os={self.os_type})"

