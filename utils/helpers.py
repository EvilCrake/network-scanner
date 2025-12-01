"""
Вспомогательные функции
"""

import ipaddress
import socket
import subprocess
import platform
import os
from typing import Optional, Tuple, List
import re

from utils.oui_lookup import oui_lookup


def get_local_network() -> Optional[Tuple[str, str]]:
    """
    Определяет локальную сеть и маску подсети
    
    Returns:
        Tuple (network, netmask) или None
    """
    try:
        import netifaces
        
        # Получаем шлюз по умолчанию
        gateways = netifaces.gateways()
        default_gateway = gateways['default'].get(netifaces.AF_INET)
        
        if not default_gateway:
            return None
            
        interface = default_gateway[1]
        
        # Получаем адреса интерфейса
        addrs = netifaces.ifaddresses(interface)
        ip_info = addrs.get(netifaces.AF_INET)
        
        if not ip_info:
            return None
            
        ip = ip_info[0]['addr']
        netmask = ip_info[0].get('netmask', '255.255.255.0')
        
        # Вычисляем сеть
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        
        return str(network.network_address), str(network.netmask)
    except Exception:
        # Fallback метод для Windows
        try:
            result = subprocess.run(
                ['ipconfig'],
                capture_output=True,
                text=True,
                timeout=5,
                encoding='utf-8',
                errors='ignore'
            )
            
            # Парсим вывод ipconfig
            lines = result.stdout.split('\n')
            ip = None
            mask = None
            
            # Ищем IP и маску в строках, содержащих IPv4 или IP Address
            for i, line in enumerate(lines):
                # Ищем строку с IPv4 адресом
                if 'IPv4' in line or 'IP Address' in line or 'IP-адрес' in line:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        # Проверяем следующую строку на наличие маски
                        if i + 1 < len(lines):
                            next_line = lines[i + 1]
                            if 'Mask' in next_line or 'Маска' in next_line or 'маска' in next_line:
                                mask_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', next_line)
                                if mask_match:
                                    mask = mask_match.group(1)
                        # Также проверяем текущую строку на наличие маски
                        if not mask:
                            mask_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if mask_match and mask_match.group(1) != ip:
                                # Если найдено два IP в одной строке, второе - маска
                                all_ips = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
                                if len(all_ips) > 1:
                                    mask = all_ips[1]
                
                # Также ищем маску отдельно
                if not mask and ('Subnet Mask' in line or 'Маска подсети' in line or 'Маска' in line):
                    mask_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if mask_match:
                        mask = mask_match.group(1)
            
            if ip and mask:
                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                return str(network.network_address), str(network.netmask)
            elif ip:
                # Если маска не найдена, используем стандартную /24
                network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                return str(network.network_address), str(network.netmask)
        except Exception as e:
            # Для отладки можно раскомментировать:
            # print(f"Fallback error: {e}")
            pass
    
    return None


def get_hostname(ip: str, timeout: float = 2.0) -> Optional[str]:
    """
    Получает hostname по IP адресу
    
    Args:
        ip: IP адрес
        timeout: Таймаут в секундах
        
    Returns:
        Hostname или None
    """
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None


def get_mac_vendor(mac: str) -> Optional[str]:
    """
    Определяет производителя по MAC адресу, используя кэшируемую базу IEEE OUI.
    """
    vendor = oui_lookup.lookup(mac)
    return vendor or None


def is_admin() -> bool:
    """
    Проверяет, запущено ли приложение с правами администратора
    
    Returns:
        True если есть права администратора
    """
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def format_mac(mac: str) -> str:
    """
    Форматирует MAC адрес в стандартный вид
    
    Args:
        mac: MAC адрес в любом формате
        
    Returns:
        MAC адрес в формате XX:XX:XX:XX:XX:XX
    """
    if not mac:
        return ""
    
    # Убираем разделители и приводим к верхнему регистру
    mac_clean = re.sub(r'[:-]', '', mac.upper())
    
    # Форматируем с двоеточиями
    if len(mac_clean) == 12:
        return ":".join([mac_clean[i:i+2] for i in range(0, 12, 2)])
    
    return mac

