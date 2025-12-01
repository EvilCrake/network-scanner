"""
Основной модуль сканирования сети
"""

import asyncio
import ipaddress
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime
import platform

try:
    from scapy.all import ARP, Ether, IP, ICMP, TCP, srp, sr1, conf
    from scapy.layers.l2 import getmacbyip
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: scapy not available. Some features may be limited.")

from scanner.device_info import DeviceInfo
from scanner.os_detection import OSDetector
from config.settings import (
    COMMON_PORTS, ICMP_TIMEOUT, TCP_TIMEOUT, ARP_TIMEOUT,
    MAX_CONCURRENT_SCANS, MAX_CONCURRENT_PORTS
)
from utils.helpers import is_admin


class NetworkScanner:
    """Класс для сканирования сети"""
    
    def __init__(self, network_range: str, timeout: float = 2.0, verbose: bool = False):
        """
        Инициализация сканера
        
        Args:
            network_range: Диапазон сети (например, "192.168.1.0/24")
            timeout: Таймаут для операций
        """
        self.network_range = network_range
        self.timeout = timeout
        self.devices: Dict[str, DeviceInfo] = {}
        self.os_detector = OSDetector()
        self.is_windows = platform.system() == "Windows"
        self.verbose = verbose
        self.scapy_enabled = SCAPY_AVAILABLE and (not self.is_windows or is_admin())
        
        if self.scapy_enabled and self.is_windows:
            # Настройка scapy для Windows (Npcap required)
            conf.use_pcap = True
        elif SCAPY_AVAILABLE and not self.scapy_enabled:
            print("Info: Scapy detected but disabled (requires admin privileges on Windows).")
        
    def _get_network_hosts(self) -> List[str]:
        """Получает список всех IP адресов в сети"""
        try:
            network = ipaddress.IPv4Network(self.network_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            raise ValueError(f"Invalid network range: {self.network_range}") from e
    
    def arp_scan(self, ip: str) -> Optional[str]:
        """
        ARP сканирование для получения MAC адреса
        
        Args:
            ip: IP адрес для сканирования
            
        Returns:
            MAC адрес или None
        """
        if not self.scapy_enabled:
            return None
        
        try:
            # Создаем ARP запрос
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Отправляем запрос
            answered_list = srp(
                arp_request_broadcast,
                timeout=ARP_TIMEOUT,
                verbose=False
            )[0]
            
            if answered_list:
                return answered_list[0][1].hwsrc
        except Exception:
            pass
        
        return None
    
    def icmp_ping(self, ip: str) -> Tuple[bool, Optional[int]]:
        """
        ICMP ping для проверки доступности
        
        Args:
            ip: IP адрес для проверки
            
        Returns:
            Tuple (is_alive, ttl)
        """
        if not self.scapy_enabled:
            # Fallback на стандартный ping
            import subprocess
            try:
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', str(int(ICMP_TIMEOUT * 1000)), ip],
                    capture_output=True,
                    timeout=ICMP_TIMEOUT + 1
                )
                return result.returncode == 0, None
            except Exception:
                return False, None
        
        try:
            # Используем scapy для ICMP
            packet = IP(dst=ip) / ICMP()
            response = sr1(packet, timeout=ICMP_TIMEOUT, verbose=False)
            
            if response:
                return True, response.ttl
        except Exception:
            pass
        
        return False, None
    
    def tcp_scan_port(self, ip: str, port: int) -> Tuple[bool, Optional[int]]:
        """
        Сканирование TCP порта
        
        Args:
            ip: IP адрес
            port: Порт для сканирования
            
        Returns:
            Tuple (is_open, window_size)
        """
        if not self.scapy_enabled:
            # Fallback на socket
            import socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(TCP_TIMEOUT)
                result = sock.connect_ex((ip, port))
                sock.close()
                return result == 0, None
            except Exception:
                return False, None
        
        try:
            # SYN scan
            packet = IP(dst=ip) / TCP(dport=port, flags="S")
            response = sr1(packet, timeout=TCP_TIMEOUT, verbose=False)
            
            if response and response.haslayer(TCP):
                tcp_layer = response[TCP]
                if tcp_layer.flags == 18:  # SYN-ACK
                    return True, tcp_layer.window
        except Exception:
            pass
        
        return False, None
    
    async def scan_device_async(self, ip: str) -> Optional[DeviceInfo]:
        """
        Асинхронное сканирование устройства
        
        Args:
            ip: IP адрес устройства
            
        Returns:
            DeviceInfo или None если устройство не найдено
        """
        device = DeviceInfo(ip)
        
        # ICMP ping для проверки доступности
        is_alive, ttl = await asyncio.to_thread(self.icmp_ping, ip)
        if not is_alive:
            return None
        
        device.status = "online"
        device.ttl = ttl
        
        # ARP для получения MAC
        mac = await asyncio.to_thread(self.arp_scan, ip)
        if mac:
            device.set_mac(mac)
        
        # Получение hostname
        device.update_hostname()
        
        # Сканирование портов
        port_tasks = []
        for port in COMMON_PORTS:
            task = asyncio.create_task(
                asyncio.to_thread(self.tcp_scan_port, ip, port)
            )
            port_tasks.append((port, task))
        
        # Ожидаем результаты портов с ограничением параллелизма
        window_size = None
        for port, task in port_tasks:
            try:
                is_open, win_size = await asyncio.wait_for(task, timeout=TCP_TIMEOUT + 1)
                if is_open:
                    device.add_port(port)
                    if win_size and not window_size:
                        window_size = win_size
            except asyncio.TimeoutError:
                pass
        
        device.window_size = window_size
        
        # Определение ОС
        os_info = self.os_detector.detect_os(
            ttl=device.ttl,
            window_size=device.window_size,
            open_ports=device.open_ports
        )
        device.set_os_info(os_info)
        
        return device
    
    async def scan_network_async(self) -> List[DeviceInfo]:
        """
        Асинхронное сканирование всей сети
        
        Returns:
            Список найденных устройств
        """
        hosts = self._get_network_hosts()
        if self.verbose:
            print(f"Scanning {len(hosts)} hosts in {self.network_range}...")
        
        # Создаем семафор для ограничения параллелизма
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
        
        async def scan_with_semaphore(ip: str):
            async with semaphore:
                return await self.scan_device_async(ip)
        
        # Создаем задачи для всех хостов
        tasks = [scan_with_semaphore(ip) for ip in hosts]
        
        # Выполняем сканирование с прогрессом
        completed = 0
        for coro in asyncio.as_completed(tasks):
            device = await coro
            completed += 1
            if device:
                self.devices[device.ip] = device
                if self.verbose:
                    print(f"[{completed}/{len(hosts)}] Found: {device.ip} ({device.hostname or 'Unknown'}) - {device.os_type}")
            elif self.verbose and completed % 10 == 0:
                print(f"[{completed}/{len(hosts)}] Scanned...")
        
        return list(self.devices.values())
    
    def scan_network(self) -> List[DeviceInfo]:
        """
        Синхронная обертка для сканирования сети
        
        Returns:
            Список найденных устройств
        """
        if not self.scapy_enabled:
            if SCAPY_AVAILABLE:
                print("Warning: Scapy disabled (requires admin/Npcap on Windows). Continuing with limited functionality...")
            else:
                print("Warning: Scapy is not available. Install it for full functionality:")
                print("  pip install scapy")
                print("Continuing with limited functionality...")
        
        return asyncio.run(self.scan_network_async())

