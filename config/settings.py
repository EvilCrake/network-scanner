"""
Конфигурация сканера сети
"""

import os
from typing import List

# Версия сканера
SCANNER_VERSION = "1.0.0"

# Стандартные порты для сканирования
COMMON_PORTS = [
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    135,   # MSRPC
    139,   # NetBIOS
    443,   # HTTPS
    445,   # SMB
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    8080,  # HTTP-Proxy
]

# Таймауты (в секундах)
ICMP_TIMEOUT = 1.0
TCP_TIMEOUT = 2.0
ARP_TIMEOUT = 1.0

# Параллелизм
MAX_CONCURRENT_SCANS = 100
MAX_CONCURRENT_PORTS = 50

# TTL значения для определения ОС
OS_TTL_SIGNATURES = {
    (64,): "Linux",
    (128,): "Windows",
    (255,): "Linux/Unix",
    (32,): "Windows 95/98",
}

# TCP Window Size для определения ОС
OS_WINDOW_SIZES = {
    (8192, 16384): "Linux",
    (65535,): "Windows",
    (4128,): "Cisco",
}

# Сервисы по портам
PORT_SERVICES = {
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    135: "MSRPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
}

# Форматы экспорта
EXPORT_FORMATS = ["csv", "json", "txt"]

# Максимальное количество попыток
MAX_RETRIES = 3

