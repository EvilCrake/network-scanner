"""
Модуль определения операционной системы устройств
"""

from typing import Optional, Dict, Tuple
from config.settings import OS_TTL_SIGNATURES, OS_WINDOW_SIZES


class OSDetector:
    """Класс для определения операционной системы по сетевым признакам"""
    
    def __init__(self):
        self.os_signatures = OS_TTL_SIGNATURES
        self.window_sizes = OS_WINDOW_SIZES
    
    def detect_by_ttl(self, ttl: int) -> Tuple[Optional[str], float]:
        """
        Определяет ОС по значению TTL
        
        Args:
            ttl: Значение TTL из ответа
            
        Returns:
            Tuple (OS type, confidence)
        """
        if not ttl:
            return None, 0.0
        
        # Нормализуем TTL (обычно отправляется 64, 128, 255)
        normalized_ttls = [64, 128, 255, 32]
        closest_ttl = min(normalized_ttls, key=lambda x: abs(x - ttl))
        
        for ttl_range, os_type in self.os_signatures.items():
            if closest_ttl in ttl_range:
                # Уверенность зависит от близости к эталонному значению
                confidence = 0.9 if abs(ttl - closest_ttl) <= 1 else 0.6
                return os_type, confidence
        
        return None, 0.0
    
    def detect_by_window_size(self, window_size: int) -> Tuple[Optional[str], float]:
        """
        Определяет ОС по размеру TCP окна
        
        Args:
            window_size: Размер TCP окна
            
        Returns:
            Tuple (OS type, confidence)
        """
        if not window_size:
            return None, 0.0
        
        for size_range, os_type in self.window_sizes.items():
            if window_size in size_range:
                return os_type, 0.7
        
        return None, 0.0
    
    def detect_by_ports(self, open_ports: list) -> Tuple[Optional[str], float]:
        """
        Определяет ОС по открытым портам
        
        Args:
            open_ports: Список открытых портов
            
        Returns:
            Tuple (OS type, confidence)
        """
        if not open_ports:
            return None, 0.0
        
        # Windows характерные порты
        windows_ports = {135, 139, 445, 3389}
        # Linux характерные порты
        linux_ports = {22, 111, 2049}
        
        windows_count = len([p for p in open_ports if p in windows_ports])
        linux_count = len([p for p in open_ports if p in linux_ports])
        
        if windows_count > linux_count and windows_count > 0:
            return "Windows", 0.6
        elif linux_count > windows_count and linux_count > 0:
            return "Linux", 0.6
        
        return None, 0.0
    
    def detect_os(self, ttl: Optional[int] = None, 
                   window_size: Optional[int] = None,
                   open_ports: Optional[list] = None) -> Dict[str, any]:
        """
        Комплексное определение ОС по всем доступным признакам
        
        Args:
            ttl: TTL значение
            window_size: Размер TCP окна
            open_ports: Список открытых портов
            
        Returns:
            Словарь с информацией об ОС
        """
        results = []
        
        # Определение по TTL
        if ttl:
            os_type, confidence = self.detect_by_ttl(ttl)
            if os_type:
                results.append((os_type, confidence, "TTL"))
        
        # Определение по Window Size
        if window_size:
            os_type, confidence = self.detect_by_window_size(window_size)
            if os_type:
                results.append((os_type, confidence, "WindowSize"))
        
        # Определение по портам
        if open_ports:
            os_type, confidence = self.detect_by_ports(open_ports)
            if os_type:
                results.append((os_type, confidence, "Ports"))
        
        if not results:
            return {
                "type": "Unknown",
                "version": "Unknown",
                "confidence": 0.0,
                "methods": []
            }
        
        # Выбираем наиболее вероятный результат
        # Взвешиваем по уверенности
        os_votes = {}
        for os_type, confidence, method in results:
            if os_type not in os_votes:
                os_votes[os_type] = {"confidence": 0.0, "methods": []}
            os_votes[os_type]["confidence"] += confidence
            os_votes[os_type]["methods"].append(method)
        
        # Находим ОС с максимальной уверенностью
        best_os = max(os_votes.items(), key=lambda x: x[1]["confidence"])
        
        # Нормализуем уверенность (максимум 1.0)
        final_confidence = min(best_os[1]["confidence"] / len(results), 1.0)
        
        return {
            "type": best_os[0],
            "version": "Unknown",  # Версию можно определить дополнительными методами
            "confidence": round(final_confidence, 2),
            "methods": best_os[1]["methods"]
        }

