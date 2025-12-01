"""
Легкий модуль для определения производителя по MAC-адресу.
Скачивает и кэширует базу IEEE OUI, обновляя её по мере необходимости.
"""

from __future__ import annotations

import csv
import json
import time
from io import StringIO
from pathlib import Path
from threading import Lock
from typing import Dict, Optional

import requests

BASE_DIR = Path(__file__).resolve().parent.parent
CACHE_DIR = BASE_DIR / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

OUI_CACHE_FILE = CACHE_DIR / "oui_cache.json"
OUI_CACHE_TTL = 7 * 24 * 60 * 60  # 7 дней
OUI_DATA_URL = "https://standards-oui.ieee.org/oui/oui.csv"


class OUILookup:
    """Менеджер загрузки и кэширования OUI-данных."""

    def __init__(self) -> None:
        self._vendors: Dict[str, str] = {}
        self._loaded_at: float = 0.0
        self._lock = Lock()

    def lookup(self, mac: Optional[str]) -> Optional[str]:
        """Возвращает производителя по MAC-адресу."""
        if not mac:
            return None

        prefix = self._normalize_prefix(mac)
        if not prefix:
            return None

        self._ensure_data_loaded()
        return self._vendors.get(prefix)

    def _normalize_prefix(self, mac: str) -> Optional[str]:
        hex_only = "".join(ch for ch in mac if ch.isalnum()).upper()
        if len(hex_only) < 6 or not all(c in "0123456789ABCDEF" for c in hex_only[:6]):
            return None
        return hex_only[:6]

    def _ensure_data_loaded(self) -> None:
        with self._lock:
            if self._vendors and (time.time() - self._loaded_at) < OUI_CACHE_TTL:
                return

            if self._load_from_cache():
                return

            if self._download_and_cache():
                return

            # В случае полного провала оставляем имеющиеся данные (если были)

    def _load_from_cache(self) -> bool:
        if not OUI_CACHE_FILE.exists():
            return False

        try:
            with OUI_CACHE_FILE.open("r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except Exception:
            return False

        updated = payload.get("updated_at", 0)
        data = payload.get("vendors")
        if not isinstance(data, dict):
            return False

        if (time.time() - updated) > OUI_CACHE_TTL:
            # Кэш устарел — используем как временный, но сразу инициируем обновление
            self._vendors = {k: str(v) for k, v in data.items()}
            self._loaded_at = updated
            # После выхода _ensure_data_loaded попробует скачать свежие данные
            return False

        self._vendors = {k: str(v) for k, v in data.items()}
        self._loaded_at = updated
        return True

    def _download_and_cache(self) -> bool:
        try:
            response = requests.get(OUI_DATA_URL, timeout=15)
            response.raise_for_status()
        except Exception:
            return False

        try:
            vendors = self._parse_csv(response.text)
        except Exception:
            return False

        if not vendors:
            return False

        self._vendors = vendors
        self._loaded_at = time.time()

        try:
            with OUI_CACHE_FILE.open("w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "updated_at": self._loaded_at,
                        "vendors": self._vendors,
                    },
                    fh,
                    ensure_ascii=False,
                )
        except Exception:
            pass

        return True

    def _parse_csv(self, csv_text: str) -> Dict[str, str]:
        reader = csv.DictReader(StringIO(csv_text))
        vendors: Dict[str, str] = {}
        for row in reader:
            assignment = (row.get("Assignment") or "").replace("-", "").replace(":", "").upper()
            name = (row.get("Organization Name") or row.get("Organization Name") or "").strip()
            if len(assignment) >= 6 and name:
                vendors[assignment[:6]] = name
        return vendors


# Глобальный экземпляр для повторного использования
oui_lookup = OUILookup()

