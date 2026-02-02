import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from urllib.parse import quote

import requests


class CertificateSearch:
    """
    Поиск доменов через публичный источник crt.sh (без ключей).
    Используется как альтернатива коммерческим API для сертификатов.
    """

    def __init__(self, cache_dir: str = "data/cache/crtsh", cache_ttl: int = 3600, rate_limit_delay: float = 1.0):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl = cache_ttl
        self.rate_limit_delay = rate_limit_delay
        self.base_url = "https://crt.sh/"

    def _cache_path(self, key: str) -> Path:
        safe_key = "".join(c for c in key if c.isalnum() or c in ["_", "-"])[:100]
        return self.cache_dir / f"{safe_key}.json"

    def _load_cache(self, key: str) -> Optional[Dict[str, Any]]:
        cache_path = self._cache_path(key)
        if not cache_path.exists():
            return None
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            if time.time() - payload.get("timestamp", 0) <= self.cache_ttl:
                return payload.get("data")
        except Exception:
            return None
        return None

    def _save_cache(self, key: str, data: Dict[str, Any]) -> None:
        cache_path = self._cache_path(key)
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump({"timestamp": time.time(), "data": data}, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def search_domain(self, domain: str, include_subdomains: bool = True, use_cache: bool = True) -> Dict[str, Any]:
        """
        Возвращает список доменов/поддоменов, найденных через crt.sh.
        """
        query = f"%.{domain}" if include_subdomains else domain
        cache_key = f"crtsh_{query}"

        if use_cache:
            cached = self._load_cache(cache_key)
            if cached:
                return cached

        time.sleep(self.rate_limit_delay)
        url = f"{self.base_url}?q={quote(query)}&output=json"
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        try:
            results = response.json()
        except ValueError:
            results = []

        domains = []
        for item in results:
            name_value = item.get("name_value", "")
            for entry in name_value.splitlines():
                entry = entry.strip().lower()
                if entry.startswith("*."):
                    entry = entry[2:]
                if entry and entry.endswith(domain.lower()):
                    domains.append(entry)

        unique_domains = sorted(set(domains))
        data = {
            "domain": domain,
            "include_subdomains": include_subdomains,
            "count": len(unique_domains),
            "domains": unique_domains
        }

        if use_cache:
            self._save_cache(cache_key, data)

        return data
