import os
import json
from typing import Dict, Any, Optional
import requests
import time
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()


class CensysAPI:
    """
    Минимальная обертка для Censys API с кэшированием.
    """

    def __init__(self, api_id: Optional[str] = None, api_secret: Optional[str] = None):
        self.api_id = api_id or os.getenv('CENSYS_API_ID')
        self.api_secret = api_secret or os.getenv('CENSYS_API_SECRET')
        if not self.api_id or not self.api_secret:
            raise ValueError("CENSYS_API_ID или CENSYS_API_SECRET не установлены в .env файле")

        self.base_url = "https://search.censys.io/api/v2"
        self.cache_dir = Path("data/cache/censys")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.rate_limit_delay = 1.0

    def _cache_path(self, key: str) -> Path:
        safe_key = "".join(c for c in key if c.isalnum() or c in ['_', '-'])[:100]
        return self.cache_dir / f"{safe_key}.json"

    def _load_cache(self, key: str) -> Optional[Dict[str, Any]]:
        cache_path = self._cache_path(key)
        if cache_path.exists():
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    def _save_cache(self, key: str, data: Dict[str, Any]):
        cache_path = self._cache_path(key)
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def search_hosts(self, query: str, per_page: int = 50, use_cache: bool = True) -> Dict[str, Any]:
        """Поиск хостов в Censys."""
        cache_key = f"hosts_{query}_{per_page}"
        if use_cache:
            cached = self._load_cache(cache_key)
            if cached:
                return cached

        time.sleep(self.rate_limit_delay)
        response = requests.get(
            f"{self.base_url}/hosts/search",
            params={"q": query, "per_page": per_page},
            auth=(self.api_id, self.api_secret),
            timeout=30
        )
        response.raise_for_status()
        data = response.json()

        if use_cache:
            self._save_cache(cache_key, data)

        return data
