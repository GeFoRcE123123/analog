"""
Кэширование для Grafana парсера

Простое файловое кэширование для снижения нагрузки на сервер Grafana
"""

import hashlib
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class GrafanaCache:
    """
    Простое файловое кэширование для парсера
    """
    
    def __init__(self, cache_dir='cache/grafana', max_age_hours=24):
        """
        Args:
            cache_dir: Директория для кэша
            max_age_hours: Максимальный возраст кэша (часы)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age = timedelta(hours=max_age_hours)
        logger.info(f"📦 Grafana cache initialized: {self.cache_dir}")
    
    def _get_cache_path(self, url: str) -> Path:
        """Путь к файлу кэша для URL"""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return self.cache_dir / f"{url_hash}.json"
    
    def get(self, url: str) -> Optional[str]:
        """
        Получить данные из кэша
        
        Args:
            url: URL для поиска
        
        Returns:
            Кэшированные данные или None
        """
        cache_path = self._get_cache_path(url)
        
        if not cache_path.exists():
            return None
        
        # Проверить возраст кэша
        cache_age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
        if cache_age > self.max_age:
            logger.debug(f"Cache expired for {url}")
            return None
        
        # Загрузить данные
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            return cache_data.get('content')
        except Exception as e:
            logger.error(f"Error reading cache: {e}")
            return None
    
    def set(self, url: str, content: str):
        """
        Сохранить данные в кэш
        
        Args:
            url: URL
            content: Содержимое для кэширования
        """
        cache_path = self._get_cache_path(url)
        
        cache_data = {
            'url': url,
            'content': content,
            'cached_at': datetime.now().isoformat()
        }
        
        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
            logger.debug(f"Cached: {url}")
        except Exception as e:
            logger.error(f"Error writing cache: {e}")
    
    def clear(self):
        """Очистить весь кэш"""
        count = 0
        for cache_file in self.cache_dir.glob('*.json'):
            cache_file.unlink()
            count += 1
        logger.info(f"🗑️  Cleared {count} cache files")
    
    def clear_old(self):
        """Удалить устаревший кэш"""
        count = 0
        for cache_file in self.cache_dir.glob('*.json'):
            cache_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
            if cache_age > self.max_age:
                cache_file.unlink()
                count += 1
        if count > 0:
            logger.info(f"🗑️  Cleared {count} old cache files")

