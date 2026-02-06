"""
Базовый класс для всех парсеров уязвимостей
Обеспечивает единообразный интерфейс и общую функциональность
"""
import logging
import time
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class ParserStatus(Enum):
    """Статусы парсера"""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


class BaseParser(ABC):
    """
    Базовый класс для всех парсеров уязвимостей
    
    Обеспечивает:
    - Единообразный интерфейс для всех парсеров
    - Общую обработку ошибок и логирование
    - Rate limiting и retry логику
    - Прогресс-трекинг
    - Безопасность (SSL проверка, валидация URL)
    """
    
    def __init__(self, name: str, config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.{name}")
        self.status = ParserStatus.IDLE
        self.config = config or {}
        
        # Конфигурация по умолчанию
        self.max_retries = self.config.get('max_retries', 3)
        self.retry_delay = self.config.get('retry_delay', 5)  # секунды
        self.request_timeout = self.config.get('request_timeout', 30)
        self.rate_limit_delay = self.config.get('rate_limit_delay', 1.0)  # секунды между запросами
        self.verify_ssl = self.config.get('verify_ssl', True)
        
        # Статистика
        self.stats = {
            'total_parsed': 0,
            'total_saved': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None,
            'last_sync': None
        }
        
        # Прогресс
        self.progress = {
            'current': 0,
            'total': 0,
            'percentage': 0,
            'current_item': None,
            'message': ''
        }
    
    @abstractmethod
    def parse(self, **kwargs) -> List[Dict[str, Any]]:
        """
        Основной метод парсинга (должен быть реализован в наследниках)
        
        Returns:
            List[Dict[str, Any]]: Список уязвимостей в унифицированном формате
        """
        pass
    
    @abstractmethod
    def get_source_info(self) -> Dict[str, Any]:
        """
        Возвращает информацию об источнике данных
        
        Returns:
            Dict с ключами: name, type, url, description, rate_limit
        """
        pass
    
    def validate_url(self, url: str) -> bool:
        """
        Валидация URL на безопасность
        
        Args:
            url: URL для проверки
            
        Returns:
            bool: True если URL безопасен
        """
        if not url:
            return False
        
        # Проверка схемы
        allowed_schemes = ['http', 'https']
        if not any(url.startswith(f'{scheme}://') for scheme in allowed_schemes):
            self.logger.warning(f"Недопустимая схема URL: {url}")
            return False
        
        # Проверка на подозрительные паттерны
        suspicious_patterns = [
            'javascript:',
            'data:',
            'file:',
            '@localhost',
            '@127.0.0.1',
        ]
        
        url_lower = url.lower()
        for pattern in suspicious_patterns:
            if pattern in url_lower:
                self.logger.warning(f"Подозрительный паттерн в URL: {pattern}")
                return False
        
        return True
    
    def make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[Any]:
        """
        Безопасный HTTP запрос с retry логикой и rate limiting
        
        Args:
            url: URL для запроса
            method: HTTP метод
            **kwargs: Дополнительные параметры для requests
            
        Returns:
            Response объект или None при ошибке
        """
        if not self.validate_url(url):
            return None
        
        import requests
        
        # Rate limiting
        time.sleep(self.rate_limit_delay)
        
        # Подготовка параметров
        request_kwargs = {
            'timeout': self.request_timeout,
            'verify': self.verify_ssl,
            **kwargs
        }
        
        # Retry логика
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                response = requests.request(method, url, **request_kwargs)
                response.raise_for_status()
                return response
                
            except requests.exceptions.SSLError as e:
                self.logger.error(f"SSL ошибка для {url}: {e}")
                if self.verify_ssl:
                    self.logger.warning("Попытка с отключенной проверкой SSL...")
                    request_kwargs['verify'] = False
                    try:
                        response = requests.request(method, url, **request_kwargs)
                        response.raise_for_status()
                        return response
                    except Exception as e2:
                        last_exception = e2
                else:
                    last_exception = e
                    
            except requests.exceptions.RequestException as e:
                last_exception = e
                self.logger.warning(f"Ошибка запроса к {url} (попытка {attempt + 1}/{self.max_retries}): {e}")
                
                if attempt < self.max_retries - 1:
                    time.sleep(self.retry_delay * (attempt + 1))  # Exponential backoff
                else:
                    self.logger.error(f"Не удалось выполнить запрос к {url} после {self.max_retries} попыток")
                    self.stats['errors'] += 1
        
        if last_exception:
            self.logger.error(f"Критическая ошибка запроса: {last_exception}")
        
        return None
    
    def update_progress(self, current: int, total: int, message: str = '', item: Optional[str] = None):
        """Обновление прогресса парсинга"""
        self.progress['current'] = current
        self.progress['total'] = total
        self.progress['percentage'] = int((current / total * 100)) if total > 0 else 0
        self.progress['message'] = message
        self.progress['current_item'] = item
        
        self.logger.info(f"Прогресс: {self.progress['percentage']}% - {message}")
    
    def start(self):
        """Начать парсинг"""
        self.status = ParserStatus.RUNNING
        self.stats['start_time'] = datetime.now()
        self.stats['errors'] = 0
        self.logger.info(f"Запуск парсера {self.name}")
    
    def stop(self):
        """Остановить парсинг"""
        self.status = ParserStatus.IDLE
        self.stats['end_time'] = datetime.now()
        self.logger.info(f"Остановка парсера {self.name}")
    
    def pause(self):
        """Приостановить парсинг"""
        if self.status == ParserStatus.RUNNING:
            self.status = ParserStatus.PAUSED
            self.logger.info(f"Парсер {self.name} приостановлен")
    
    def resume(self):
        """Возобновить парсинг"""
        if self.status == ParserStatus.PAUSED:
            self.status = ParserStatus.RUNNING
            self.logger.info(f"Парсер {self.name} возобновлен")
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику парсера"""
        duration = None
        if self.stats['start_time']:
            end_time = self.stats['end_time'] or datetime.now()
            duration = (end_time - self.stats['start_time']).total_seconds()
        
        return {
            **self.stats,
            'status': self.status.value,
            'progress': self.progress.copy(),
            'duration_seconds': duration,
            'source_info': self.get_source_info()
        }
    
    def reset_stats(self):
        """Сбросить статистику"""
        self.stats = {
            'total_parsed': 0,
            'total_saved': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None,
            'last_sync': None
        }
        self.progress = {
            'current': 0,
            'total': 0,
            'percentage': 0,
            'current_item': None,
            'message': ''
        }

