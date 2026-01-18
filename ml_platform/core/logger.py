"""
Система логирования с поддержкой systemd journal
"""

import logging
import sys
import os
from pathlib import Path
from typing import Optional
from datetime import datetime

try:
    from systemd import journal
    JOURNALD_AVAILABLE = True
except ImportError:
    JOURNALD_AVAILABLE = False


class SystemdJournalHandler(logging.Handler):
    """Обработчик для записи в systemd journal"""
    
    def __init__(self):
        super().__init__()
        if JOURNALD_AVAILABLE:
            self.journal = journal.JournalHandler()
        else:
            self.journal = None
    
    def emit(self, record):
        """Отправка записи в journal"""
        if self.journal:
            try:
                self.journal.emit(record)
            except Exception:
                pass  # Graceful degradation


class PlatformLogger:
    """Централизованный логгер платформы"""
    
    _instance: Optional['PlatformLogger'] = None
    _logger: Optional[logging.Logger] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._logger is None:
            self._setup_logger()
    
    def _setup_logger(self):
        """Настройка логгера"""
        self._logger = logging.getLogger("ml_platform")
        self._logger.setLevel(logging.DEBUG)
        
        # Очистка существующих обработчиков
        self._logger.handlers.clear()
        
        # Форматтер
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Консольный обработчик
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self._logger.addHandler(console_handler)
        
        # Обработчик для systemd journal
        if JOURNALD_AVAILABLE:
            try:
                journal_handler = SystemdJournalHandler()
                journal_handler.setLevel(logging.INFO)
                self._logger.addHandler(journal_handler)
            except Exception as e:
                self._logger.warning(f"Не удалось инициализировать journald: {e}")
        
        # Файловый обработчик
        log_dir = Path("/var/log/ml_platform")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / "training.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        self._logger.addHandler(file_handler)
    
    @classmethod
    def get_logger(cls) -> logging.Logger:
        """Получение экземпляра логгера"""
        if cls._logger is None:
            cls()
        return cls._logger
    
    @classmethod
    def configure(cls, level: str = "INFO", log_file: Optional[str] = None, use_journald: bool = True):
        """
        Настройка логгера
        
        Args:
            level: Уровень логирования
            log_file: Путь к файлу логов
            use_journald: Использовать systemd journal
        """
        logger = cls.get_logger()
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_path)
            file_handler.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
    
    @classmethod
    def info(cls, message: str, **kwargs):
        """Информационное сообщение"""
        cls.get_logger().info(message, **kwargs)
    
    @classmethod
    def warning(cls, message: str, **kwargs):
        """Предупреждение"""
        cls.get_logger().warning(message, **kwargs)
    
    @classmethod
    def error(cls, message: str, **kwargs):
        """Ошибка"""
        cls.get_logger().error(message, **kwargs)
    
    @classmethod
    def debug(cls, message: str, **kwargs):
        """Отладочное сообщение"""
        cls.get_logger().debug(message, **kwargs)
    
    @classmethod
    def critical(cls, message: str, **kwargs):
        """Критическая ошибка"""
        cls.get_logger().critical(message, **kwargs)
    
    @classmethod
    def log_training_start(cls, model_name: str, epochs: int, batch_size: int):
        """Логирование начала обучения"""
        cls.info(
            f"Начало обучения модели '{model_name}': "
            f"эпохи={epochs}, batch_size={batch_size}"
        )
    
    @classmethod
    def log_epoch(cls, epoch: int, loss: float, accuracy: float, val_loss: Optional[float] = None, val_accuracy: Optional[float] = None):
        """Логирование эпохи"""
        msg = f"Эпоха {epoch}: loss={loss:.4f}, accuracy={accuracy:.4f}"
        if val_loss is not None and val_accuracy is not None:
            msg += f", val_loss={val_loss:.4f}, val_accuracy={val_accuracy:.4f}"
        cls.info(msg)
    
    @classmethod
    def log_training_complete(cls, model_name: str, final_accuracy: float, epochs_trained: int):
        """Логирование завершения обучения"""
        cls.info(
            f"Обучение модели '{model_name}' завершено: "
            f"точность={final_accuracy:.4f}, эпох={epochs_trained}"
        )
    
    @classmethod
    def log_gpu_status(cls, available: bool, memory_gb: Optional[float] = None):
        """Логирование статуса GPU"""
        if available:
            cls.info(f"GPU доступна, память: {memory_gb:.2f} GB" if memory_gb else "GPU доступна")
        else:
            cls.warning("GPU недоступна, используется CPU")
