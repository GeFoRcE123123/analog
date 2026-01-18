"""
Менеджер конфигурации для управления настройками платформы
"""

import os
import yaml
import json
from typing import Dict, Any, Optional
from pathlib import Path


class ConfigManager:
    """Управление конфигурацией системы"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Инициализация менеджера конфигурации
        
        Args:
            config_path: Путь к файлу конфигурации (YAML или JSON)
        """
        self.config: Dict[str, Any] = {}
        self.config_path = config_path
        
        # Загрузка конфигурации из файла
        if config_path and os.path.exists(config_path):
            self.load_from_file(config_path)
        else:
            # Загрузка конфигурации по умолчанию
            self._load_default_config()
        
        # Переопределение из переменных окружения
        self._load_from_env()
    
    def _load_default_config(self):
        """Загрузка конфигурации по умолчанию"""
        self.config = {
            "training": {
                "default_epochs": 100,
                "batch_size": 32,
                "learning_rate": 0.001,
                "early_stopping_patience": 10,
                "min_accuracy_threshold": 0.7,
                "save_best_only": True,
                "optimizer": "adam",
                "loss_function": "cross_entropy"
            },
            "gpu": {
                "min_memory_gb": 2,
                "auto_clear_cache": True,
                "fallback_to_cpu": True
            },
            "data": {
                "train_split": 0.7,
                "val_split": 0.15,
                "test_split": 0.15,
                "normalize": True,
                "supported_formats": ["csv", "parquet", "hdf5", "pkl"]
            },
            "paths": {
                "models_dir": "/home/user/projects/models",
                "logs_dir": "/var/log/ml_platform",
                "data_dir": "/home/user/projects/data"
            },
            "logging": {
                "level": "INFO",
                "use_journald": True,
                "log_file": "/var/log/ml_platform/training.log"
            },
            "api": {
                "host": "0.0.0.0",
                "port": 8000,
                "workers": 4
            },
            "monitoring": {
                "prometheus_enabled": True,
                "prometheus_port": 9090,
                "metrics_path": "/metrics"
            }
        }
    
    def load_from_file(self, config_path: str):
        """
        Загрузка конфигурации из файла
        
        Args:
            config_path: Путь к файлу конфигурации
        """
        self.config_path = config_path
        path = Path(config_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Конфигурационный файл не найден: {config_path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            if path.suffix in ['.yaml', '.yml']:
                self.config = yaml.safe_load(f) or {}
            elif path.suffix == '.json':
                self.config = json.load(f)
            else:
                raise ValueError(f"Неподдерживаемый формат конфигурации: {path.suffix}")
    
    def _load_from_env(self):
        """Загрузка конфигурации из переменных окружения"""
        env_mappings = {
            "ML_PLATFORM_MODELS_DIR": ("paths", "models_dir"),
            "ML_PLATFORM_LOGS_DIR": ("paths", "logs_dir"),
            "ML_PLATFORM_DATA_DIR": ("paths", "data_dir"),
            "ML_PLATFORM_BATCH_SIZE": ("training", "batch_size", int),
            "ML_PLATFORM_LEARNING_RATE": ("training", "learning_rate", float),
            "ML_PLATFORM_EPOCHS": ("training", "default_epochs", int),
            "ML_PLATFORM_API_HOST": ("api", "host"),
            "ML_PLATFORM_API_PORT": ("api", "port", int),
            "ML_PLATFORM_LOG_LEVEL": ("logging", "level"),
        }
        
        for env_var, (section, key, *converter) in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                if converter:
                    try:
                        value = converter[0](value)
                    except (ValueError, TypeError):
                        continue
                if section in self.config and isinstance(self.config[section], dict):
                    self.config[section][key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Получение значения конфигурации
        
        Args:
            key: Ключ конфигурации (поддерживает вложенные ключи через точку)
            default: Значение по умолчанию
            
        Returns:
            Значение конфигурации
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """
        Установка значения конфигурации
        
        Args:
            key: Ключ конфигурации (поддерживает вложенные ключи через точку)
            value: Значение для установки
        """
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self, config_path: Optional[str] = None):
        """
        Сохранение конфигурации в файл
        
        Args:
            config_path: Путь для сохранения (если не указан, используется текущий)
        """
        path = Path(config_path or self.config_path or "config.yaml")
        
        with open(path, 'w', encoding='utf-8') as f:
            if path.suffix in ['.yaml', '.yml']:
                yaml.dump(self.config, f, default_flow_style=False, allow_unicode=True)
            elif path.suffix == '.json':
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            else:
                raise ValueError(f"Неподдерживаемый формат конфигурации: {path.suffix}")
    
    def get_profile(self, profile_name: str) -> Dict[str, Any]:
        """
        Получение профиля конфигурации
        
        Args:
            profile_name: Имя профиля
            
        Returns:
            Словарь с настройками профиля
        """
        profiles = self.get("profiles", {})
        return profiles.get(profile_name, {})
