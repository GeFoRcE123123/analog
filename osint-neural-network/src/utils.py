import logging
from pathlib import Path
from typing import Dict, Any
import yaml


def setup_logging(name: str, level: int = logging.INFO) -> logging.Logger:
    """Настройка базового логгера."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def load_config(config_path: str) -> Dict[str, Any]:
    """Загрузка YAML конфигурации."""
    path = Path(config_path)
    if not path.exists():
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f) or {}
