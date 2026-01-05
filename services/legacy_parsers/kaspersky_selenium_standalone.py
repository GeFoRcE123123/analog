#!/usr/bin/env python3
"""
Станandalone скрипт для парсинга уязвимостей Kaspersky с использованием Selenium
Запуск: python kaspersky_selenium_standalone.py
"""
import sys
import os
import logging
from pathlib import Path

# Добавляем корень проекта в путь
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from config import Config
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from services.legacy_parsers.kaspersky_selenium_parser import KasperskySeleniumParser

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('kaspersky_selenium_parser.log')
    ]
)

logger = logging.getLogger(__name__)


def main():
    """Главная функция"""
    logger.info("=" * 60)
    logger.info("Запуск парсера Kaspersky с Selenium")
    logger.info("=" * 60)
    
    try:
        # Инициализация БД
        logger.info("Подключение к базе данных...")
        db_manager = DatabaseManager()
        vulnerability_repo = LegacyVulnerabilityRepository(db_manager.connection)
        logger.info("✅ Подключение к БД установлено")
        
        # Создание парсера
        # headless=True для запуска без GUI (опционально)
        # use_undetected=True для обхода обнаружения (рекомендуется)
        parser = KasperskySeleniumParser(
            vulnerability_repo,
            headless=False,  # Установите True для headless режима
            use_undetected=True
        )
        
        # Парсинг
        logger.info("Начало парсинга...")
        results = parser.parse(limit=None)  # None = парсить все
        
        # Вывод результатов
        logger.info("=" * 60)
        logger.info("РЕЗУЛЬТАТЫ ПАРСИНГА:")
        logger.info(f"  Спарсено: {results['parsed']}")
        logger.info(f"  Сохранено: {results['saved']}")
        logger.info(f"  Ошибок: {len(results['errors'])}")
        
        if results['errors']:
            logger.warning("Ошибки:")
            for error in results['errors']:
                logger.warning(f"  - {error}")
        
        logger.info("=" * 60)
        
        return 0 if results['saved'] > 0 else 1
        
    except KeyboardInterrupt:
        logger.info("\n⚠️ Парсинг прерван пользователем")
        return 1
    except Exception as e:
        logger.error(f"❌ Критическая ошибка: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit(main())

