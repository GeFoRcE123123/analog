#!/usr/bin/env python3
"""
Скрипт запуска парсеров на VM 10.0.88.23
"""
import logging
import time
import signal
import sys
from datetime import datetime

# Импорты парсеров
import sys
import os

# Добавляем путь к корню проекта для импортов
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from services.parsing_manager import AsyncParser, ParsingProgressManager
from services.nvd_integration_service import NVDIntegrationService
from services.nvd_scheduler import NVDScheduler
from services.redhat_cve_importer import RedHatCVEImporter
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config

# Настройка логирования
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/parsers.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

# Глобальные переменные для graceful shutdown
running = True
parsers = {}


def signal_handler(sig, frame):
    """Обработчик сигналов для graceful shutdown"""
    global running
    logger.info("Получен сигнал остановки, завершаем работу...")
    running = False
    
    # Останавливаем планировщик
    if 'scheduler' in parsers:
        parsers['scheduler'].stop()
    
    sys.exit(0)


def main():
    """Основная функция запуска парсеров"""
    global running, parsers
    
    logger.info("=" * 60)
    logger.info("Запуск сервиса парсеров (VM: 10.0.88.23)")
    logger.info(f"Database: {Config.DATABASE_CONFIG.host}:{Config.DATABASE_CONFIG.port}")
    logger.info("=" * 60)
    
    # Регистрируем обработчики сигналов
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Инициализация подключения к БД
        db_manager = DatabaseManager()
        db_manager.configure(
            host=Config.DATABASE_CONFIG.host,
            port=Config.DATABASE_CONFIG.port,
            database=Config.DATABASE_CONFIG.database,
            username=Config.DATABASE_CONFIG.username,
            password=Config.DATABASE_CONFIG.password
        )
        
        if not db_manager.connect():
            logger.error("Не удалось подключиться к базе данных")
            sys.exit(1)
        
        logger.info("✅ Подключение к базе данных установлено")
        
        # Создаем репозиторий
        if Config.USE_LEGACY_SCHEMA:
            vulnerability_repo = LegacyVulnerabilityRepository(db_manager.connection)
            logger.info("Используется legacy схема БД")
        else:
            from models.postgres_repositories import PostgresVulnerabilityRepository
            vulnerability_repo = PostgresVulnerabilityRepository(db_manager.connection)
            logger.info("Используется modern схема БД")
        
        # Инициализация парсеров
        logger.info("Инициализация парсеров...")
        
        # NVD Integration Service
        # Используем API ключ из конфигурации
        api_key = Config.NVD_API_KEY if Config.NVD_API_KEY else None
        nvd_integration = NVDIntegrationService(vulnerability_repo, api_key=api_key)
        parsers['nvd'] = nvd_integration
        
        # NVD Scheduler
        scheduler = NVDScheduler(nvd_integration)
        parsers['scheduler'] = scheduler
        
        # RedHat Importer
        redhat_importer = RedHatCVEImporter()
        parsers['redhat'] = redhat_importer
        
        # Async Parser
        async_parser = AsyncParser()
        parsers['async'] = async_parser
        
        logger.info("✅ Все парсеры инициализированы")
        
        # Запускаем планировщик (ежечасная синхронизация)
        logger.info("Запуск планировщика NVD (ежечасная синхронизация)...")
        scheduler.start_hourly_sync()
        scheduler.start()
        
        logger.info("=" * 60)
        logger.info("Сервис парсеров запущен и работает")
        logger.info("Планировщик: активен (ежечасная синхронизация)")
        logger.info("Для остановки нажмите Ctrl+C")
        logger.info("=" * 60)
        
        # Основной цикл
        while running:
            time.sleep(60)  # Проверяем каждую минуту
            
            # Проверяем состояние подключения к БД
            if not db_manager.is_connected():
                logger.warning("Потеряно подключение к БД, переподключаемся...")
                if not db_manager.reconnect():
                    logger.error("Не удалось переподключиться к БД")
                    break
        
    except KeyboardInterrupt:
        logger.info("Получен сигнал прерывания")
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}", exc_info=True)
    finally:
        logger.info("Завершение работы сервиса парсеров...")
        if 'scheduler' in parsers:
            parsers['scheduler'].stop()
        if db_manager:
            db_manager.disconnect()
        logger.info("Сервис парсеров остановлен")


if __name__ == "__main__":
    main()

