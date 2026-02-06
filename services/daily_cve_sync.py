#!/usr/bin/env python3
"""
Скрипт для ежедневного автоматического скачивания всех CVE с cve.org
Запускается через cron или systemd timer
"""
import sys
import os
import logging
from pathlib import Path

# Добавляем путь к корню проекта
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from services.cve_org_integration_service import CVEOrgIntegrationService
from config import Config

# Настройка логирования
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/daily_cve_sync.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)


def main():
    """Основная функция ежедневной синхронизации"""
    try:
        logger.info("=" * 80)
        logger.info("🚀 Начало ежедневной синхронизации CVE с cve.org")
        logger.info("=" * 80)
        
        # Инициализация БД
        db_manager = DatabaseManager()
        if Config.USE_LEGACY_SCHEMA:
            vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        else:
            from models.postgres_repositories import PostgresVulnerabilityRepository
            vuln_repo = PostgresVulnerabilityRepository(db_manager.connection)
        
        # Инициализация CVE.org сервиса
        cve_org_service = CVEOrgIntegrationService(
            vuln_repo, 
            storage_path="/tmp/cve_data"
        )
        
        # Запуск инкрементальной синхронизации (обновляет репозиторий и обрабатывает изменения)
        logger.info("🔄 Запуск инкрементальной синхронизации...")
        stats = cve_org_service.incremental_sync(days=1)
        
        logger.info("=" * 80)
        logger.info("✅ Синхронизация завершена")
        logger.info(f"   Статус: {stats.get('status')}")
        logger.info(f"   Обработано: {stats.get('total_processed', 0)}")
        logger.info(f"   Сохранено: {stats.get('total_saved', 0)}")
        logger.info(f"   Ошибки: {stats.get('total_errors', 0)}")
        logger.info("=" * 80)
        
        return 0
        
    except Exception as e:
        logger.error(f"❌ Критическая ошибка синхронизации: {e}", exc_info=True)
        return 1
    finally:
        # Закрываем соединение с БД
        try:
            db_manager.disconnect()
        except:
            pass


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)

