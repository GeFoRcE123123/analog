#!/usr/bin/env python3
"""
Скрипт для полной синхронизации всех CVE с cve.org (~380,000 CVE)
Запускается вручную для первичной загрузки
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
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/full_cve_sync.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)


def main():
    """Основная функция полной синхронизации"""
    try:
        logger.info("=" * 80)
        logger.info("🚀 Начало ПОЛНОЙ синхронизации CVE с cve.org (~380,000 CVE)")
        logger.info("⚠️  Это может занять несколько часов!")
        logger.info("=" * 80)
        
        # Инициализация БД
        db_manager = DatabaseManager()
        if Config.USE_LEGACY_SCHEMA:
            vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        else:
            from models.postgres_repositories import PostgresVulnerabilityRepository
            vuln_repo = PostgresVulnerabilityRepository(db_manager.connection)
        
        # Инициализация CVE.org сервиса с callback для обновления прогресса
        def progress_callback(progress_data):
            """Callback для обновления прогресса"""
            batch = progress_data.get('batch', 0)
            total_batches = progress_data.get('total_batches', 0)
            total_saved = progress_data.get('total_saved', 0)
            total_cves = progress_data.get('total_cves', 0)
            progress_pct = progress_data.get('progress_percent', 0)
            logger.info(f"📊 Прогресс: Пакет {batch}/{total_batches} | Сохранено: {total_saved}/{total_cves} ({progress_pct:.1f}%)")
        
        cve_org_service = CVEOrgIntegrationService(
            vuln_repo, 
            storage_path="/tmp/cve_data",
            progress_callback=progress_callback
        )
        
        # Запуск полной синхронизации
        logger.info("🔄 Запуск полной синхронизации всех CVE...")
        stats = cve_org_service.sync_all_cves()
        
        logger.info("=" * 80)
        logger.info("✅ Полная синхронизация завершена")
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

