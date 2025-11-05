import schedule
import time
import threading
import logging
from services.nvd_integration_service import NVDIntegrationService


class NVDScheduler:
    """
    Планировщик для автоматической синхронизации с NVD
    """

    def __init__(self, integration_service: NVDIntegrationService):
        self.integration_service = integration_service
        self.logger = logging.getLogger(__name__)
        self.is_running = False
        self.scheduler_thread = None

    def start_daily_sync(self, hour: int = 2, minute: int = 0):
        """Запуск ежедневной синхронизации"""
        schedule.every().day.at(f"{hour:02d}:{minute:02d}").do(
            self._run_daily_sync
        )
        self.logger.info(f"Ежедневная синхронизация запланирована на {hour:02d}:{minute:02d}")

    def start_hourly_sync(self):
        """Запуск ежечасной инкрементальной синхронизации"""
        schedule.every().hour.do(self._run_incremental_sync)
        self.logger.info("Инкрементальная синхронизация запланирована каждый час")

    def start(self):
        """Запуск планировщика"""
        self.is_running = True
        self.scheduler_thread = threading.Thread(target=self._run_scheduler)
        self.scheduler_thread.daemon = True
        self.scheduler_thread.start()
        self.logger.info("Планировщик NVD синхронизации запущен")

    def stop(self):
        """Остановка планировщика"""
        self.is_running = False
        self.logger.info("Планировщик NVD синхронизации остановлен")

    def _run_scheduler(self):
        """Основной цикл планировщика"""
        while self.is_running:
            schedule.run_pending()
            time.sleep(60)  # Проверяем каждую минуту

    def _run_daily_sync(self):
        """Выполнение ежедневной синхронизации"""
        self.logger.info("Запуск ежедневной синхронизации")
        try:
            result = self.integration_service.incremental_sync(days=1)
            self.logger.info(f"Ежедневная синхронизация завершена: {result}")
        except Exception as e:
            self.logger.error(f"Ошибка ежедневной синхронизации: {e}")

    def _run_incremental_sync(self):
        """Выполнение инкрементальной синхронизации"""
        self.logger.info("Запуск инкрементальной синхронизации")
        try:
            result = self.integration_service.incremental_sync(days=1)
            self.logger.info(f"Инкрементальная синхронизация завершена: {result}")
        except Exception as e:
            self.logger.error(f"Ошибка инкрементальной синхронизации: {e}")