import logging
from typing import List
from datetime import datetime
from models.entities import Vulnerability
from services.osv_parser import OSVParser
from services.data_manager import DataManager

logger = logging.getLogger(__name__)


class ParserService:
    def __init__(self):
        self.parser = OSVParser()
        self.data_manager = DataManager()
        self.logger = logging.getLogger(__name__)
        self.last_run = None
        self.total_parsed = 0

    def parse_and_save_vulnerabilities(self) -> int:
        """Парсинг и сохранение уязвимостей в БД"""
        try:
            self.logger.info("Запуск парсера уязвимостей")
            self.last_run = datetime.now()

            # Парсим уязвимости
            vulnerabilities = self.parser.parse_vulnerabilities()
            self.logger.info(f"Найдено {len(vulnerabilities)} уязвимостей")

            # Сохраняем в БД
            saved_count = 0
            for vuln in vulnerabilities:
                if self.data_manager.add_vulnerability(vuln):
                    saved_count += 1

            self.total_parsed += saved_count
            self.logger.info(f"Сохранено {saved_count} уязвимостей в БД")
            return saved_count

        except Exception as e:
            self.logger.error(f"Ошибка при парсинге и сохранении уязвимостей: {e}")
            return 0

    def get_parsing_status(self) -> dict:
        """Получить статус парсинга"""
        try:
            parser_status = self.parser.get_parsing_status()
            total_vulnerabilities = self.data_manager.get_vulnerabilities_count()

            status = {
                'status': 'ready',
                'base_url': parser_status.get('base_url', 'https://osv.dev/list'),
                'max_pages': parser_status.get('max_pages', 3),
                'keywords_count': parser_status.get('keywords_count', 0),
                'total_in_system': total_vulnerabilities,
                'system_status': 'operational',
                'last_updated': self.last_run.strftime('%Y-%m-%d %H:%M:%S') if self.last_run else None,
                'total_processed': self.total_parsed,
                'last_run_count': self.total_parsed
            }
            return status

        except Exception as e:
            self.logger.error(f"Ошибка получения статуса парсинга: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'system_status': 'error',
                'total_in_system': self.data_manager.get_vulnerabilities_count(),
                'base_url': 'https://osv.dev/list',
                'max_pages': 3,
                'keywords_count': 0,
                'total_processed': self.total_parsed
            }