import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import asdict
import time

from services.nvd_parser import MultiThreadedNVDParser
from models.entities import NVDVulnerability
from models.repositories import VulnerabilityRepository


class NVDIntegrationService:
    """
    Сервис интеграции с NVD API для управления процессом парсинга,
    сохранения и синхронизации уязвимостей
    """

    def __init__(self, vulnerability_repo: VulnerabilityRepository, api_key: str = None):
        self.parser = MultiThreadedNVDParser(api_key=api_key)
        self.vulnerability_repo = vulnerability_repo
        self.logger = logging.getLogger(__name__)

        # Конфигурация интеграции
        self.config = {
            'max_retries': 3,
            'retry_delay': 60,  # секунды
            'batch_size': 100,
            'sync_interval_hours': 24
        }

    def full_sync(self) -> Dict:
        """
        Полная синхронизация всех уязвимостей из NVD
        Возвращает: Статистика выполнения
        """
        self.logger.info("Запуск полной синхронизации с NVD")
        print("=== ЗАПУСК ПОЛНОЙ СИНХРОНИЗАЦИИ С NVD ===")

        start_time = datetime.now()
        stats = {
            'operation': 'full_sync',
            'start_time': start_time,
            'total_processed': 0,
            'ai_vulnerabilities': 0,
            'errors': 0,
            'status': 'running'
        }

        try:
            # Получаем все уязвимости
            all_vulnerabilities, ai_vulnerabilities = self.parser.get_all_vulnerabilities()

            if not all_vulnerabilities:
                stats.update({
                    'status': 'error',
                    'message': 'Не удалось получить уязвимости из NVD'
                })
                return stats

            # Сохраняем пачками
            saved_count = self._save_in_batches(all_vulnerabilities)

            # Формируем отчет
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            stats.update({
                'status': 'completed',
                'end_time': end_time,
                'duration_seconds': duration,
                'total_parsed': len(all_vulnerabilities),
                'ai_vulnerabilities': len(ai_vulnerabilities),
                'saved_count': saved_count,
                'message': f'Полная синхронизация завершена за {duration:.2f} секунд'
            })

            self._print_sync_report(stats)
            return stats

        except Exception as e:
            error_msg = f"Ошибка полной синхронизации: {e}"
            self.logger.error(error_msg)
            stats.update({
                'status': 'error',
                'message': error_msg,
                'end_time': datetime.now()
            })
            return stats

    def incremental_sync(self, days: int = 1) -> Dict:
        """
        Инкрементальная синхронизация за последние N дней
        """
        self.logger.info(f"Запуск инкрементальной синхронизации за {days} дней")
        print(f"=== ИНКРЕМЕНТАЛЬНАЯ СИНХРОНИЗАЦИЯ ЗА {days} ДНЕЙ ===")

        start_time = datetime.now()
        stats = {
            'operation': 'incremental_sync',
            'days': days,
            'start_time': start_time,
            'total_processed': 0,
            'ai_vulnerabilities': 0,
            'errors': 0,
            'status': 'running'
        }

        try:
            # Получаем уязвимости за период
            all_vulnerabilities, ai_vulnerabilities = self.parser.get_recent_vulnerabilities(days)

            if not all_vulnerabilities:
                stats.update({
                    'status': 'completed',
                    'message': 'Новых уязвимостей не найдено'
                })
                return stats

            # Сохраняем пачками
            saved_count = self._save_in_batches(all_vulnerabilities)

            # Формируем отчет
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            stats.update({
                'status': 'completed',
                'end_time': end_time,
                'duration_seconds': duration,
                'total_parsed': len(all_vulnerabilities),
                'ai_vulnerabilities': len(ai_vulnerabilities),
                'saved_count': saved_count,
                'message': f'Инкрементальная синхронизация завершена за {duration:.2f} секунд'
            })

            self._print_sync_report(stats)
            return stats

        except Exception as e:
            error_msg = f"Ошибка инкрементальной синхронизации: {e}"
            self.logger.error(error_msg)
            stats.update({
                'status': 'error',
                'message': error_msg,
                'end_time': datetime.now()
            })
            return stats

    def sync_ai_vulnerabilities(self) -> Dict:
        """
        Специальная синхронизация только AI-уязвимостей
        """
        self.logger.info("Запуск синхронизации AI уязвимостей")
        print("=== СИНХРОНИЗАЦИЯ AI УЯЗВИМОСТЕЙ ===")

        start_time = datetime.now()

        try:
            # Получаем все уязвимости
            all_vulnerabilities, ai_vulnerabilities = self.parser.get_all_vulnerabilities()

            if not ai_vulnerabilities:
                return {
                    'operation': 'ai_sync',
                    'status': 'completed',
                    'message': 'AI уязвимостей не найдено',
                    'total_processed': 0,
                    'start_time': start_time,
                    'end_time': datetime.now()
                }

            # Сохраняем только AI уязвимости
            saved_count = self._save_in_batches(ai_vulnerabilities)

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            stats = {
                'operation': 'ai_sync',
                'status': 'completed',
                'start_time': start_time,
                'end_time': end_time,
                'duration_seconds': duration,
                'total_parsed': len(ai_vulnerabilities),
                'saved_count': saved_count,
                'message': f'Синхронизация AI уязвимостей завершена за {duration:.2f} секунд'
            }

            self._print_sync_report(stats)
            return stats

        except Exception as e:
            error_msg = f"Ошибка синхронизации AI уязвимостей: {e}"
            self.logger.error(error_msg)
            return {
                'operation': 'ai_sync',
                'status': 'error',
                'message': error_msg,
                'start_time': start_time,
                'end_time': datetime.now()
            }

    def _save_in_batches(self, vulnerabilities: List[NVDVulnerability]) -> int:
        """Сохранение уязвимостей пачками"""
        total_saved = 0
        batch_size = self.config['batch_size']

        for i in range(0, len(vulnerabilities), batch_size):
            batch = vulnerabilities[i:i + batch_size]
            batch_saved = 0

            for attempt in range(self.config['max_retries']):
                try:
                    # Конвертируем в словари для сохранения
                    vuln_dicts = [asdict(vuln) for vuln in batch]

                    # РЕАЛЬНЫЙ ВЫЗОВ вместо заглушки
                    batch_saved = self.vulnerability_repo.bulk_save_nvd_vulnerabilities(vuln_dicts)
                    break

                except Exception as e:
                    self.logger.warning(f"Попытка {attempt + 1} сохранения пачки не удалась: {e}")
                    if attempt < self.config['max_retries'] - 1:
                        time.sleep(self.config['retry_delay'])
                    else:
                        self.logger.error(f"Не удалось сохранить пачку после {self.config['max_retries']} попыток")

            total_saved += batch_saved
            print(f"Сохранено пачка: {batch_saved}/{len(batch)} уязвимостей")

        return total_saved

    def _print_sync_report(self, stats: Dict):
        """Печать отчета о синхронизации"""
        print(f"\n=== ОТЧЕТ СИНХРОНИЗАЦИИ ===")
        print(f"Операция: {stats['operation']}")
        print(f"Статус: {stats['status']}")
        print(f"Время выполнения: {stats.get('duration_seconds', 0):.2f} сек")
        print(f"Всего обработано: {stats.get('total_parsed', 0)}")
        print(f"AI уязвимостей: {stats.get('ai_vulnerabilities', 0)}")
        print(f"Сохранено в БД: {stats.get('saved_count', 0)}")
        print(f"Сообщение: {stats.get('message', '')}")
        print("=" * 40)

    def get_sync_status(self) -> Dict:
        """Получение статуса последней синхронизации"""
        # Здесь можно добавить логику получения статуса из БД
        return {
            'service': 'nvd_integration',
            'status': 'active',
            'last_sync': None,  # Будет из БД
            'next_sync': None  # Будет из БД
        }

    def validate_connection(self) -> Dict:
        """Проверка подключения к NVD API"""
        try:
            test_params = {'resultsPerPage': 1}
            data = self.parser._make_request(test_params)

            if data:
                return {
                    'status': 'success',
                    'message': 'Подключение к NVD API успешно'
                }
            else:
                return {
                    'status': 'error',
                    'message': 'Не удалось подключиться к NVD API'
                }

        except Exception as e:
            return {
                'status': 'error',
                'message': f'Ошибка подключения: {e}'
            }