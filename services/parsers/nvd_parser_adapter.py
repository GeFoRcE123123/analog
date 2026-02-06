"""
Адаптер NVD парсера к новой архитектуре
Использует существующий MultiThreadedNVDParser, но оборачивает его в BaseParser
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from .base_parser import BaseParser, ParserStatus
from .normalizer import normalizer
from .ai_analyzer import ai_analyzer
from ..nvd_parser import MultiThreadedNVDParser


logger = logging.getLogger(__name__)


class NVDParserAdapter(BaseParser):
    """
    Адаптер для NVD парсера с использованием новой архитектуры
    """
    
    def __init__(self, api_key: Optional[str] = None, config: Optional[Dict[str, Any]] = None):
        super().__init__('nvd', config)
        self.api_key = api_key
        # Инициализация оригинального парсера
        self.parser = MultiThreadedNVDParser(
            api_key=api_key,
            max_workers=self.config.get('max_workers', 10),
            requests_per_second=self.config.get('requests_per_second', 5)
        )
    
    def get_source_info(self) -> Dict[str, Any]:
        """Информация об источнике NVD"""
        return {
            'name': 'NVD (National Vulnerability Database)',
            'type': 'api',
            'url': 'https://nvd.nist.gov/',
            'description': 'Официальная база данных уязвимостей NIST',
            'rate_limit': '5 requests/second (без API ключа), 50 requests/second (с API ключом)',
            'authentication': 'Опционально (API ключ)',
            'formats': ['JSON API 2.0']
        }
    
    def parse(
        self,
        days: Optional[int] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: Optional[int] = None,
        full_sync: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Парсинг уязвимостей из NVD
        
        Args:
            days: Количество дней назад для инкрементального парсинга
            start_date: Начальная дата
            end_date: Конечная дата
            limit: Максимальное количество уязвимостей
            full_sync: Полная синхронизация всех уязвимостей
            
        Returns:
            Список нормализованных уязвимостей
        """
        self.start()
        normalized_vulnerabilities = []
        
        try:
            # Определение параметров парсинга
            if full_sync:
                self.logger.info("Запуск полной синхронизации NVD")
                all_vulns, ai_vulns = self.parser.get_all_vulnerabilities()
                raw_vulnerabilities = all_vulns
            elif days:
                self.logger.info(f"Инкрементальная синхронизация за последние {days} дней")
                end_date = datetime.now()
                start_date = end_date - timedelta(days=days)
                raw_vulnerabilities = self.parser.get_vulnerabilities_by_date_range(
                    start_date=start_date,
                    end_date=end_date
                )
            elif start_date and end_date:
                self.logger.info(f"Парсинг за период {start_date} - {end_date}")
                raw_vulnerabilities = self.parser.get_vulnerabilities_by_date_range(
                    start_date=start_date,
                    end_date=end_date
                )
            else:
                # По умолчанию: последние 7 дней
                end_date = datetime.now()
                start_date = end_date - timedelta(days=7)
                raw_vulnerabilities = self.parser.get_vulnerabilities_by_date_range(
                    start_date=start_date,
                    end_date=end_date
                )
            
            if not raw_vulnerabilities:
                self.logger.warning("Не получено уязвимостей из NVD")
                return []
            
            total_count = len(raw_vulnerabilities)
            self.update_progress(0, total_count, f"Начало обработки {total_count} уязвимостей")
            
            # Нормализация и обработка каждой уязвимости
            for idx, raw_vuln in enumerate(raw_vulnerabilities):
                if self.status == ParserStatus.PAUSED:
                    self.logger.info("Парсинг приостановлен")
                    break
                
                if self.status != ParserStatus.RUNNING:
                    break
                
                try:
                    # Преобразование NVDVulnerability в словарь
                    if hasattr(raw_vuln, '__dict__'):
                        vuln_dict = raw_vuln.__dict__
                    elif hasattr(raw_vuln, '_asdict'):
                        vuln_dict = raw_vuln._asdict()
                    else:
                        vuln_dict = raw_vuln
                    
                    # Нормализация
                    normalized = normalizer.normalize_vulnerability(vuln_dict, source='nvd')
                    
                    # AI анализ
                    ai_result = ai_analyzer.analyze_all(vuln_dict)
                    
                    # Добавление AI данных
                    normalized_dict = {
                        'cve_id': normalized.cve_id,
                        'title': normalized.title,
                        'description': normalized.description,
                        'severity': normalized.severity,
                        'cvss_score': normalized.cvss_score,
                        'cvss_version': normalized.cvss_version,
                        'cvss_vector': normalized.cvss_vector,
                        'cwe_ids': normalized.cwe_ids,
                        'cpe_list': normalized.cpe_list,
                        'affected_products': normalized.affected_products,
                        'references': normalized.references,
                        'published_date': normalized.published_date.isoformat() if normalized.published_date else None,
                        'last_modified': normalized.last_modified.isoformat() if normalized.last_modified else None,
                        'source': normalized.source,
                        'source_id': normalized.source_id,
                        'status': normalized.status,
                        'tags': normalized.tags,
                        'is_ai_related': ai_result['ai_classification']['is_ai_related'],
                        'ai_confidence': ai_result['ai_classification']['confidence'],
                        'ai_categories': ai_result['ai_classification']['categories'],
                        'has_exploit': normalized.has_exploit,
                        'has_poc': normalized.has_poc,
                        'epss_score': normalized.epss_score,
                        'kev_status': normalized.kev_status,
                        'owasp_categories': ai_result['owasp_classification'],
                        'zero_day_potential': ai_result['zero_day_assessment'],
                        'metadata': normalized.metadata
                    }
                    
                    normalized_vulnerabilities.append(normalized_dict)
                    self.stats['total_parsed'] += 1
                    
                    # Обновление прогресса
                    if (idx + 1) % 100 == 0 or idx == total_count - 1:
                        self.update_progress(
                            idx + 1,
                            total_count,
                            f"Обработано {idx + 1}/{total_count} уязвимостей",
                            normalized.cve_id
                        )
                
                except Exception as e:
                    self.logger.error(f"Ошибка обработки уязвимости {idx + 1}: {e}", exc_info=True)
                    self.stats['errors'] += 1
                    continue
            
            # Применение лимита
            if limit and len(normalized_vulnerabilities) > limit:
                normalized_vulnerabilities = normalized_vulnerabilities[:limit]
            
            self.stats['total_parsed'] = len(normalized_vulnerabilities)
            self.status = ParserStatus.COMPLETED
            self.logger.info(f"Успешно обработано {len(normalized_vulnerabilities)} уязвимостей из NVD")
            
        except Exception as e:
            self.logger.error(f"Критическая ошибка парсинга NVD: {e}", exc_info=True)
            self.status = ParserStatus.ERROR
            self.stats['errors'] += 1
        
        finally:
            self.stop()
        
        return normalized_vulnerabilities
    
    def incremental_sync(self, days: int = 1) -> List[Dict[str, Any]]:
        """Инкрементальная синхронизация за последние N дней"""
        return self.parse(days=days)
    
    def full_sync(self) -> List[Dict[str, Any]]:
        """Полная синхронизация всех уязвимостей"""
        return self.parse(full_sync=True)

