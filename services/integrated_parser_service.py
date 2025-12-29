"""
Интегрированный сервис парсинга с автоматической адаптацией данных
и пакетным сохранением в унифицированную схему БД
"""

import logging
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from services.universal_adapter import universal_adapter, UnifiedVulnerability
from services.unified_db_manager import unified_db_manager
from services.nvd_parser import MultiThreadedNVDParser
from services.fast_osv_parser import FastOSVParser
from services.redhat_cve_importer import RedHatCVEImporter

logger = logging.getLogger(__name__)


class IntegratedParserService:
    """
    Интегрированный сервис для парсинга уязвимостей из всех источников
    с автоматической адаптацией к унифицированной схеме БД
    """
    
    def __init__(self):
        self.nvd_parser = None
        self.osv_parser = None
        self.redhat_importer = None
        self.batch_size = 100  # Размер пакета для вставки
        
        # Rate limiting для OSV
        self.osv_request_delay = 3.0  # Секунды между запросами
        self.osv_max_workers = 2  # Максимум параллельных потоков для OSV
    
    def parse_all_sources(self, sources: Optional[List[str]] = None, limit_per_source: int = 100) -> Dict[str, Any]:
        """
        Парсинг из всех источников с автоматической адаптацией
        
        Args:
            sources: Список источников ['nvd', 'osv', 'redhat'], None = все
            limit_per_source: Лимит уязвимостей с каждого источника
        
        Returns:
            Статистика парсинга
        """
        if sources is None:
            sources = ['nvd', 'osv', 'redhat']
        
        results = {
            'total_parsed': 0,
            'total_saved': 0,
            'by_source': {},
            'errors': []
        }
        
        logger.info(f"🚀 Начало парсинга из источников: {sources}")
        
        # Парсим каждый источник
        for source in sources:
            try:
                logger.info(f"📥 Парсинг из {source.upper()}...")
                
                if source.lower() == 'nvd':
                    source_results = self._parse_nvd(limit=limit_per_source)
                elif source.lower() == 'osv':
                    source_results = self._parse_osv(limit=limit_per_source)
                elif source.lower() == 'redhat':
                    source_results = self._parse_redhat(limit=limit_per_source)
                else:
                    logger.warning(f"⚠️ Неизвестный источник: {source}")
                    continue
                
                results['by_source'][source] = source_results
                results['total_parsed'] += source_results['parsed']
                results['total_saved'] += source_results['saved']
                
                logger.info(f"✅ {source.upper()}: parsed={source_results['parsed']}, saved={source_results['saved']}")
                
            except Exception as e:
                error_msg = f"Ошибка парсинга {source}: {e}"
                logger.error(f"❌ {error_msg}")
                results['errors'].append(error_msg)
        
        # Общая статистика
        logger.info(f"""
        ═══════════════════════════════════════════════
        ИТОГОВАЯ СТАТИСТИКА ПАРСИНГА
        ═══════════════════════════════════════════════
        Всего распарсено: {results['total_parsed']}
        Успешно сохранено: {results['total_saved']}
        Ошибок: {len(results['errors'])}
        ═══════════════════════════════════════════════
        """)
        
        return results
    
    def _parse_nvd(self, limit: int = 100) -> Dict[str, int]:
        """Парсинг из NVD с адаптацией"""
        try:
            # Инициализируем NVD парсер с максимальными настройками для полной синхронизации
            if not self.nvd_parser:
                from config import Config
                api_key = Config.NVD_API_KEY if Config.NVD_API_KEY else None
                requests_per_sec = Config.NVD_FULL_SYNC_REQUESTS_PER_SECOND if api_key else 5
                max_workers = Config.NVD_FULL_SYNC_MAX_WORKERS if api_key else 10
                self.nvd_parser = MultiThreadedNVDParser(
                    api_key=api_key,
                    max_workers=max_workers,
                    requests_per_second=requests_per_sec
                )
            
            # Получаем последние уязвимости
            logger.info("📡 Загрузка данных из NVD API...")
            all_vulns, ai_vulns = self.nvd_parser.get_recent_vulnerabilities(days=30)
            
            # Ограничиваем количество
            vulns_to_process = all_vulns[:limit]
            
            logger.info(f"📊 Получено {len(vulns_to_process)} уязвимостей из NVD")
            
            # Адаптируем к унифицированной структуре
            unified_vulns = []
            for nvd_vuln in vulns_to_process:
                try:
                    # Конвертируем в словарь
                    nvd_dict = nvd_vuln.to_dict() if hasattr(nvd_vuln, 'to_dict') else nvd_vuln.__dict__
                    
                    # Адаптируем
                    unified_vuln = universal_adapter.adapt_nvd_data(nvd_dict)
                    unified_vulns.append(unified_vuln)
                    
                except Exception as e:
                    logger.error(f"Ошибка адаптации NVD уязвимости: {e}")
                    continue
            
            # Сохраняем пакетно
            saved_count = self._batch_save(unified_vulns)
            
            return {
                'parsed': len(vulns_to_process),
                'saved': saved_count
            }
            
        except Exception as e:
            logger.error(f"Критическая ошибка парсинга NVD: {e}")
            return {'parsed': 0, 'saved': 0}
    
    def _parse_osv(self, limit: int = 100) -> Dict[str, int]:
        """Парсинг из OSV с адаптацией и rate limiting"""
        try:
            # Инициализируем OSV парсер с ограничениями
            if not self.osv_parser:
                self.osv_parser = FastOSVParser(
                    max_workers=self.osv_max_workers,  # Только 2 потока
                    max_pages=3  # Ограничиваем количество страниц
                )
            
            logger.info("📡 Загрузка данных из OSV (с rate limiting)...")
            
            # Получаем ссылки
            links = self.osv_parser._get_all_vulnerability_links()
            links = links[:limit]  # Ограничиваем
            
            logger.info(f"📊 Найдено {len(links)} ссылок из OSV")
            
            # Парсим уязвимости с ограничением скорости
            osv_data = self.osv_parser._parse_all_vulnerabilities(links)
            
            logger.info(f"✅ Успешно распарсено {len(osv_data)} уязвимостей")
            
            # Адаптируем к унифицированной структуре
            unified_vulns = []
            for osv_vuln in osv_data:
                try:
                    unified_vuln = universal_adapter.adapt_osv_data(osv_vuln)
                    unified_vulns.append(unified_vuln)
                except Exception as e:
                    logger.error(f"Ошибка адаптации OSV уязвимости: {e}")
                    continue
            
            # Сохраняем пакетно
            saved_count = self._batch_save(unified_vulns)
            
            return {
                'parsed': len(osv_data),
                'saved': saved_count
            }
            
        except Exception as e:
            logger.error(f"Критическая ошибка парсинга OSV: {e}")
            return {'parsed': 0, 'saved': 0}
    
    def _parse_redhat(self, limit: int = 100) -> Dict[str, int]:
        """Парсинг из RedHat с адаптацией"""
        try:
            # Инициализируем RedHat импортер
            if not self.redhat_importer:
                self.redhat_importer = RedHatCVEImporter()
            
            logger.info("📡 Загрузка данных из RedHat API...")
            
            # Получаем CVE
            redhat_cves = self.redhat_importer.fetch_cves(page=1, per_page=limit)
            
            logger.info(f"📊 Получено {len(redhat_cves)} CVE из RedHat")
            
            # Адаптируем к унифицированной структуре
            unified_vulns = []
            for redhat_cve in redhat_cves:
                try:
                    # Преобразуем в NVD-совместимый формат
                    nvd_format = self.redhat_importer.transform_redhat_to_nvd_format(redhat_cve)
                    
                    if nvd_format:
                        # Адаптируем через RedHat адаптер
                        unified_vuln = universal_adapter.adapt_redhat_data(nvd_format)
                        unified_vulns.append(unified_vuln)
                        
                except Exception as e:
                    logger.error(f"Ошибка адаптации RedHat CVE: {e}")
                    continue
            
            # Сохраняем пакетно
            saved_count = self._batch_save(unified_vulns)
            
            return {
                'parsed': len(redhat_cves),
                'saved': saved_count
            }
            
        except Exception as e:
            logger.error(f"Критическая ошибка парсинга RedHat: {e}")
            return {'parsed': 0, 'saved': 0}
    
    def _batch_save(self, vulnerabilities: List[UnifiedVulnerability]) -> int:
        """Пакетное сохранение уязвимостей"""
        if not vulnerabilities:
            return 0
        
        try:
            logger.info(f"💾 Сохранение {len(vulnerabilities)} уязвимостей пакетами по {self.batch_size}...")
            
            total_saved = 0
            
            # Разбиваем на пакеты
            for i in range(0, len(vulnerabilities), self.batch_size):
                batch = vulnerabilities[i:i + self.batch_size]
                
                # Сохраняем пакет
                saved = unified_db_manager.insert_vulnerability_batch(batch)
                total_saved += saved
                
                logger.info(f"📦 Пакет {i // self.batch_size + 1}: сохранено {saved} записей")
            
            logger.info(f"✅ Всего сохранено: {total_saved} уязвимостей")
            return total_saved
            
        except Exception as e:
            logger.error(f"❌ Ошибка пакетного сохранения: {e}")
            return 0
    
    def parse_ai_vulnerabilities_only(self) -> Dict[str, Any]:
        """Парсинг только AI-уязвимостей из всех источников"""
        logger.info("🤖 Парсинг AI-уязвимостей...")
        
        results = {
            'total_parsed': 0,
            'total_saved': 0,
            'by_source': {}
        }
        
        # NVD AI уязвимости
        try:
            if not self.nvd_parser:
                from config import Config
                api_key = Config.NVD_API_KEY if Config.NVD_API_KEY else None
                requests_per_sec = Config.NVD_FULL_SYNC_REQUESTS_PER_SECOND if api_key else 5
                max_workers = Config.NVD_FULL_SYNC_MAX_WORKERS if api_key else 10
                self.nvd_parser = MultiThreadedNVDParser(
                    api_key=api_key,
                    max_workers=max_workers,
                    requests_per_second=requests_per_sec
                )
            
            all_vulns, ai_vulns = self.nvd_parser.get_recent_vulnerabilities(days=60)
            
            # Адаптируем только AI уязвимости
            unified_ai_vulns = []
            for nvd_vuln in ai_vulns:
                try:
                    nvd_dict = nvd_vuln.to_dict() if hasattr(nvd_vuln, 'to_dict') else nvd_vuln.__dict__
                    unified_vuln = universal_adapter.adapt_nvd_data(nvd_dict)
                    unified_ai_vulns.append(unified_vuln)
                except Exception as e:
                    logger.error(f"Ошибка адаптации AI уязвимости NVD: {e}")
            
            saved = self._batch_save(unified_ai_vulns)
            results['by_source']['nvd'] = {'parsed': len(ai_vulns), 'saved': saved}
            results['total_parsed'] += len(ai_vulns)
            results['total_saved'] += saved
            
        except Exception as e:
            logger.error(f"Ошибка парсинга AI из NVD: {e}")
        
        # OSV AI уязвимости
        try:
            if not self.osv_parser:
                self.osv_parser = FastOSVParser(max_workers=10, max_pages=10)
            
            links = self.osv_parser._get_all_vulnerability_links()
            osv_data = self.osv_parser._parse_all_vulnerabilities(links)
            
            # Фильтруем AI уязвимости
            ai_osv_data = self.osv_parser._filter_by_ai_keywords(osv_data)
            
            # Адаптируем
            unified_ai_vulns = []
            for osv_vuln in ai_osv_data:
                try:
                    unified_vuln = universal_adapter.adapt_osv_data(osv_vuln)
                    unified_ai_vulns.append(unified_vuln)
                except Exception as e:
                    logger.error(f"Ошибка адаптации AI уязвимости OSV: {e}")
            
            saved = self._batch_save(unified_ai_vulns)
            results['by_source']['osv'] = {'parsed': len(ai_osv_data), 'saved': saved}
            results['total_parsed'] += len(ai_osv_data)
            results['total_saved'] += saved
            
        except Exception as e:
            logger.error(f"Ошибка парсинга AI из OSV: {e}")
        
        logger.info(f"""
        🤖 AI УЯЗВИМОСТИ: Найдено {results['total_parsed']}, Сохранено {results['total_saved']}
        """)
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Получение статистики из БД"""
        return unified_db_manager.get_statistics()


# Глобальный экземпляр
integrated_parser = IntegratedParserService()
