"""
Универсальный сервис парсинга уязвимостей
Запускает все парсеры и сохраняет данные в БД
"""
import logging
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from models.database import DatabaseManager
from models.postgres_repositories import PostgresVulnerabilityRepository
from models.legacy_repositories import LegacyVulnerabilityRepository
from models.entities import Vulnerability
from config import Config

logger = logging.getLogger(__name__)


class UnifiedParserService:
    """
    Универсальный сервис для запуска всех парсеров и сохранения данных в БД
    """
    
    def __init__(self):
        self.db_manager = DatabaseManager()
        if Config.USE_LEGACY_SCHEMA:
            self.vuln_repo = LegacyVulnerabilityRepository(self.db_manager.connection)
        else:
            self.vuln_repo = PostgresVulnerabilityRepository(self.db_manager.connection)
        
        self.logger = logging.getLogger(__name__)
        self._parsing_active = False
        self._parsing_lock = threading.Lock()
        
        # Импорт парсеров с безопасной обработкой ошибок
        self.html_parser = None
        self.vendor_parser = None
        self.redhat_importer = None
        self.nvd_service = None
        
        try:
            from services.html_vulnerability_parser import HTMLVulnerabilityParser
            self.html_parser = HTMLVulnerabilityParser()
            self.logger.info("✅ HTML парсер инициализирован")
            print(f"[INIT] ✅ HTML парсер инициализирован: {self.html_parser}")
        except Exception as e:
            error_msg = f"⚠️ HTML парсер не доступен: {e}"
            self.logger.error(error_msg, exc_info=True)
            print(f"[INIT] ❌ {error_msg}")
            import traceback
            traceback.print_exc()
            self.html_parser = None
        
        try:
            from services.universal_vendor_parser import UniversalVendorParser
            self.vendor_parser = UniversalVendorParser()
            self.logger.info("✅ Vendor парсер инициализирован")
        except Exception as e:
            self.logger.warning(f"⚠️ Vendor парсер не доступен: {e}")
            self.vendor_parser = None
        
        try:
            from services.redhat_cve_importer import RedHatCVEImporter
            self.redhat_importer = RedHatCVEImporter()
            self.logger.info("✅ RedHat importer инициализирован")
        except Exception as e:
            self.logger.warning(f"⚠️ RedHat importer не доступен: {e}")
            self.redhat_importer = None
        
        try:
            from services.nvd_integration_service import NVDIntegrationService
            # Используем API ключ из конфигурации
            api_key = Config.NVD_API_KEY if Config.NVD_API_KEY else None
            self.nvd_service = NVDIntegrationService(self.vuln_repo, api_key=api_key)
            self.logger.info("✅ NVD service инициализирован")
        except Exception as e:
            self.logger.warning(f"⚠️ NVD service не доступен: {e}")
            self.nvd_service = None
        
        try:
            from services.osv_api_parser import OSVAPIParser
            self.osv_api_parser = OSVAPIParser()
            self.logger.info("✅ OSV API парсер инициализирован")
        except Exception as e:
            self.logger.warning(f"⚠️ OSV API парсер не доступен: {e}")
            self.osv_api_parser = None
        
        # Импорт парсеров вендоров
        try:
            from services.vendor_parsers import vendor_parsers
            self.vendor_parsers = vendor_parsers
            self.logger.info("✅ Vendor парсеры инициализированы")
        except Exception as e:
            self.logger.warning(f"⚠️ Vendor парсеры не доступны: {e}")
            self.vendor_parsers = None
        
        # Инициализация CVE JSON 5.x адаптера
        try:
            from services.cve_json5_adapter import cve_json5_adapter
            from services.cve_json_loader import cve_json_loader
            self.cve_json5_adapter = cve_json5_adapter
            self.cve_json_loader = cve_json_loader
            self.logger.info("✅ CVE JSON 5.x адаптер инициализирован")
        except Exception as e:
            self.logger.warning(f"⚠️ CVE JSON 5.x адаптер не доступен: {e}")
            self.cve_json5_adapter = None
            self.cve_json_loader = None
        
        # Инициализация CVE.org интеграционного сервиса
        try:
            from services.cve_org_integration_service import CVEOrgIntegrationService
            # Используем /tmp/cve_data для хранения репозитория
            self.cve_org_service = CVEOrgIntegrationService(self.vuln_repo, storage_path="/tmp/cve_data")
            self.logger.info("✅ CVE.org интеграционный сервис инициализирован")
        except Exception as e:
            self.logger.warning(f"⚠️ CVE.org сервис не доступен: {e}")
            self.cve_org_service = None
        
        # Инициализация Legacy парсеров из папки pars/
        self.legacy_parsers = {}
        try:
            from services.legacy_parsers import (
                RedHatParser, DebianParser, CiscoParser, CertParser,
                FortiGuardParser, IBMParser, PostgreSQLParser, SUSEParser,
                PaloAltoParser, JuniperParser, CyberSecurityParser,
                CXSecurityParser, KasperskyParser, KasperskyStatParser,
                NVDKeywordsParser, ZeroDayInitiativeParser, CVEDetailsParser
            )
            
            # Инициализируем все парсеры
            self.legacy_parsers['redhat'] = RedHatParser(self.vuln_repo)
            self.legacy_parsers['debian'] = DebianParser(self.vuln_repo)
            self.legacy_parsers['cisco'] = CiscoParser(self.vuln_repo)
            self.legacy_parsers['cert'] = CertParser(self.vuln_repo)
            self.legacy_parsers['fortiguard'] = FortiGuardParser(self.vuln_repo)
            self.legacy_parsers['ibm'] = IBMParser(self.vuln_repo)
            self.legacy_parsers['postgresql'] = PostgreSQLParser(self.vuln_repo)
            self.legacy_parsers['suse'] = SUSEParser(self.vuln_repo)
            self.legacy_parsers['paloalto'] = PaloAltoParser(self.vuln_repo)
            self.legacy_parsers['juniper'] = JuniperParser(self.vuln_repo)
            self.legacy_parsers['cybersecurity'] = CyberSecurityParser(self.vuln_repo)
            self.legacy_parsers['cxsecurity'] = CXSecurityParser(self.vuln_repo)
            self.legacy_parsers['kaspersky'] = KasperskyParser(self.vuln_repo)
            self.legacy_parsers['kaspersky_stat'] = KasperskyStatParser(self.vuln_repo)
            self.legacy_parsers['nvd_keywords'] = NVDKeywordsParser(self.vuln_repo)
            self.legacy_parsers['zerodayinitiative'] = ZeroDayInitiativeParser(self.vuln_repo)
            self.legacy_parsers['cvedetails'] = CVEDetailsParser(self.vuln_repo)
            
            self.logger.info(f"✅ Legacy парсеры инициализированы: {list(self.legacy_parsers.keys())}")
        except Exception as e:
            self.logger.warning(f"⚠️ Legacy парсеры не доступны: {e}", exc_info=True)
            self.legacy_parsers = {}
    
    def parse_all(
        self,
        sources: Optional[List[str]] = None,
        limit_per_source: int = 50,
        enable_nvd: bool = False,
        enable_redhat: bool = False,
        enable_osv: bool = False,
        enable_vendors: bool = False,
        vendor_sources: Optional[List[str]] = None,
        nvd_days: int = 1,
        enable_cve_org: bool = False,
        enable_legacy_parsers: bool = False,
        legacy_parser_sources: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Запуск всех парсеров и сохранение данных в БД
        
        Args:
            sources: Список источников для парсинга (ubuntu, debian, nvd, redhat, etc.)
            limit_per_source: Лимит уязвимостей на источник
            enable_nvd: Включить NVD парсинг
            enable_redhat: Включить RedHat импорт
            enable_osv: Включить OSV API парсинг
            enable_vendors: Включить vendor парсеры (Cisco, Fortiguard, etc.)
            vendor_sources: Список vendor источников для парсинга
            nvd_days: Количество дней для NVD инкрементального парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        with self._parsing_lock:
            if self._parsing_active:
                return {'success': False, 'message': 'Парсинг уже выполняется'}
            
            self._parsing_active = True
        
        results = {
            'success': True,
            'start_time': datetime.now().isoformat(),
            'total_parsed': 0,
            'total_saved': 0,
            'by_source': {},
            'errors': [],
            'progress_messages': []  # Детальные сообщения о прогрессе
        }
        
        self.logger.info(f"🚀 [PARSE_ALL] Начало парсинга: sources={sources}, limit={limit_per_source}, nvd={enable_nvd}, redhat={enable_redhat}, osv={enable_osv}, vendors={enable_vendors}, vendor_sources={vendor_sources}")
        self.logger.info(f"   [PARSE_ALL] html_parser={self.html_parser}, type={type(self.html_parser)}")
        self.logger.info(f"   [PARSE_ALL] vendor_parser={self.vendor_parser}, type={type(self.vendor_parser)}")
        self.logger.info(f"   [PARSE_ALL] osv_api_parser={self.osv_api_parser}, type={type(self.osv_api_parser)}")
        print(f"[PARSE_ALL] 🚀 Начало парсинга: sources={sources}, html_parser={self.html_parser}, type={type(self.html_parser)}")
        
        try:
            # HTML парсинг (используем для всех источников)
            if sources and len(sources) > 0:
                self.logger.info(f"🔍 [PARSE_ALL] Начинаем HTML парсинг источников: {sources}, лимит: {limit_per_source}")
                results['progress_messages'].append({
                    'stage': 'start',
                    'message': f'🚀 Начало парсинга источников: {", ".join(sources)}',
                    'sources': sources,
                    'limit': limit_per_source,
                    'timestamp': datetime.now().isoformat()
                })
                
                html_results = self._parse_html_sources(sources, limit_per_source)
                self.logger.info(f"📊 [PARSE_ALL] HTML парсинг завершен: results={html_results}")
                
                # Добавляем прогресс-сообщения из HTML парсинга
                if 'progress_messages' in html_results:
                    results['progress_messages'].extend(html_results['progress_messages'])
                
                results['by_source'].update(html_results.get('by_source', {}))
                results['total_parsed'] += html_results.get('total_parsed', 0)
                results['total_saved'] += html_results.get('total_saved', 0)
                self.logger.info(f"✅ [PARSE_ALL] HTML парсинг: спарсено={html_results.get('total_parsed', 0)}, сохранено={html_results.get('total_saved', 0)}")
            else:
                self.logger.warning(f"⚠️ [PARSE_ALL] Источники не указаны или пусты: sources={sources}")
            
            # Vendor парсинг НЕ используем, чтобы избежать дублирования с HTML парсером
            
            # NVD парсинг
            if enable_nvd:
                nvd_results = self._parse_nvd(nvd_days)
                results['by_source']['nvd'] = nvd_results
                results['total_parsed'] += nvd_results.get('parsed', 0)
                results['total_saved'] += nvd_results.get('saved', 0)
            
            # RedHat импорт
            if enable_redhat:
                redhat_results = self._parse_redhat()
                results['by_source']['redhat'] = redhat_results
                results['total_parsed'] += redhat_results.get('parsed', 0)
                results['total_saved'] += redhat_results.get('saved', 0)
            
            # OSV API парсинг
            if enable_osv and self.osv_api_parser:
                osv_results = self._parse_osv_api(limit_per_source)
                results['by_source']['osv'] = osv_results
                results['total_parsed'] += osv_results.get('parsed', 0)
                results['total_saved'] += osv_results.get('saved', 0)
            
            # Vendor парсеры (дополнительные источники)
            if enable_vendors and self.vendor_parsers and vendor_sources:
                vendor_results = self._parse_vendor_parsers(vendor_sources, limit_per_source)
                results['by_source'].update(vendor_results.get('by_source', {}))
                results['total_parsed'] += vendor_results.get('total_parsed', 0)
                results['total_saved'] += vendor_results.get('total_saved', 0)
            
            # CVE.org синхронизация (все ~380,000 CVE)
            if enable_cve_org and self.cve_org_service:
                cve_org_results = self._parse_cve_org()
                results['by_source']['cve_org'] = cve_org_results
                results['total_parsed'] += cve_org_results.get('parsed', 0)
                results['total_saved'] += cve_org_results.get('saved', 0)
            
            # Legacy парсеры из папки pars/
            if enable_legacy_parsers and self.legacy_parsers and legacy_parser_sources:
                legacy_results = self._parse_legacy_parsers(legacy_parser_sources, limit_per_source)
                results['by_source'].update(legacy_results.get('by_source', {}))
                results['total_parsed'] += legacy_results.get('total_parsed', 0)
                results['total_saved'] += legacy_results.get('total_saved', 0)
            
            results['end_time'] = datetime.now().isoformat()
            results['success'] = True
            self.logger.info(f"✅ [PARSE_ALL] Парсинг завершен: спарсено={results['total_parsed']}, сохранено={results['total_saved']}, by_source={results.get('by_source', {})}")
            
        except Exception as e:
            error_msg = str(e)
            self.logger.error(f"❌ Критическая ошибка парсинга: {error_msg}", exc_info=True)
            results['success'] = False
            results['errors'].append(error_msg)
        
        finally:
            with self._parsing_lock:
                self._parsing_active = False
            self.logger.info("🔒 Блокировка парсинга снята")
        
        return results
    
    def _parse_html_sources(self, sources: List[str], limit: int) -> Dict[str, Any]:
        """Парсинг HTML источников с детальным логированием"""
        self.logger.info(f"🔍 [HTML] Проверка HTML парсера: html_parser={self.html_parser}, type={type(self.html_parser)}")
        print(f"[HTML] 🔍 Проверка HTML парсера: html_parser={self.html_parser}, type={type(self.html_parser)}")
        if not self.html_parser:
            error_msg = "❌ [HTML] HTML парсер не инициализирован! Проверьте импорт HTMLVulnerabilityParser"
            self.logger.error(error_msg)
            print(f"[HTML] {error_msg}")
            return {'total_parsed': 0, 'total_saved': 0, 'by_source': {}, 'progress_messages': []}
        
        results = {
            'total_parsed': 0,
            'total_saved': 0,
            'by_source': {},
            'progress_messages': []  # Детальные сообщения о прогрессе
        }
        
        for source_idx, source in enumerate(sources, 1):
            try:
                progress_msg = f"🌐 Парсинг источника {source} ({source_idx}/{len(sources)})..."
                self.logger.info(f"🔍 [HTML] {progress_msg}")
                results['progress_messages'].append({
                    'stage': 'parsing',
                    'source': source,
                    'message': progress_msg,
                    'timestamp': datetime.now().isoformat()
                })
                
                self.logger.info(f"🔍 [HTML] Начинаем HTML парсинг источника: {source}, лимит: {limit}")
                self.logger.debug(f"   [HTML] Вызываем html_parser.parse_source(source='{source}', limit={limit})")
                
                # Парсинг
                parsed_vulns = self.html_parser.parse_source(source, limit=limit)
                parsed_count = len(parsed_vulns)
                
                # Детальная информация о спарсенных уязвимостях
                if parsed_vulns:
                    cve_ids = [v.get('cve_id', 'N/A') for v in parsed_vulns[:5]]
                    cvss_scores = [v.get('cvss_score', 0.0) for v in parsed_vulns if v.get('cvss_score', 0.0) > 0]
                    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0
                    
                    detail_msg = f"✅ {source}: получено {parsed_count} уязвимостей. CVE: {', '.join(cve_ids[:3])}"
                    if cvss_scores:
                        detail_msg += f". Средний CVSS: {avg_cvss:.1f}"
                    
                    self.logger.info(f"✅ [HTML] {detail_msg}")
                    results['progress_messages'].append({
                        'stage': 'parsed',
                        'source': source,
                        'message': detail_msg,
                        'parsed_count': parsed_count,
                        'cvss_found': len(cvss_scores),
                        'avg_cvss': round(avg_cvss, 2),
                        'timestamp': datetime.now().isoformat()
                    })
                else:
                    warning_msg = f"⚠️ {source}: не получено уязвимостей"
                    self.logger.warning(f"   ⚠️  [HTML] {warning_msg}")
                    results['progress_messages'].append({
                        'stage': 'error',
                        'source': source,
                        'message': warning_msg,
                        'timestamp': datetime.now().isoformat()
                    })
                
                results['by_source'][source] = {
                    'parsed': parsed_count,
                    'saved': 0,
                    'cvss_extracted': len([v for v in parsed_vulns if v.get('cvss_score', 0.0) > 0]),
                    'cve_ids': [v.get('cve_id') for v in parsed_vulns[:10]]
                }
                results['total_parsed'] += parsed_count
                
                # Сохранение в БД
                if parsed_vulns:
                    saving_msg = f"💾 Сохранение {parsed_count} уязвимостей из {source} в БД..."
                    self.logger.info(f"💾 [HTML] {saving_msg}")
                    results['progress_messages'].append({
                        'stage': 'saving',
                        'source': source,
                        'message': saving_msg,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    saved_count = self._save_html_vulnerabilities(parsed_vulns)
                    results['by_source'][source]['saved'] = saved_count
                    results['total_saved'] += saved_count
                    
                    saved_msg = f"✅ {source}: сохранено {saved_count} из {parsed_count} уязвимостей в БД"
                    self.logger.info(f"✅ [HTML] {saved_msg}")
                    results['progress_messages'].append({
                        'stage': 'saved',
                        'source': source,
                        'message': saved_msg,
                        'saved_count': saved_count,
                        'timestamp': datetime.now().isoformat()
                    })
                else:
                    warning_msg = f"⚠️ {source}: не получено уязвимостей для сохранения"
                    self.logger.warning(f"⚠️ [HTML] {warning_msg}")
                    results['progress_messages'].append({
                        'stage': 'warning',
                        'source': source,
                        'message': warning_msg,
                        'timestamp': datetime.now().isoformat()
                    })
                
            except Exception as e:
                error_msg = f"❌ Ошибка парсинга {source}: {str(e)}"
                self.logger.error(f"❌ [HTML] {error_msg}", exc_info=True)
                results['by_source'][source] = {'parsed': 0, 'saved': 0, 'error': str(e)}
                results['errors'] = results.get('errors', [])
                results['errors'].append(f"{source}: {str(e)}")
                results['progress_messages'].append({
                    'stage': 'error',
                    'source': source,
                    'message': error_msg,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        return results
    
    def _parse_vendor_sources(self, sources: List[str], limit: int) -> Dict[str, Any]:
        """Парсинг vendor источников через UniversalVendorParser"""
        if not self.vendor_parser:
            return {'total_parsed': 0, 'total_saved': 0, 'by_source': {}}
        
        try:
            self.logger.info(f"Vendor парсинг источников: {sources}")
            
            # Парсинг всех источников
            parse_results = self.vendor_parser.parse_all_sources(sources, limit_per_source=limit)
            
            # Сохранение в БД
            saved_count = self.vendor_parser.save_parsed_vulnerabilities(parse_results)
            
            results = {
                'total_parsed': parse_results.get('total_parsed', 0),
                'total_saved': saved_count,
                'by_source': {}
            }
            
            # Детализация по источникам
            for source_name, source_data in parse_results.get('by_source', {}).items():
                results['by_source'][source_name] = {
                    'parsed': len(source_data.get('data', [])),
                    'saved': saved_count if source_name in sources else 0
                }
            
            return results
            
        except Exception as e:
            self.logger.error(f"Ошибка vendor парсинга: {e}", exc_info=True)
            return {'total_parsed': 0, 'total_saved': 0, 'by_source': {}, 'error': str(e)}
    
    def _parse_nvd(self, days: int = 1) -> Dict[str, Any]:
        """Парсинг NVD"""
        if not self.nvd_service:
            return {'parsed': 0, 'saved': 0, 'error': 'NVD service не доступен'}
        
        try:
            self.logger.info(f"NVD инкрементальный парсинг за {days} дней")
            
            # Инкрементальная синхронизация
            sync_result = self.nvd_service.incremental_sync(days=days)
            
            return {
                'parsed': sync_result.get('total_parsed', 0),
                'saved': sync_result.get('saved_count', 0),
                'status': sync_result.get('status', 'unknown')
            }
            
        except Exception as e:
            self.logger.error(f"Ошибка NVD парсинга: {e}", exc_info=True)
            return {'parsed': 0, 'saved': 0, 'error': str(e)}
    
    def _parse_cve_org(self) -> Dict[str, Any]:
        """Парсинг всех CVE с cve.org (~380,000 CVE)"""
        if not self.cve_org_service:
            return {'parsed': 0, 'saved': 0, 'error': 'CVE.org service не доступен'}
        
        try:
            self.logger.info("CVE.org инкрементальная синхронизация")
            
            # Инкрементальная синхронизация (обновляет репозиторий и обрабатывает изменения)
            sync_result = self.cve_org_service.incremental_sync(days=1)
            
            return {
                'parsed': sync_result.get('total_processed', 0),
                'saved': sync_result.get('total_saved', 0),
                'status': sync_result.get('status', 'unknown')
            }
            
        except Exception as e:
            self.logger.error(f"Ошибка CVE.org парсинга: {e}", exc_info=True)
            return {'parsed': 0, 'saved': 0, 'error': str(e)}
    
    def _parse_osv_api(self, limit: int = 50) -> Dict[str, Any]:
        """Парсинг уязвимостей из OSV.dev API"""
        if not self.osv_api_parser:
            return {'parsed': 0, 'saved': 0, 'error': 'OSV API парсер не доступен'}
        
        try:
            self.logger.info(f"OSV API парсинг (лимит: {limit})")
            
            # Запрос уязвимостей через API
            parsed_vulns = self.osv_api_parser.query_vulnerabilities(limit=limit)
            self.logger.info(f"✅ OSV API: получено {len(parsed_vulns)} уязвимостей")
            
            if not parsed_vulns:
                return {'parsed': 0, 'saved': 0}
            
            # Сохранение в БД
            saved_count = self._save_html_vulnerabilities(parsed_vulns)
            
            return {
                'parsed': len(parsed_vulns),
                'saved': saved_count
            }
            
        except Exception as e:
            self.logger.error(f"Ошибка OSV API парсинга: {e}", exc_info=True)
            return {'parsed': 0, 'saved': 0, 'error': str(e)}
    
    def _parse_cve_json5(self, file_path: Optional[str] = None, cve_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Парсинг CVE из официального JSON 5.x формата
        
        Args:
            file_path: Путь к JSON файлу (опционально, для загрузки с диска)
            cve_ids: Список конкретных CVE ID для поиска (опционально)
            
        Returns:
            Dict с результатами парсинга
        """
        if not self.cve_json_loader or not self.cve_json5_adapter:
            return {'parsed': 0, 'saved': 0, 'error': 'CVE JSON 5.x адаптер не доступен'}
        
        try:
            self.logger.info("🔍 Парсинг CVE из официального JSON 5.x формата...")
            
            # Если указан файл, загружаем его
            if file_path:
                parsed_cves = self.cve_json_loader.load_and_parse_file(file_path)
            else:
                # TODO: Загрузка с официального API
                self.logger.warning("⚠️ Загрузка с официального API не реализована. Используйте file_path")
                return {'parsed': 0, 'saved': 0, 'error': 'Не указан file_path и загрузка с API не реализована'}
            
            if not parsed_cves:
                return {'parsed': 0, 'saved': 0}
            
            # Фильтрация по CVE ID если указано
            if cve_ids:
                parsed_cves = [cve for cve in parsed_cves if cve.get('cve_id') in cve_ids]
            
            # Преобразование в объекты Vulnerability
            vulnerabilities_to_save = []
            for cve_data in parsed_cves:
                try:
                    vulnerability = self.cve_json5_adapter.to_vulnerability(cve_data)
                    vulnerabilities_to_save.append((cve_data.get('cve_id'), vulnerability))
                except Exception as e:
                    self.logger.error(f"Ошибка преобразования CVE {cve_data.get('cve_id')}: {e}")
            
            # Сохранение в БД
            saved_count = 0
            for cve_id, vulnerability in vulnerabilities_to_save:
                try:
                    if hasattr(self.vuln_repo, 'save_vulnerability'):
                        result = self.vuln_repo.save_vulnerability(vulnerability)
                    elif hasattr(self.vuln_repo, 'add'):
                        result = self.vuln_repo.add(vulnerability)
                    else:
                        result = False
                    
                    if result:
                        saved_count += 1
                except Exception as e:
                    self.logger.error(f"Ошибка сохранения CVE {cve_id}: {e}")
            
            self.logger.info(f"✅ CVE JSON 5.x: спарсено={len(parsed_cves)}, сохранено={saved_count}")
            
            return {
                'parsed': len(parsed_cves),
                'saved': saved_count
            }
            
        except Exception as e:
            self.logger.error(f"Ошибка парсинга CVE JSON 5.x: {e}", exc_info=True)
            return {'parsed': 0, 'saved': 0, 'error': str(e)}
    
    def _parse_vendor_parsers(self, vendor_sources: List[str], limit: int) -> Dict[str, Any]:
        """Парсинг vendor источников через vendor_parsers"""
        if not self.vendor_parsers:
            return {'total_parsed': 0, 'total_saved': 0, 'by_source': {}}
        
        # Маппинг названий источников на методы парсеров
        parser_methods = {
            'cxsecurity': 'parse_cxsecurity',
            'cert': 'parse_cert',
            'us-cert': 'parse_cert',
            'cisco': 'parse_cisco',
            'cybersecurity-help': 'parse_cybersecurity_help',
            'fortiguard': 'parse_fortiguard',
            'ibm': 'parse_ibm',
            'juniper': 'parse_juniper',
            'kaspersky-stat': 'parse_kaspersky_stat',
            'kaspersky': 'parse_kaspersky',
            'paloalto': 'parse_paloalto',
            'postgresql': 'parse_postgresql',
            'suse': 'parse_suse',
            'zerodayinitiative': 'parse_zerodayinitiative',
            'nvd-keywords': 'parse_nvd_by_keywords'
        }
        
        results = {
            'total_parsed': 0,
            'total_saved': 0,
            'by_source': {}
        }
        
        for source in vendor_sources:
            try:
                method_name = parser_methods.get(source.lower())
                if not method_name:
                    self.logger.warning(f"⚠️ Неизвестный vendor источник: {source}")
                    continue
                
                parser_method = getattr(self.vendor_parsers, method_name, None)
                if not parser_method:
                    self.logger.warning(f"⚠️ Метод {method_name} не найден в vendor_parsers")
                    continue
                
                self.logger.info(f"🔍 Vendor парсинг {source} (лимит: {limit})")
                
                # Специальная обработка для NVD по ключевым словам
                if method_name == 'parse_nvd_by_keywords':
                    # Требуется список ключевых слов (можно получить из словаря или использовать дефолтные)
                    keywords = []  # TODO: получить ключевые слова из БД или конфига
                    if not keywords:
                        self.logger.warning(f"⚠️ Для {source} нужны ключевые слова, пропускаем")
                        continue
                    parsed_vulns = parser_method(keywords, limit)
                else:
                    parsed_vulns = parser_method(limit)
                
                parsed_count = len(parsed_vulns)
                results['by_source'][source] = {
                    'parsed': parsed_count,
                    'saved': 0
                }
                results['total_parsed'] += parsed_count
                
                # Сохранение в БД
                if parsed_vulns:
                    saved_count = self._save_html_vulnerabilities(parsed_vulns)
                    results['by_source'][source]['saved'] = saved_count
                    results['total_saved'] += saved_count
                    self.logger.info(f"✅ {source}: спарсено={parsed_count}, сохранено={saved_count}")
                else:
                    self.logger.warning(f"⚠️ {source}: не получено уязвимостей")
                
            except Exception as e:
                error_msg = str(e)
                self.logger.error(f"❌ Ошибка vendor парсинга {source}: {error_msg}", exc_info=True)
                results['by_source'][source] = {'parsed': 0, 'saved': 0, 'error': error_msg}
        
        return results
    
    def _parse_legacy_parsers(self, parser_sources: List[str], limit: int) -> Dict[str, Any]:
        """
        Парсинг через legacy парсеры из папки pars/
        
        Args:
            parser_sources: Список парсеров для запуска
            limit: Лимит уязвимостей на парсер
            
        Returns:
            Dict с результатами парсинга
        """
        if not self.legacy_parsers:
            return {'total_parsed': 0, 'total_saved': 0, 'by_source': {}}
        
        results = {
            'total_parsed': 0,
            'total_saved': 0,
            'by_source': {}
        }
        
        for parser_name in parser_sources:
            if parser_name not in self.legacy_parsers:
                self.logger.warning(f"⚠️ Legacy парсер '{parser_name}' не найден")
                continue
            
            parser = self.legacy_parsers[parser_name]
            self.logger.info(f"🔍 Запуск legacy парсера: {parser_name} (limit={limit})")
            
            try:
                parser_results = parser.parse(limit=limit)
                results['by_source'][parser_name] = parser_results
                results['total_parsed'] += parser_results.get('parsed', 0)
                results['total_saved'] += parser_results.get('saved', 0)
                
                self.logger.info(f"✅ {parser_name}: спарсено {parser_results.get('parsed', 0)}, сохранено {parser_results.get('saved', 0)}")
            except Exception as e:
                error_msg = f"Ошибка парсинга {parser_name}: {e}"
                self.logger.error(error_msg, exc_info=True)
                results['by_source'][parser_name] = {
                    'parsed': 0,
                    'saved': 0,
                    'errors': [error_msg]
                }
        
        return results
    
    def _parse_redhat(self) -> Dict[str, Any]:
        """Импорт RedHat CVE"""
        if not self.redhat_importer:
            return {'parsed': 0, 'saved': 0, 'error': 'RedHat importer не доступен'}
        
        try:
            self.logger.info("RedHat импорт последних 7 дней")
            
            # Получение CVE
            from datetime import datetime, timedelta
            after_date = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
            cves = self.redhat_importer.fetch_cves(after_date=after_date, per_page=100)
            
            saved_count = 0
            for cve in cves:
                try:
                    # Преобразование в формат уязвимости
                    vuln_dict = self.redhat_importer.transform_redhat_to_nvd_format(cve)
                    
                    # Создание объекта Vulnerability
                    vulnerability = self._create_vulnerability_from_dict(vuln_dict)
                    
                    # Сохранение
                    if hasattr(self.vuln_repo, 'add'):
                        result = self.vuln_repo.add(vulnerability)
                    elif hasattr(self.vuln_repo, 'save_vulnerability'):
                        result = self.vuln_repo.save_vulnerability(vulnerability)
                    else:
                        result = False
                    
                    if result:
                        saved_count += 1
                
                except Exception as e:
                    self.logger.error(f"Ошибка сохранения RedHat CVE: {e}")
            
            return {
                'parsed': len(cves),
                'saved': saved_count
            }
            
        except Exception as e:
            self.logger.error(f"Ошибка RedHat импорта: {e}", exc_info=True)
            return {'parsed': 0, 'saved': 0, 'error': str(e)}
    
    def _create_vulnerability_from_dict(self, vuln_dict: Dict[str, Any]) -> Vulnerability:
        """Создание объекта Vulnerability из словаря"""
        from datetime import datetime
        
        # Извлечение описания
        descriptions = vuln_dict.get('descriptions', [])
        description = ''
        if descriptions:
            if isinstance(descriptions, list):
                description = descriptions[0].get('value', '') if descriptions else ''
            else:
                description = str(descriptions)
        
        # Извлечение CVSS
        cvss_score = 0.0
        if 'metrics' in vuln_dict:
            metrics = vuln_dict['metrics']
            if hasattr(metrics, 'cvss_v3'):
                cvss_score = metrics.cvss_v3.get('baseScore', 0.0) if metrics.cvss_v3 else 0.0
            elif hasattr(metrics, 'cvss_v2'):
                cvss_score = metrics.cvss_v2.get('baseScore', 0.0) if metrics.cvss_v2 else 0.0
        
        # Нормализация severity
        severity = 'medium'
        if cvss_score >= 9.0:
            severity = 'critical'
        elif cvss_score >= 7.0:
            severity = 'high'
        elif cvss_score >= 4.0:
            severity = 'medium'
        elif cvss_score > 0:
            severity = 'low'
        
        # Парсинг дат
        published = vuln_dict.get('published', '')
        if isinstance(published, str):
            try:
                published_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
            except:
                published_date = datetime.now()
        else:
            published_date = published if isinstance(published, datetime) else datetime.now()
        
        return Vulnerability(
            id=None,
            title=vuln_dict.get('cve_id', 'Unknown CVE'),
            description=description or 'No description available',
            severity=severity,
            status='new',
            assigned_operator=None,
            created_date=published_date,
            completed_date=None,
            approved=False,
            modifications=None,
            cvss_score=cvss_score,
            risk_level=severity,
            category=vuln_dict.get('source_identifier', 'unknown')
        )
    
    def _save_html_vulnerabilities(self, parsed_vulns: List[Dict[str, Any]]) -> int:
        """Сохранение HTML уязвимостей в БД с пакетной обработкой"""
        saved_count = 0
        skipped_count = 0
        error_count = 0
        
        self.logger.info(f"💾 Начинаем сохранение {len(parsed_vulns)} уязвимостей в БД (пакетами по 100)")
        
        # Пакетная обработка по 100 уязвимостей
        batch_size = 100
        batches = [parsed_vulns[i:i + batch_size] for i in range(0, len(parsed_vulns), batch_size)]
        
        for batch_idx, batch in enumerate(batches, 1):
            self.logger.info(f"📦 Обрабатываем пакет {batch_idx}/{len(batches)} ({len(batch)} уязвимостей)")
            
            # Подготовка данных для пакетного сохранения
            vulnerabilities_to_save = []
            cve_ids_to_check = []
            
            for vuln_data in batch:
                try:
                    cve_id = vuln_data.get('cve_id') or vuln_data.get('id') or 'UNKNOWN'
                    if cve_id and cve_id != 'UNKNOWN':
                        cve_ids_to_check.append(str(cve_id))
                        vulnerability = self._create_vulnerability_from_html_data(vuln_data)
                        vulnerabilities_to_save.append((cve_id, vulnerability))
                except Exception as e:
                    error_count += 1
                    cve_id = vuln_data.get('cve_id', 'unknown')
                    self.logger.error(f"   ❌ Ошибка создания уязвимости {cve_id}: {e}", exc_info=True)
            
            # Пакетная проверка существующих CVE (для legacy схемы используем прямой SQL запрос)
            existing_cves = set()
            if cve_ids_to_check and hasattr(self.vuln_repo, 'db'):
                try:
                    cursor = self.vuln_repo.db.cursor()
                    # Используем правильный синтаксис для PostgreSQL IN с параметрами
                    placeholders = ','.join(['%s'] * len(cve_ids_to_check))
                    query = f"SELECT DISTINCT cve FROM turn WHERE cve IN ({placeholders})"
                    self.logger.info(f"🔍 Проверка существующих CVE: запрос для {len(cve_ids_to_check)} CVE")
                    self.logger.debug(f"   Первые 5 CVE для проверки: {cve_ids_to_check[:5]}")
                    cursor.execute(query, tuple(cve_ids_to_check))
                    existing_rows = cursor.fetchall()
                    existing_cves = {row[0] for row in existing_rows if row[0]}
                    cursor.close()
                    self.logger.info(f"📊 Найдено существующих CVE: {len(existing_cves)} из {len(cve_ids_to_check)}")
                    if existing_cves:
                        self.logger.info(f"   Существующие CVE (первые 5): {list(existing_cves)[:5]}")
                    else:
                        self.logger.info(f"   ✅ Все CVE новые, можно сохранять!")
                except Exception as e:
                    self.logger.error(f"❌ Ошибка пакетной проверки существующих CVE: {e}", exc_info=True)
                    # В случае ошибки продолжаем без фильтрации (попытаемся сохранить все)
                    existing_cves = set()  # Пустой set, чтобы попытаться сохранить все
            
            # Пакетное сохранение с многопоточностью
            def save_single_vuln(cve_id: str, vulnerability: Vulnerability) -> tuple:
                """Сохранение одной уязвимости"""
                try:
                    # ВРЕМЕННО ОТКЛЮЧЕНО: Проверка существования
                    # if cve_id in existing_cves:
                    #     return (cve_id, 'skipped', 'Уже существует в БД')
                    
                    # Фильтр для ИИ уязвимостей (отдельная обработка)
                    # ЗАКОММЕНТИРОВАНО: Логика ИИ уязвимостей
                    # is_ai_related = getattr(vulnerability, 'is_ai_related', False)
                    # if is_ai_related:
                    #     # ИИ уязвимости обрабатываются отдельно
                    #     return (cve_id, 'skipped', 'ИИ уязвимость - обрабатывается отдельно')
                    
                    # Сохранение
                    self.logger.info(f"💾 Сохраняем {cve_id}...")
                    self.logger.debug(f"   Объект: title={vulnerability.title[:50]}, source_identifier={getattr(vulnerability, 'source_identifier', 'N/A')}")
                    
                    if hasattr(self.vuln_repo, 'save_vulnerability'):
                        result = self.vuln_repo.save_vulnerability(vulnerability)
                        self.logger.info(f"   save_vulnerability({cve_id}) вернул: {result}")
                    elif hasattr(self.vuln_repo, 'add'):
                        result = self.vuln_repo.add(vulnerability)
                        self.logger.info(f"   add({cve_id}) вернул: {result}")
                    else:
                        self.logger.error(f"   ❌ Репозиторий не имеет методов сохранения")
                        return (cve_id, 'error', 'Репозиторий не имеет методов сохранения')
                    
                    if result:
                        self.logger.info(f"   ✅ Успешно сохранено: {cve_id}")
                        return (cve_id, 'saved', None)
                    else:
                        # Детальная диагностика почему вернул False
                        self.logger.error(f"   ❌ save_vulnerability вернул False для {cve_id}")
                        return (cve_id, 'error', 'Метод сохранения вернул False')
                except Exception as save_error:
                    import traceback
                    error_msg = f"{str(save_error)}\n{traceback.format_exc()}"
                    self.logger.error(f"   ❌ Исключение при сохранении {cve_id}: {error_msg}")
                    return (cve_id, 'error', error_msg)
            
            # В РЕЖИМЕ ТЕСТИРОВАНИЯ: Сохраняем ВСЕ уязвимости без фильтрации
            new_vulnerabilities = vulnerabilities_to_save
            self.logger.info(f"📦 Сохраняем ВСЕ {len(new_vulnerabilities)} уязвимостей (режим тестирования)")
            
            # Многопоточное сохранение (до 10 потоков для сохранения в БД)
            max_save_workers = min(10, len(new_vulnerabilities))
            if len(new_vulnerabilities) > 1:
                self.logger.info(f"⚡ Многопоточное сохранение {len(new_vulnerabilities)} уязвимостей (потоков: {max_save_workers})")
                with ThreadPoolExecutor(max_workers=max_save_workers) as executor:
                    futures = {
                        executor.submit(save_single_vuln, cve_id, vuln): (cve_id, vuln)
                        for cve_id, vuln in new_vulnerabilities
                    }
                    
                    for future in as_completed(futures):
                        cve_id, status, error = future.result()
                        if status == 'saved':
                            saved_count += 1
                            existing_cves.add(cve_id)
                            self.logger.debug(f"   ✅ Сохранена: {cve_id}")
                        elif status == 'skipped':
                            skipped_count += 1
                            self.logger.debug(f"   ⏭️  {cve_id} уже существует, пропускаем")
                        else:
                            error_count += 1
                            self.logger.error(f"   ❌ Ошибка сохранения {cve_id}: {error}")
            else:
                # Последовательное сохранение для небольшого количества элементов
                for cve_id, vulnerability in new_vulnerabilities:
                    cve_id_result, status, error = save_single_vuln(cve_id, vulnerability)
                    if status == 'saved':
                        saved_count += 1
                        existing_cves.add(cve_id)
                        self.logger.debug(f"   ✅ Сохранена: {cve_id}")
                    elif status == 'skipped':
                        skipped_count += 1
                        self.logger.debug(f"   ⏭️  {cve_id} уже существует, пропускаем")
                    else:
                        error_count += 1
                        self.logger.error(f"   ❌ Ошибка сохранения {cve_id}: {error}")
            
            # Добавляем пропущенные (уже существующие) в skipped_count
            skipped_count += len(vulnerabilities_to_save) - len(new_vulnerabilities)
            
            self.logger.info(f"   📊 Пакет {batch_idx}: сохранено={saved_count}, пропущено={skipped_count}, ошибок={error_count}")
        
        self.logger.info(f"📊 ИТОГОВЫЕ результаты сохранения: сохранено={saved_count}, пропущено={skipped_count}, ошибок={error_count}")
        return saved_count
    
    def _create_vulnerability_from_html_data(self, vuln_data: Dict[str, Any]) -> Vulnerability:
        """Создание Vulnerability из парсера данных с полными данными из JSON"""
        from datetime import datetime
        
        # Извлечение основных данных
        cve_id = vuln_data.get('cve_id', 'UNKNOWN-CVE')
        title = vuln_data.get('title') or vuln_data.get('summary') or f"Уязвимость {cve_id}"
        
        # Полное описание (приоритет: description > details > summary)
        description = vuln_data.get('description') or vuln_data.get('details') or vuln_data.get('summary') or ''
        if not description:
            description = f"Уязвимость {cve_id} из источника {vuln_data.get('source', 'unknown')}"
        
        # CVSS и severity - извлекаем из разных полей
        cvss_score = 0.0
        cvss_v3_data = vuln_data.get('cvss_v3') or vuln_data.get('cvss3')
        
        # Пробуем извлечь CVSS из разных мест
        if vuln_data.get('cvss_score'):
            cvss_score = float(vuln_data.get('cvss_score', 0.0))
        elif cvss_v3_data and isinstance(cvss_v3_data, dict):
            cvss_score = float(cvss_v3_data.get('baseScore', 0.0))
        elif vuln_data.get('cvss3_score'):
            cvss_score = float(vuln_data.get('cvss3_score', 0.0))
        
        # Определяем severity
        severity = vuln_data.get('severity', 'medium')
        if not severity or severity == 'unknown':
            if cvss_score >= 9.0:
                severity = 'critical'
            elif cvss_score >= 7.0:
                severity = 'high'
            elif cvss_score >= 4.0:
                severity = 'medium'
            elif cvss_score > 0:
                severity = 'low'
            else:
                severity = 'medium'
        
        # Дата публикации - извлекаем из разных полей
        published_date = vuln_data.get('published_date') or vuln_data.get('published') or vuln_data.get('date')
        if isinstance(published_date, str):
            try:
                # Пробуем разные форматы
                if 'T' in published_date or '+' in published_date:
                    published = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                else:
                    published = datetime.fromisoformat(published_date)
            except:
                try:
                    published = datetime.strptime(published_date, '%Y-%m-%d')
                except:
                    published = datetime.now()
        elif isinstance(published_date, datetime):
            published = published_date
        else:
            published = datetime.now()
        
        # Дата последнего изменения
        modified_date = vuln_data.get('modified_date') or vuln_data.get('modified')
        if isinstance(modified_date, str):
            try:
                if 'T' in modified_date or '+' in modified_date:
                    modified = datetime.fromisoformat(modified_date.replace('Z', '+00:00'))
                else:
                    modified = datetime.fromisoformat(modified_date)
            except:
                try:
                    modified = datetime.strptime(modified_date, '%Y-%m-%d')
                except:
                    modified = published
        elif isinstance(modified_date, datetime):
            modified = modified_date
        else:
            modified = published
        
        # Источник
        source = vuln_data.get('source') or 'html_parser'
        
        # ВАЖНО: Обязательно передаем cve_id!
        # modifications должен быть int, а не None (по определению dataclass)
        vulnerability = Vulnerability(
            id=0,  # 0 для новых записей (автоинкремент в БД)
            title=title[:500] if len(title) > 500 else title,  # Ограничение длины
            description=description[:5000] if len(description) > 5000 else description,
            severity=severity,
            status='new',
            assigned_operator=None,
            created_date=published,
            completed_date=None,
            approved=False,
            modifications=0,  # int, а не None
            cvss_score=cvss_score,
            risk_level=severity,
            category=source,
            cve_id=cve_id  # КРИТИЧЕСКИ ВАЖНО: передаем cve_id для возможности поиска
        )
        
        # Для legacy схемы нужно установить source_identifier для правильного сохранения в turn.source
        # Legacy репозиторий использует source_identifier для определения источника
        source_lower = source.lower()
        if source_lower == 'debian':
            vulnerability.source_identifier = 'Debian'
        elif source_lower == 'ubuntu':
            vulnerability.source_identifier = 'Ubuntu'
        elif source_lower == 'redhat':
            vulnerability.source_identifier = 'RedHat'
        elif source_lower == 'osv':
            vulnerability.source_identifier = 'OSV'
        elif source_lower in ['cisco', 'cxsecurity', 'cert', 'us-cert', 'cybersecurity-help', 
                               'fortiguard', 'ibm', 'juniper', 'kaspersky', 'paloalto', 
                               'postgresql', 'suse', 'zerodayinitiative']:
            # Vendor источники сохраняем с их именем
            vulnerability.source_identifier = source.capitalize()
        else:
            vulnerability.source_identifier = 'NVD'  # По умолчанию
        
        # Сохраняем дополнительные данные как атрибуты
        if vuln_data.get('url'):
            setattr(vulnerability, 'url', str(vuln_data.get('url')))
        
        if vuln_data.get('affected_packages'):
            setattr(vulnerability, 'affected_packages', vuln_data.get('affected_packages'))
        
        if vuln_data.get('references'):
            setattr(vulnerability, 'references', vuln_data.get('references'))
        
        if vuln_data.get('cwe'):
            setattr(vulnerability, 'cwe', str(vuln_data.get('cwe')))
        
        if cvss_v3_data:
            setattr(vulnerability, 'cvss_v3', cvss_v3_data)
        
        if modified != published:
            setattr(vulnerability, 'modified_date', modified)
        
        return vulnerability
    
    def get_parsing_status(self) -> Dict[str, Any]:
        """Получить статус парсинга"""
        return {
            'is_active': self._parsing_active,
            'timestamp': datetime.now().isoformat()
        }


# Глобальный экземпляр (ленивая инициализация)
_unified_parser_service_instance = None

def get_unified_parser_service():
    """Получить экземпляр unified_parser_service с ленивой инициализацией"""
    global _unified_parser_service_instance
    if _unified_parser_service_instance is None:
        try:
            _unified_parser_service_instance = UnifiedParserService()
        except Exception as e:
            logger.error(f"Ошибка создания UnifiedParserService: {e}", exc_info=True)
            raise
    return _unified_parser_service_instance

# Proxy объект для обратной совместимости
class _UnifiedParserServiceProxy:
    """Proxy для ленивой инициализации unified_parser_service"""
    def __getattr__(self, name):
        return getattr(get_unified_parser_service(), name)
    
    def __call__(self, *args, **kwargs):
        return get_unified_parser_service()(*args, **kwargs)

unified_parser_service = _UnifiedParserServiceProxy()

