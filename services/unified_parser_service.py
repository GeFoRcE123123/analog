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
            self.nvd_service = NVDIntegrationService(self.vuln_repo)
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
    
    def parse_all(
        self,
        sources: Optional[List[str]] = None,
        limit_per_source: int = 50,
        enable_nvd: bool = False,
        enable_redhat: bool = False,
        enable_osv: bool = False,
        nvd_days: int = 1
    ) -> Dict[str, Any]:
        """
        Запуск всех парсеров и сохранение данных в БД
        
        Args:
            sources: Список источников для парсинга (ubuntu, debian, nvd, redhat, etc.)
            limit_per_source: Лимит уязвимостей на источник
            enable_nvd: Включить NVD парсинг
            enable_redhat: Включить RedHat импорт
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
            'errors': []
        }
        
        self.logger.info(f"🚀 [PARSE_ALL] Начало парсинга: sources={sources}, limit={limit_per_source}, nvd={enable_nvd}, redhat={enable_redhat}, osv={enable_osv}")
        self.logger.info(f"   [PARSE_ALL] html_parser={self.html_parser}, type={type(self.html_parser)}")
        self.logger.info(f"   [PARSE_ALL] vendor_parser={self.vendor_parser}, type={type(self.vendor_parser)}")
        self.logger.info(f"   [PARSE_ALL] osv_api_parser={self.osv_api_parser}, type={type(self.osv_api_parser)}")
        print(f"[PARSE_ALL] 🚀 Начало парсинга: sources={sources}, html_parser={self.html_parser}, type={type(self.html_parser)}")
        
        try:
            # HTML парсинг (используем для всех источников)
            if sources and len(sources) > 0:
                self.logger.info(f"🔍 [PARSE_ALL] Начинаем HTML парсинг источников: {sources}, лимит: {limit_per_source}")
                html_results = self._parse_html_sources(sources, limit_per_source)
                self.logger.info(f"📊 [PARSE_ALL] HTML парсинг завершен: results={html_results}")
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
        """Парсинг HTML источников"""
        self.logger.info(f"🔍 [HTML] Проверка HTML парсера: html_parser={self.html_parser}, type={type(self.html_parser)}")
        print(f"[HTML] 🔍 Проверка HTML парсера: html_parser={self.html_parser}, type={type(self.html_parser)}")
        if not self.html_parser:
            error_msg = "❌ [HTML] HTML парсер не инициализирован! Проверьте импорт HTMLVulnerabilityParser"
            self.logger.error(error_msg)
            print(f"[HTML] {error_msg}")
            return {'total_parsed': 0, 'total_saved': 0, 'by_source': {}}
        
        results = {
            'total_parsed': 0,
            'total_saved': 0,
            'by_source': {}
        }
        
        for source in sources:
            try:
                self.logger.info(f"🔍 [HTML] Начинаем HTML парсинг источника: {source}, лимит: {limit}")
                self.logger.debug(f"   [HTML] Вызываем html_parser.parse_source(source='{source}', limit={limit})")
                
                # Парсинг
                parsed_vulns = self.html_parser.parse_source(source, limit=limit)
                self.logger.info(f"✅ [HTML] Источник {source}: получено {len(parsed_vulns)} уязвимостей")
                if parsed_vulns:
                    self.logger.debug(f"   [HTML] Первые 3 CVE: {[v.get('cve_id', 'N/A') for v in parsed_vulns[:3]]}")
                else:
                    self.logger.warning(f"   ⚠️  [HTML] Источник {source}: parse_source вернул пустой список!")
                
                results['by_source'][source] = {
                    'parsed': len(parsed_vulns),
                    'saved': 0
                }
                results['total_parsed'] += len(parsed_vulns)
                
                # Сохранение в БД
                if parsed_vulns:
                    self.logger.info(f"💾 Сохранение {len(parsed_vulns)} уязвимостей из {source} в БД...")
                    saved_count = self._save_html_vulnerabilities(parsed_vulns)
                    results['by_source'][source]['saved'] = saved_count
                    results['total_saved'] += saved_count
                    self.logger.info(f"✅ Сохранено {saved_count} уязвимостей из {source} в БД")
                else:
                    self.logger.warning(f"⚠️ Источник {source}: не получено уязвимостей для сохранения")
                
            except Exception as e:
                error_msg = str(e)
                self.logger.error(f"❌ Ошибка парсинга {source}: {error_msg}", exc_info=True)
                results['by_source'][source] = {'parsed': 0, 'saved': 0, 'error': error_msg}
                results['errors'] = results.get('errors', [])
                results['errors'].append(f"{source}: {error_msg}")
        
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
                    placeholders = ','.join(['%s'] * len(cve_ids_to_check))
                    cursor.execute(f"SELECT DISTINCT cve FROM turn WHERE cve IN ({placeholders})", tuple(cve_ids_to_check))
                    existing_cves = {row[0] for row in cursor.fetchall()}
                    cursor.close()
                except Exception as e:
                    self.logger.warning(f"⚠️ Ошибка пакетной проверки существующих CVE: {e}, продолжаем")
            
            # Пакетное сохранение с многопоточностью
            # Используем thread-safe set для отслеживания существующих CVE
            existing_cves_set = existing_cves.copy()  # Копируем для thread-safety
            
            def save_single_vuln(cve_id: str, vulnerability: Vulnerability) -> tuple:
                """Сохранение одной уязвимости"""
                try:
                    # Пропускаем если уже существует (проверка выполняется до запуска потоков)
                    # Сохранение
                    if hasattr(self.vuln_repo, 'save_vulnerability'):
                        result = self.vuln_repo.save_vulnerability(vulnerability)
                    elif hasattr(self.vuln_repo, 'add'):
                        result = self.vuln_repo.add(vulnerability)
                    else:
                        return (cve_id, 'error', 'Репозиторий не имеет методов сохранения')
                    
                    if result:
                        return (cve_id, 'saved', None)
                    else:
                        return (cve_id, 'error', 'Метод сохранения вернул False')
                except Exception as save_error:
                    import traceback
                    error_msg = f"{str(save_error)}\n{traceback.format_exc()}"
                    return (cve_id, 'error', error_msg)
            
            # Фильтруем уязвимости, которые еще не существуют
            new_vulnerabilities = [(cve_id, vuln) for cve_id, vuln in vulnerabilities_to_save if cve_id not in existing_cves]
            
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
        """Создание Vulnerability из HTML парсера данных"""
        from datetime import datetime
        
        # Извлечение данных
        cve_id = vuln_data.get('cve_id', 'UNKNOWN-CVE')
        title = vuln_data.get('title') or vuln_data.get('summary') or f"Уязвимость {cve_id}"
        description = vuln_data.get('description') or vuln_data.get('summary') or ''
        
        # CVSS и severity
        cvss_score = float(vuln_data.get('cvss_score', 0.0))
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
        
        # Дата
        published_date = vuln_data.get('published_date') or vuln_data.get('date')
        if isinstance(published_date, str):
            try:
                published = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
            except:
                published = datetime.now()
        elif isinstance(published_date, datetime):
            published = published_date
        else:
            published = datetime.now()
        
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
        if source.lower() == 'debian':
            vulnerability.source_identifier = 'Debian'
        elif source.lower() == 'ubuntu':
            vulnerability.source_identifier = 'Ubuntu'
        elif source.lower() == 'redhat':
            vulnerability.source_identifier = 'RedHat'
        elif source.lower() == 'osv':
            vulnerability.source_identifier = 'OSV'
        else:
            vulnerability.source_identifier = 'NVD'  # По умолчанию
        
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

