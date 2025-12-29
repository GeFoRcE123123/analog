"""
Интеграционный сервис для работы с CVE.org данными
Объединяет загрузку, парсинг и сохранение всех ~380,000 CVE
"""
import logging
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from services.cve_org_downloader import get_cve_org_downloader
from services.cve_json5_adapter import cve_json5_adapter
from models.legacy_repositories import LegacyVulnerabilityRepository

logger = logging.getLogger(__name__)

# Импорт статуса синхронизации (опционально, если модуль доступен)
try:
    from services.backend.cve_sync_status import get_sync_status, start_sync, complete_sync, error_sync, update_sync_status
    SYNC_STATUS_AVAILABLE = True
except ImportError:
    SYNC_STATUS_AVAILABLE = False
    logger.warning("cve_sync_status модуль не доступен, статус синхронизации не будет обновляться")


class CVEOrgIntegrationService:
    """
    Интеграционный сервис для автоматической загрузки и обработки всех CVE с cve.org
    """
    
    def __init__(self, vulnerability_repo: LegacyVulnerabilityRepository, storage_path: str = "/tmp/cve_data", progress_callback: Optional[Callable] = None):
        """
        Инициализация сервиса
        
        Args:
            vulnerability_repo: Репозиторий для сохранения уязвимостей
            storage_path: Путь для хранения клонированного репозитория
            progress_callback: Callback функция для обновления прогресса (опционально)
        """
        self.vulnerability_repo = vulnerability_repo
        self.downloader = get_cve_org_downloader(storage_path=storage_path)
        self.logger = logging.getLogger(__name__)
        self.progress_callback = progress_callback
        
        # Конфигурация
        self.config = {
            'batch_size': 1000,  # Размер пакета для сохранения
            'max_workers': 10,   # Количество потоков для обработки
            'update_on_start': False  # Не обновлять репозиторий при старте (клонируется на хосте)
        }
    
    def sync_all_cves(self, max_cves: Optional[int] = None) -> Dict[str, Any]:
        """
        Полная синхронизация всех CVE
        
        Args:
            max_cves: Максимальное количество CVE для синхронизации (None = все)
            
        Returns:
            Статистика синхронизации
        """
        stats = {
            'status': 'running',
            'start_time': datetime.now().isoformat(),
            'total_processed': 0,
            'total_saved': 0,
            'total_errors': 0,
            'errors': []
        }
        
        try:
            # Обновляем статус синхронизации - начало
            if SYNC_STATUS_AVAILABLE:
                start_sync(total_cves=0)  # Будет обновлено после загрузки всех CVE
            
            self.logger.info("🚀 Начало полной синхронизации CVE с cve.org")
            
            # 1. Обновляем/клонируем репозиторий
            if self.config['update_on_start']:
                self.logger.info("📥 Обновление репозитория CVE...")
                if self.downloader.repo_path.exists() and (self.downloader.repo_path / ".git").exists():
                    if not self.downloader.update_repository():
                        self.logger.error("❌ Ошибка обновления репозитория, пробуем клонировать заново...")
                        self.downloader.clone_repository(force=True)
                else:
                    self.downloader.clone_repository(force=False)
            
            # 2. Получаем все CVE записи
            self.logger.info("📥 Загрузка всех CVE записей...")
            all_cves = []
            
            for cve_data in self.downloader.iterate_cve_files(max_files=max_cves):
                all_cves.append(cve_data)
                stats['total_processed'] += 1
                
                if stats['total_processed'] % 10000 == 0:
                    self.logger.info(f"📊 Загружено {stats['total_processed']} CVE записей")
            
            self.logger.info(f"✅ Всего загружено {len(all_cves)} CVE записей")
            
            # Обновляем статус с общим количеством
            if SYNC_STATUS_AVAILABLE:
                update_sync_status(total_cves=len(all_cves))
            stats['total_processed'] = len(all_cves)
            
            # 3. Парсим и сохраняем пакетами по 1000
            self.logger.info("🔄 Парсинг и сохранение CVE записей пакетами по 1000...")
            saved_count = 0
            batch_size = 1000  # Фиксированный размер пакета для синхронизации
            total_batches = (len(all_cves) + batch_size - 1) // batch_size
            
            for batch_start in range(0, len(all_cves), batch_size):
                batch = all_cves[batch_start:batch_start + batch_size]
                batch_saved = self._process_and_save_batch(batch)
                saved_count += batch_saved
                
                batch_num = batch_start // batch_size + 1
                progress_pct = (saved_count / len(all_cves) * 100) if len(all_cves) > 0 else 0
                
                self.logger.info(f"💾 Пакет {batch_num}/{total_batches}: Сохранено {batch_saved} CVE | Всего: {saved_count}/{len(all_cves)} ({progress_pct:.1f}%)")
                
                # Обновляем статус синхронизации
                if SYNC_STATUS_AVAILABLE:
                    update_sync_status(
                        processed_cves=saved_count,
                        saved_cves=saved_count,
                        current_batch=batch_num,
                        total_batches=total_batches,
                        progress_percent=progress_pct
                    )
                
                # Вызываем callback для обновления прогресса (если есть)
                if self.progress_callback:
                    try:
                        self.progress_callback({
                            'batch': batch_num,
                            'total_batches': total_batches,
                            'batch_saved': batch_saved,
                            'total_saved': saved_count,
                            'total_cves': len(all_cves),
                            'progress_percent': progress_pct
                        })
                    except Exception as e:
                        self.logger.warning(f"⚠️ Ошибка в progress_callback: {e}")
            
            # После завершения всех пакетов обновляем финальную статистику
            stats['total_saved'] = saved_count
            stats['status'] = 'completed'
            stats['end_time'] = datetime.now().isoformat()
            
            # Завершаем статус синхронизации
            if SYNC_STATUS_AVAILABLE:
                complete_sync(saved_count)
            
            self.logger.info(f"✅ Синхронизация завершена: обработано {stats['total_processed']}, сохранено {stats['total_saved']}")
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка синхронизации: {e}", exc_info=True)
            stats['status'] = 'error'
            stats['errors'].append(str(e))
            stats['end_time'] = datetime.now().isoformat()
            
            # Устанавливаем ошибку в статусе
            if SYNC_STATUS_AVAILABLE:
                error_sync(str(e))
        
        return stats
    
    def incremental_sync(self, days: int = 1) -> Dict[str, Any]:
        """
        Инкрементальная синхронизация (обновление репозитория)
        
        Args:
            days: Количество дней для фильтрации (пока не используется)
            
        Returns:
            Статистика синхронизации
        """
        stats = {
            'status': 'running',
            'start_time': datetime.now().isoformat(),
            'total_processed': 0,
            'total_saved': 0,
            'total_errors': 0,
            'errors': []
        }
        
        try:
            self.logger.info("🔄 Начало инкрементальной синхронизации CVE")
            
            # Обновляем репозиторий
            if not self.downloader.update_repository():
                self.logger.warning("⚠️ Не удалось обновить репозиторий, выполняем полную синхронизацию")
                return self.sync_all_cves()
            
            # Получаем новые/измененные CVE (пока обрабатываем все из обновленного репозитория)
            # TODO: Реализовать проверку изменений через git log
            self.logger.info("📥 Загрузка обновленных CVE...")
            
            # Пока что делаем полную синхронизацию после обновления
            # В будущем можно оптимизировать, проверяя только измененные файлы
            return self.sync_all_cves()
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка инкрементальной синхронизации: {e}", exc_info=True)
            stats['status'] = 'error'
            stats['errors'].append(str(e))
            stats['end_time'] = datetime.now().isoformat()
            return stats
    
    def _process_and_save_batch(self, cve_batch: List[Dict[str, Any]]) -> int:
        """
        Обработка и сохранение пакета CVE
        
        Args:
            cve_batch: Пакет CVE записей
            
        Returns:
            Количество успешно сохраненных CVE
        """
        saved_count = 0
        
        for cve_data in cve_batch:
            try:
                # Парсим CVE запись через адаптер
                parsed_vuln = cve_json5_adapter.parse_cve_record(cve_data)
                
                if not parsed_vuln:
                    continue
                
                # Проверяем тип возвращаемого значения
                if isinstance(parsed_vuln, list):
                    self.logger.warning(f"⚠️ parse_cve_record вернул список вместо словаря, пропускаем")
                    continue
                
                if not isinstance(parsed_vuln, dict):
                    self.logger.warning(f"⚠️ parse_cve_record вернул {type(parsed_vuln)}, ожидался dict, пропускаем")
                    continue
                
                # Преобразуем в объект Vulnerability
                # Адаптер возвращает: published_date, updated_date, state, source и т.д.
                from models.entities import Vulnerability
                vulnerability = Vulnerability(
                    id=0,  # id будет присвоен при сохранении в БД
                    title=parsed_vuln.get('title', '')[:500] if parsed_vuln.get('title') else '',  # Ограничение длины
                    description=parsed_vuln.get('description', ''),
                    severity=parsed_vuln.get('severity', 'medium'),
                    status='new',
                    cvss_score=parsed_vuln.get('cvss_score', 0.0),
                    category='NVD',  # По умолчанию для CVE.org
                    cve_id=parsed_vuln.get('cve_id', '')
                )
                
                # Добавляем дополнительные поля через setattr (как в universal_vendor_parser)
                setattr(vulnerability, 'source_identifier', parsed_vuln.get('source', 'cve.org'))
                setattr(vulnerability, 'published', parsed_vuln.get('published_date'))
                setattr(vulnerability, 'last_modified', parsed_vuln.get('updated_date'))
                setattr(vulnerability, 'vuln_status', parsed_vuln.get('state', 'PUBLISHED'))
                setattr(vulnerability, 'descriptions', [])
                setattr(vulnerability, 'metrics', None)
                setattr(vulnerability, 'weaknesses', [])
                setattr(vulnerability, 'configurations', [])
                setattr(vulnerability, 'references', parsed_vuln.get('references', []))
                setattr(vulnerability, 'vendor_comments', [])
                setattr(vulnerability, 'has_kev', False)
                setattr(vulnerability, 'has_cert_alerts', False)
                setattr(vulnerability, 'raw_cve_json5', cve_data)  # Сохраняем оригинальные данные
                
                # Сохраняем в БД
                if self.vulnerability_repo.save_vulnerability(vulnerability):
                    saved_count += 1
                
            except Exception as e:
                self.logger.error(f"❌ Ошибка обработки CVE: {e}")
                continue
        
        return saved_count

