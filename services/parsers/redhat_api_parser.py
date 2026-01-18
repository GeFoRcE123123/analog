"""
Парсер Red Hat CVE через API
Основан на коде из Jupyter ноутбука (ml_backup/training_history)
"""
import requests
import json
import logging
import time
import sys
import os
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any
from queue import Queue
from contextlib import contextmanager

# Добавляем путь к корню проекта
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from config import Config
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from models.entities import Vulnerability
import psycopg

logger = logging.getLogger(__name__)


class ConnectionPool:
    """
    Простой connection pool для psycopg3
    """
    def __init__(self, minconn=2, maxconn=10):
        self.minconn = minconn
        self.maxconn = maxconn
        self._pool = Queue(maxsize=maxconn)
        self._created = 0
        self._lock = threading.Lock()
        self.db_config = Config.DATABASE_CONFIG
        self._initialize_pool()
    
    def _create_connection(self):
        """Создать новое соединение"""
        return psycopg.connect(
            host=self.db_config.host,
            port=self.db_config.port,
            dbname=self.db_config.database,
            user=self.db_config.username,
            password=self.db_config.password
        )
    
    def _initialize_pool(self):
        """Инициализировать пул минимальным количеством соединений"""
        for _ in range(self.minconn):
            conn = self._create_connection()
            self._pool.put(conn)
            self._created += 1
    
    @contextmanager
    def get_connection(self):
        """Получить соединение из пула (context manager)"""
        conn = None
        try:
            # Пытаемся получить из пула
            try:
                conn = self._pool.get_nowait()
            except:
                # Если пул пуст, создаем новое соединение (если не превышен лимит)
                with self._lock:
                    if self._created < self.maxconn:
                        conn = self._create_connection()
                        self._created += 1
                    else:
                        # Ждем освобождения соединения
                        conn = self._pool.get(timeout=30)
            
            # Проверяем, что соединение живое
            if conn.closed:
                conn = self._create_connection()
            
            yield conn
        finally:
            # Возвращаем соединение в пул
            if conn and not conn.closed:
                try:
                    self._pool.put_nowait(conn)
                except:
                    # Если пул полон, закрываем соединение
                    conn.close()
                    with self._lock:
                        self._created -= 1
    
    def close_all(self):
        """Закрыть все соединения в пуле"""
        while not self._pool.empty():
            try:
                conn = self._pool.get_nowait()
                if not conn.closed:
                    conn.close()
            except:
                pass


class RedHatAPIParser:
    """
    Парсер уязвимостей Red Hat через официальный API
    https://access.redhat.com/hydra/rest/securitydata/cve.json
    
    Улучшения:
    - Connection pooling для параллельных операций
    - Retry логика для временных ошибок БД
    - Батчинг сохранений для производительности
    """
    
    def __init__(self, pool_size=5):
        self.base_url = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
        self.logger = logging.getLogger(__name__)
        
        # Connection pooling
        self._pool = ConnectionPool(minconn=2, maxconn=pool_size)
        self._pool_lock = threading.Lock()
        
        # Батчинг
        self._batch_size = 50
        self._batch_lock = threading.Lock()
    
    def _retry_db_operation(self, operation, max_retries=3, base_delay=1.0):
        """
        Retry логика для операций с БД с exponential backoff
        
        Args:
            operation: Функция для выполнения
            max_retries: Максимальное количество попыток
            base_delay: Базовая задержка в секундах
            
        Returns:
            Результат операции или None при ошибке
        """
        for attempt in range(max_retries):
            try:
                return operation()
            except Exception as e:
                error_msg = str(e).lower()
                
                # Проверяем, стоит ли повторять
                retryable_errors = [
                    'connection', 'timeout', 'network', 'temporary',
                    'another command is already in progress',
                    'server closed the connection'
                ]
                
                is_retryable = any(err in error_msg for err in retryable_errors)
                
                if not is_retryable or attempt == max_retries - 1:
                    # Не повторяем или последняя попытка
                    self.logger.debug(f"Операция не удалась после {attempt + 1} попыток: {e}")
                    return None
                
                # Exponential backoff
                delay = base_delay * (2 ** attempt)
                self.logger.debug(f"Повторная попытка {attempt + 1}/{max_retries} через {delay:.2f}с: {e}")
                time.sleep(delay)
        
        return None
    
    def fetch_page(self, page: int = 1, per_page: int = 1000) -> List[Dict]:
        """
        Получить одну страницу CVE из Red Hat API
        
        Args:
            page: Номер страницы
            per_page: Количество записей на странице (макс 1000)
            
        Returns:
            Список CVE записей
        """
        try:
            url = f"{self.base_url}?per_page={per_page}&page={page}&isCompressed=false"
            self.logger.info(f"📡 Запрос к Red Hat API: page={page}, per_page={per_page}")
            
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            self.logger.info(f"✅ Получено {len(data)} CVE записей со страницы {page}")
            return data
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"❌ Ошибка запроса к Red Hat API (page={page}): {e}")
            return []
        except Exception as e:
            self.logger.error(f"❌ Неожиданная ошибка при получении страницы {page}: {e}")
            return []
    
    def fetch_all_pages(self, max_pages: Optional[int] = None, delay: float = 1.0) -> List[Dict]:
        """
        Получить все страницы CVE из Red Hat API
        
        Args:
            max_pages: Максимальное количество страниц (None = все)
            delay: Задержка между запросами (секунды)
            
        Returns:
            Список всех CVE записей
        """
        all_cves = []
        page = 1
        
        while True:
            if max_pages and page > max_pages:
                break
            
            cves = self.fetch_page(page=page, per_page=1000)
            
            if not cves:
                self.logger.info(f"📄 Страница {page} пуста, завершаем парсинг")
                break
            
            all_cves.extend(cves)
            self.logger.info(f"📊 Всего собрано: {len(all_cves)} CVE")
            
            # Уважаем API - делаем паузу
            if delay > 0:
                time.sleep(delay)
            
            page += 1
        
        return all_cves
    
    def transform_to_vulnerability(self, redhat_cve: Dict) -> Optional[Vulnerability]:
        """
        Преобразовать Red Hat CVE в объект Vulnerability
        
        Args:
            redhat_cve: Словарь с данными CVE из Red Hat API
            
        Returns:
            Объект Vulnerability или None
        """
        try:
            cve_id = redhat_cve.get('CVE', '').strip()
            if not cve_id:
                self.logger.warning("⚠️ CVE без идентификатора, пропускаем")
                return None
            
            # Описание
            description = redhat_cve.get('bugzilla_description', '') or ''
            if not description and redhat_cve.get('details'):
                if isinstance(redhat_cve['details'], list):
                    description = ' '.join(redhat_cve['details'])
                else:
                    description = str(redhat_cve['details'])
            
            # CVSS score и метрики
            cvss_score = 0.0
            cvss_v3_vector = None
            cvss_v2_vector = None
            cvss_v4_vector = None
            cvss_version = None
            cvss_v3_metrics = None
            cvss_v2_metrics = None
            cvss_v4_metrics = None
            
            # CVSS v3 (приоритет)
            if redhat_cve.get('cvss3_score'):
                try:
                    cvss_score = float(redhat_cve['cvss3_score'])
                    cvss_version = '3.1'
                    cvss_v3_vector = redhat_cve.get('cvss3_scoring_vector')
                    
                    # Создаем структуру метрик CVSS v3
                    if cvss_v3_vector:
                        cvss_v3_metrics = {
                            'version': '3.1',
                            'vectorString': cvss_v3_vector,
                            'baseScore': cvss_score,
                            'baseSeverity': redhat_cve.get('severity', 'medium').lower()
                        }
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Ошибка парсинга CVSS v3 для {cve_id}: {e}")
            
            # CVSS v2 (fallback)
            elif redhat_cve.get('cvss_score'):
                try:
                    cvss_score = float(redhat_cve['cvss_score'])
                    cvss_version = '2.0'
                    cvss_v2_vector = redhat_cve.get('cvss_scoring_vector')
                    
                    # Создаем структуру метрик CVSS v2
                    if cvss_v2_vector:
                        cvss_v2_metrics = {
                            'version': '2.0',
                            'vectorString': cvss_v2_vector,
                            'baseScore': cvss_score
                        }
                except (ValueError, TypeError) as e:
                    self.logger.debug(f"Ошибка парсинга CVSS v2 для {cve_id}: {e}")
            
            # Severity (обработка None)
            severity_raw = redhat_cve.get('severity', 'medium')
            if severity_raw is None:
                severity_raw = 'medium'
            severity = str(severity_raw).lower()
            severity_map = {
                'critical': 'critical',
                'important': 'high',
                'moderate': 'medium',
                'low': 'low'
            }
            severity = severity_map.get(severity, 'medium')
            
            # Дата публикации
            published_date = None
            if redhat_cve.get('public_date'):
                try:
                    date_str = redhat_cve['public_date'].replace('Z', '+00:00')
                    published_date = datetime.fromisoformat(date_str)
                except (ValueError, TypeError):
                    pass
            
            # Создаем объект Vulnerability
            vulnerability = Vulnerability(
                id=0,  # БД сама назначит ID
                title=f"Red Hat: {cve_id}",
                description=description[:1000] if description else f"Security vulnerability {cve_id}",
                severity=severity,
                status='new',
                assigned_operator=None,
                created_date=published_date or datetime.now(),
                completed_date=None,
                approved=False,
                modifications=0,
                cvss_score=cvss_score,
                risk_level=severity,
                category='security'
            )
            
            # Добавляем дополнительные поля через setattr
            setattr(vulnerability, 'cve_id', cve_id)
            setattr(vulnerability, 'source_identifier', 'redhat')
            setattr(vulnerability, 'published', published_date)
            setattr(vulnerability, 'last_modified', published_date)
            
            # CVSS векторы и метрики
            if cvss_v3_vector:
                setattr(vulnerability, 'cvss_v3_vector', cvss_v3_vector)
            if cvss_v2_vector:
                setattr(vulnerability, 'cvss_v2_vector', cvss_v2_vector)
            if cvss_v4_vector:
                setattr(vulnerability, 'cvss_v4_vector', cvss_v4_vector)
            if cvss_version:
                setattr(vulnerability, 'cvss_version', cvss_version)
            
            # CVSS метрики (для сохранения в nvd_metrics и cvss_v3_metrics)
            metrics = {}
            if cvss_v3_metrics:
                metrics['cvss_v3'] = cvss_v3_metrics
                setattr(vulnerability, 'cvss_v3_metrics', cvss_v3_metrics)
            if cvss_v2_metrics:
                metrics['cvss_v2'] = cvss_v2_metrics
                setattr(vulnerability, 'cvss_v2_metrics', cvss_v2_metrics)
            if cvss_v4_metrics:
                metrics['cvss_v4'] = cvss_v4_metrics
                setattr(vulnerability, 'cvss_v4_metrics', cvss_v4_metrics)
            
            if metrics:
                setattr(vulnerability, 'metrics', metrics)
            
            # CWE
            if redhat_cve.get('CWE'):
                cwe_list = [redhat_cve['CWE']] if isinstance(redhat_cve['CWE'], str) else redhat_cve['CWE']
                setattr(vulnerability, 'cwe_ids', cwe_list)
            
            # Affected packages
            if redhat_cve.get('affected_packages'):
                setattr(vulnerability, 'affected_packages', redhat_cve['affected_packages'])
            
            # References
            references = []
            if redhat_cve.get('resource_url'):
                references.append({
                    'url': f"https://access.redhat.com{redhat_cve['resource_url']}",
                    'source': 'redhat'
                })
            references.append({
                'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                'source': 'nvd'
            })
            setattr(vulnerability, 'references', references)
            
            # NVD descriptions (для legacy схемы)
            nvd_descriptions = []
            if description:
                nvd_descriptions.append({
                    'lang': 'en',
                    'value': description
                })
            setattr(vulnerability, 'nvd_descriptions', nvd_descriptions)
            
            return vulnerability
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка преобразования CVE {redhat_cve.get('CVE', 'unknown')}: {e}", exc_info=True)
            return None
    
    def check_exists(self, cve_id: str) -> bool:
        """
        Проверить, существует ли CVE в БД (с connection pooling и retry)
        
        Args:
            cve_id: Идентификатор CVE
            
        Returns:
            True если существует, False иначе
        """
        def _check():
            with self._pool.get_connection() as conn:
                if Config.USE_LEGACY_SCHEMA:
                    query = "SELECT 1 FROM turn WHERE cve = %s LIMIT 1"
                else:
                    query = "SELECT 1 FROM vulnerabilities WHERE cve_id = %s LIMIT 1"
                
                with conn.cursor() as cursor:
                    cursor.execute(query, (cve_id,))
                    return cursor.fetchone() is not None
        
        result = self._retry_db_operation(_check, max_retries=3)
        return result if result is not None else False
    
    def save_vulnerability(self, vulnerability: Vulnerability) -> bool:
        """
        Сохранить уязвимость в БД (с connection pooling и retry)
        
        Args:
            vulnerability: Объект Vulnerability
            
        Returns:
            True если успешно, False иначе
        """
        def _save():
            with self._pool.get_connection() as conn:
                if Config.USE_LEGACY_SCHEMA:
                    repo = LegacyVulnerabilityRepository(conn)
                    return repo.save_vulnerability(vulnerability)
                else:
                    from models.postgres_repositories import PostgresVulnerabilityRepository
                    repo = PostgresVulnerabilityRepository(conn)
                    return repo.add(vulnerability) is not None
        
        result = self._retry_db_operation(_save, max_retries=3)
        
        if result is None:
            cve_id = getattr(vulnerability, 'cve_id', 'unknown')
            self.logger.debug(f"⚠️ Не удалось сохранить CVE {cve_id} после retry")
            return False
        
        return result
    
    def save_vulnerabilities_batch(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """
        Сохранить уязвимости батчем (для производительности)
        
        Args:
            vulnerabilities: Список объектов Vulnerability
            
        Returns:
            Dict со статистикой: {'saved': int, 'skipped': int, 'errors': int}
        """
        if not vulnerabilities:
            return {'saved': 0, 'skipped': 0, 'errors': 0}
        
        stats = {'saved': 0, 'skipped': 0, 'errors': 0}
        
        def _save_batch():
            with self._pool.get_connection() as conn:
                try:
                    if Config.USE_LEGACY_SCHEMA:
                        repo = LegacyVulnerabilityRepository(conn)
                        saved = 0
                        for vuln in vulnerabilities:
                            try:
                                if repo.save_vulnerability(vuln):
                                    saved += 1
                            except Exception as e:
                                error_msg = str(e).lower()
                                if 'duplicate' in error_msg or 'unique' in error_msg:
                                    stats['skipped'] += 1
                                else:
                                    stats['errors'] += 1
                        stats['saved'] = saved
                        conn.commit()
                        return True
                    else:
                        from models.postgres_repositories import PostgresVulnerabilityRepository
                        repo = PostgresVulnerabilityRepository(conn)
                        saved = 0
                        for vuln in vulnerabilities:
                            try:
                                if repo.add(vuln) is not None:
                                    saved += 1
                            except Exception as e:
                                error_msg = str(e).lower()
                                if 'duplicate' in error_msg or 'unique' in error_msg:
                                    stats['skipped'] += 1
                                else:
                                    stats['errors'] += 1
                        stats['saved'] = saved
                        conn.commit()
                        return True
                except Exception as e:
                    conn.rollback()
                    raise e
        
        result = self._retry_db_operation(_save_batch, max_retries=3)
        
        if result is None:
            # Если батч не сохранился, пробуем по одному
            self.logger.warning(f"Батч не сохранился, пробуем по одному ({len(vulnerabilities)} CVE)")
            for vuln in vulnerabilities:
                if self.save_vulnerability(vuln):
                    stats['saved'] += 1
                else:
                    stats['skipped'] += 1
        
        return stats
    
    def parse_and_save(self, limit: Optional[int] = None, max_pages: Optional[int] = None) -> Dict[str, Any]:
        """
        Парсить и сохранить CVE из Red Hat API
        
        Args:
            limit: Максимальное количество CVE для сохранения
            max_pages: Максимальное количество страниц для парсинга
            
        Returns:
            Словарь со статистикой
        """
        stats = {
            'total_fetched': 0,
            'total_saved': 0,
            'total_skipped': 0,
            'total_errors': 0,
            'start_time': datetime.now().isoformat(),
            'end_time': None
        }
        
        try:
            self.logger.info(f"🚀 Начинаем парсинг Red Hat CVE (limit={limit}, max_pages={max_pages})")
            
            # Получаем CVE
            if max_pages:
                all_cves = []
                for page in range(1, max_pages + 1):
                    cves = self.fetch_page(page=page, per_page=1000)
                    if not cves:
                        break
                    all_cves.extend(cves)
                    if limit and len(all_cves) >= limit:
                        all_cves = all_cves[:limit]
                        break
                    time.sleep(1)  # Задержка между страницами
            else:
                # Получаем только первую страницу для теста
                all_cves = self.fetch_page(page=1, per_page=limit or 100)
            
            stats['total_fetched'] = len(all_cves)
            self.logger.info(f"📊 Получено {len(all_cves)} CVE из API")
            
            # Батчинг: обрабатываем CVE батчами для производительности
            batch = []
            processed = 0
            
            for idx, redhat_cve in enumerate(all_cves, 1):
                try:
                    cve_id = redhat_cve.get('CVE', '').strip()
                    if not cve_id:
                        stats['total_errors'] += 1
                        continue
                    
                    # Проверяем существование (с connection pooling и retry)
                    if self.check_exists(cve_id):
                        stats['total_skipped'] += 1
                        continue
                    
                    # Преобразуем
                    vulnerability = self.transform_to_vulnerability(redhat_cve)
                    if not vulnerability:
                        stats['total_errors'] += 1
                        continue
                    
                    # Добавляем в батч
                    batch.append(vulnerability)
                    
                    # Сохраняем батч когда он заполнен
                    if len(batch) >= self._batch_size:
                        batch_stats = self.save_vulnerabilities_batch(batch)
                        stats['total_saved'] += batch_stats['saved']
                        stats['total_skipped'] += batch_stats['skipped']
                        stats['total_errors'] += batch_stats['errors']
                        processed += len(batch)
                        
                        if processed % 500 == 0:
                            self.logger.info(f"✅ Обработано {processed}/{len(all_cves)} CVE (сохранено: {stats['total_saved']})")
                        
                        batch = []  # Очищаем батч
                    
                except Exception as e:
                    self.logger.debug(f"❌ Ошибка обработки CVE {redhat_cve.get('CVE', 'unknown')}: {e}")
                    stats['total_errors'] += 1
            
            # Сохраняем оставшиеся CVE в батче
            if batch:
                batch_stats = self.save_vulnerabilities_batch(batch)
                stats['total_saved'] += batch_stats['saved']
                stats['total_skipped'] += batch_stats['skipped']
                stats['total_errors'] += batch_stats['errors']
            
            stats['end_time'] = datetime.now().isoformat()
            duration = (datetime.fromisoformat(stats['end_time']) - 
                       datetime.fromisoformat(stats['start_time'])).total_seconds()
            
            # Закрываем пул соединений
            try:
                self._pool.close_all()
            except:
                pass
            
            success_rate = ((stats['total_saved'] + stats['total_skipped']) / stats['total_fetched'] * 100) if stats['total_fetched'] > 0 else 0
            
            self.logger.info(f"""
✅ Парсинг Red Hat завершен:
   Получено: {stats['total_fetched']}
   Сохранено: {stats['total_saved']}
   Пропущено: {stats['total_skipped']}
   Ошибок: {stats['total_errors']}
   Успешно: {success_rate:.1f}%
   Время: {duration:.2f} сек ({duration/60:.2f} мин)
   Скорость: {stats['total_fetched']/duration:.1f} CVE/сек
""")
            
            return stats
            
        except Exception as e:
            self.logger.error(f"❌ Критическая ошибка парсинга Red Hat: {e}", exc_info=True)
            stats['end_time'] = datetime.now().isoformat()
            stats['error'] = str(e)
            
            # Закрываем пул при ошибке
            try:
                self._pool.close_all()
            except:
                pass
            
            return stats
    
    def __del__(self):
        """Закрыть пул соединений при удалении объекта"""
        try:
            if hasattr(self, '_pool'):
                self._pool.close_all()
        except:
            pass


def main():
    """Тестовая функция"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Red Hat CVE Parser')
    parser.add_argument('--limit', type=int, default=10, help='Количество CVE для парсинга')
    parser.add_argument('--pages', type=int, help='Максимальное количество страниц')
    
    args = parser.parse_args()
    
    redhat_parser = RedHatAPIParser()
    stats = redhat_parser.parse_and_save(limit=args.limit, max_pages=args.pages)
    
    print("\n" + "=" * 50)
    print("РЕЗУЛЬТАТЫ ПАРСИНГА RED HAT")
    print("=" * 50)
    print(f"Получено из API: {stats['total_fetched']}")
    print(f"Сохранено в БД: {stats['total_saved']}")
    print(f"Пропущено (дубликаты): {stats['total_skipped']}")
    print(f"Ошибок: {stats['total_errors']}")
    if 'error' in stats:
        print(f"Критическая ошибка: {stats['error']}")
    print("=" * 50)
    
    return 0 if stats['total_saved'] > 0 else 1


if __name__ == "__main__":
    exit(main())

