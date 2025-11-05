import requests
import json
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any
from config import Config
from models.database import DatabaseManager
from models.entities import Vulnerability
from models.postgres_repositories import PostgresVulnerabilityRepository

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RedHatCVEImporter:
    """Импортер CVE из Red Hat Security Data API"""

    def __init__(self):
        self.base_url = "https://access.redhat.com/hydra/rest/securitydata"
        self.db_manager = DatabaseManager()
        self.vuln_repo = PostgresVulnerabilityRepository(self.db_manager.connection)

    def fetch_cves(self, page: int = 1, per_page: int = 100,
                   severity: Optional[str] = None,
                   product: Optional[str] = None,
                   after_date: Optional[str] = None) -> List[Dict]:
        """
        Получить CVE из Red Hat API
        """
        try:
            params = {
                'page': page,
                'per_page': per_page
            }

            if severity:
                params['severity'] = severity
            if product:
                params['product'] = product
            if after_date:
                params['after'] = after_date

            logger.info(f"Fetching CVE from Red Hat API: page={page}, per_page={per_page}")

            response = requests.get(
                f"{self.base_url}/cve.json",
                params=params,
                timeout=30
            )
            response.raise_for_status()

            cves = response.json()
            logger.info(f"Retrieved {len(cves)} CVE entries")
            return cves

        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching CVE data: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return []

    def transform_redhat_to_nvd_format(self, redhat_cve: Dict) -> Dict:
        """
        Преобразовать формат Red Hat CVE в наш NVD-совместимый формат
        """
        try:
            cve_id = redhat_cve.get('CVE', '')

            # Базовые поля
            nvd_vuln = {
                'cve_id': cve_id,
                'source_identifier': 'redhat',
                'published': redhat_cve.get('public_date', ''),
                'last_modified': redhat_cve.get('updated_date', redhat_cve.get('public_date', '')),
                'vuln_status': 'Analyzed',
                'descriptions': [],
                'metrics': {},
                'weaknesses': [],
                'configurations': [],
                'references': [],
                'vendor_comments': [],
                'is_ai_related': False,
                'ai_confidence': 0.0,
                'has_kev': False,
                'has_cert_alerts': False
            }

            # Описания
            if 'bugzilla_description' in redhat_cve:
                nvd_vuln['descriptions'].append({
                    'lang': 'en',
                    'value': redhat_cve['bugzilla_description']
                })
            elif 'details' in redhat_cve and isinstance(redhat_cve['details'], list):
                for detail in redhat_cve['details']:
                    nvd_vuln['descriptions'].append({
                        'lang': 'en',
                        'value': detail
                    })

            # Метрики CVSS
            cvss_score = redhat_cve.get('cvss3_score') or redhat_cve.get('cvss_score', 0.0)
            cvss_severity = redhat_cve.get('cvss3_severity') or redhat_cve.get('severity', 'medium')

            if cvss_score:
                nvd_vuln['metrics'] = {
                    'cvss_v3': {
                        'version': '3.1',
                        'baseScore': float(cvss_score),
                        'baseSeverity': cvss_severity.capitalize() if cvss_severity else 'Medium'
                    }
                }

            # Ссылки
            if 'resource_url' in redhat_cve:
                nvd_vuln['references'].append({
                    'url': f"https://access.redhat.com{redhat_cve['resource_url']}",
                    'source': 'redhat'
                })

            # Добавляем ссылку на CVE
            nvd_vuln['references'].append({
                'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                'source': 'nvd'
            })

            # Пакеты/продукты
            packages = redhat_cve.get('affected_packages', [])
            if packages:
                nodes = []
                for pkg in packages:
                    nodes.append({
                        'operator': 'OR',
                        'cpe_match': [{
                            'vulnerable': True,
                            'cpe23Uri': f"cpe:2.3:a:redhat:{pkg}:*:*:*:*:*:*:*:*"
                        }]
                    })

                nvd_vuln['configurations'].append({
                    'nodes': nodes,
                    'operator': 'OR'
                })

            # Weaknesses (CWE)
            if 'cwe' in redhat_cve:
                nvd_vuln['weaknesses'].append({
                    'source': 'redhat',
                    'type': 'Primary',
                    'description': redhat_cve['cwe']
                })

            # Определяем AI-отношение
            description_text = ' '.join([desc['value'].lower() for desc in nvd_vuln['descriptions']])
            ai_keywords = ['ai', 'artificial intelligence', 'machine learning', 'neural network',
                           'deep learning', 'tensorflow', 'pytorch', 'keras', 'scikit-learn']

            nvd_vuln['is_ai_related'] = any(keyword in description_text for keyword in ai_keywords)
            if nvd_vuln['is_ai_related']:
                nvd_vuln['ai_confidence'] = 0.8

            logger.debug(f"Transformed CVE: {cve_id}")
            return nvd_vuln

        except Exception as e:
            logger.error(f"Error transforming CVE {redhat_cve.get('CVE', 'unknown')}: {e}")
            return {}

    def save_nvd_vulnerability(self, nvd_vuln: Dict) -> bool:
        """
        Сохранить NVD уязвимость в БД
        """
        try:
            # Создаем объект Vulnerability из NVD данных
            vulnerability = self._create_vulnerability_from_nvd(nvd_vuln)

            # Сохраняем через стандартный метод add
            return self.vuln_repo.add(vulnerability)

        except Exception as e:
            logger.error(f"Error saving NVD vulnerability {nvd_vuln.get('cve_id', 'unknown')}: {e}")
            return False

    def _create_vulnerability_from_nvd(self, nvd_vuln: Dict) -> Vulnerability:
        """
        Создать объект Vulnerability из NVD данных
        """
        # Получаем основное описание
        description = ""
        if nvd_vuln.get('descriptions'):
            for desc in nvd_vuln['descriptions']:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            if not description and nvd_vuln['descriptions']:
                description = nvd_vuln['descriptions'][0].get('value', '')

        # Определяем severity
        severity = 'medium'
        cvss_score = 0.0

        if nvd_vuln.get('metrics', {}).get('cvss_v3'):
            cvss_data = nvd_vuln['metrics']['cvss_v3']
            cvss_score = cvss_data.get('baseScore', 0.0)
            severity_str = cvss_data.get('baseSeverity', 'medium').lower()

            severity_map = {
                'critical': 'critical',
                'high': 'high',
                'medium': 'medium',
                'low': 'low'
            }
            severity = severity_map.get(severity_str, 'medium')

        # Создаем базовый объект Vulnerability без NVD полей
        vulnerability = Vulnerability(
            id=0,  # БД сама назначит ID
            title=nvd_vuln.get('cve_id', 'Unknown CVE'),
            description=description[:1000],  # Ограничиваем длину
            severity=severity,
            status='new',
            assigned_operator=None,
            created_date=datetime.now(),
            completed_date=None,
            approved=False,
            modifications=0,
            cvss_score=cvss_score,
            risk_level=severity,
            category='security'
        )

        # Добавляем NVD поля как атрибуты через setattr
        # Это обходит проблему с конструктором
        setattr(vulnerability, 'cve_id', nvd_vuln.get('cve_id'))
        setattr(vulnerability, 'source_identifier', nvd_vuln.get('source_identifier'))
        setattr(vulnerability, 'published', self._parse_date(nvd_vuln.get('published')))
        setattr(vulnerability, 'last_modified', self._parse_date(nvd_vuln.get('last_modified')))
        setattr(vulnerability, 'vuln_status', nvd_vuln.get('vuln_status'))
        setattr(vulnerability, 'descriptions', nvd_vuln.get('descriptions', []))
        setattr(vulnerability, 'metrics', nvd_vuln.get('metrics', {}))
        setattr(vulnerability, 'weaknesses', nvd_vuln.get('weaknesses', []))
        setattr(vulnerability, 'configurations', nvd_vuln.get('configurations', []))
        setattr(vulnerability, 'references', nvd_vuln.get('references', []))
        setattr(vulnerability, 'vendor_comments', nvd_vuln.get('vendor_comments', []))
        setattr(vulnerability, 'is_ai_related', nvd_vuln.get('is_ai_related', False))
        setattr(vulnerability, 'ai_confidence', nvd_vuln.get('ai_confidence', 0.0))
        setattr(vulnerability, 'has_kev', nvd_vuln.get('has_kev', False))
        setattr(vulnerability, 'has_cert_alerts', nvd_vuln.get('has_cert_alerts', False))

        return vulnerability

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Парсинг даты из строки"""
        if not date_str:
            return None

        try:
            # Убираем Z и парсим
            date_str = date_str.replace('Z', '+00:00')
            return datetime.fromisoformat(date_str)
        except (ValueError, TypeError):
            return None

    def check_cve_exists(self, cve_id: str) -> bool:
        """
        Проверить существует ли CVE в БД
        """
        try:
            # Проверяем напрямую через SQL запрос
            query = "SELECT 1 FROM vulnerabilities WHERE cve_id = %s LIMIT 1"
            with self.db_manager.connection.cursor() as cursor:
                cursor.execute(query, (cve_id,))
                return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Error checking if CVE {cve_id} exists: {e}")
            return False

    def import_cves(self, limit: Optional[int] = None, **filters) -> Dict[str, Any]:
        """
        Импортировать CVE из Red Hat API в БД
        """
        stats = {
            'total_fetched': 0,
            'successfully_saved': 0,
            'errors': 0,
            'skipped': 0
        }

        try:
            page = 1
            per_page = min(100, limit) if limit else 100

            while True:
                # Получаем CVE с API
                cves = self.fetch_cves(page=page, per_page=per_page, **filters)
                if not cves:
                    break

                stats['total_fetched'] += len(cves)

                # Обрабатываем каждый CVE
                for redhat_cve in cves:
                    try:
                        cve_id = redhat_cve.get('CVE', 'unknown')

                        # Проверяем, существует ли уже CVE
                        if self.check_cve_exists(cve_id):
                            logger.info(f"⚠️ CVE already exists: {cve_id}")
                            stats['skipped'] += 1
                            continue

                        # Преобразуем формат
                        nvd_vuln = self.transform_redhat_to_nvd_format(redhat_cve)
                        if not nvd_vuln:
                            stats['errors'] += 1
                            continue

                        # Сохраняем в БД
                        if self.save_nvd_vulnerability(nvd_vuln):
                            stats['successfully_saved'] += 1
                            logger.info(f"✅ CVE saved: {nvd_vuln['cve_id']}")
                        else:
                            stats['errors'] += 1
                            logger.error(f"❌ Failed to save: {nvd_vuln['cve_id']}")

                    except Exception as e:
                        logger.error(f"Error processing CVE {redhat_cve.get('CVE', 'unknown')}: {e}")
                        stats['errors'] += 1

                # Проверяем лимит
                if limit and stats['total_fetched'] >= limit:
                    break

                # Переходим на следующую страницу
                page += 1

                # Небольшая задержка чтобы не перегружать API
                import time
                time.sleep(0.5)

            logger.info(f"Import completed: {stats}")
            return stats

        except Exception as e:
            logger.error(f"Error during import: {e}")
            stats['errors'] += 1
            return stats

    def import_recent_cves(self, days: int = 7) -> Dict[str, Any]:
        """
        Импортировать недавние CVE
        """
        from datetime import datetime, timedelta

        after_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
        logger.info(f"Importing CVE from last {days} days (after {after_date})")

        return self.import_cves(after_date=after_date, severity='important,critical')

    def import_by_severity(self, severity: str, limit: int = 50) -> Dict[str, Any]:
        """
        Импортировать CVE по severity
        """
        logger.info(f"Importing {limit} CVE with severity: {severity}")
        return self.import_cves(severity=severity, limit=limit)


def main():
    """Основная функция для запуска импорта"""
    import argparse

    parser = argparse.ArgumentParser(description='Import CVE from Red Hat Security Data API')
    parser.add_argument('--limit', type=int, default=5, help='Maximum number of CVE to import')
    parser.add_argument('--severity', type=str, choices=['critical', 'important', 'moderate', 'low'],
                        help='Filter by severity')
    parser.add_argument('--recent', type=int, help='Import CVE from last N days')
    parser.add_argument('--product', type=str, help='Filter by product (e.g., "Red Hat Enterprise Linux 8")')

    args = parser.parse_args()

    importer = RedHatCVEImporter()

    try:
        if args.recent:
            stats = importer.import_recent_cves(days=args.recent)
        else:
            filters = {}
            if args.severity:
                filters['severity'] = args.severity
            if args.product:
                filters['product'] = args.product

            stats = importer.import_cves(limit=args.limit, **filters)

        # Вывод результатов
        print("\n" + "=" * 50)
        print("IMPORT RESULTS")
        print("=" * 50)
        print(f"Total fetched from API: {stats['total_fetched']}")
        print(f"Successfully saved: {stats['successfully_saved']}")
        print(f"Errors: {stats['errors']}")
        print(f"Skipped (already exists): {stats['skipped']}")

    except Exception as e:
        logger.error(f"Import failed: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())