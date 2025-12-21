"""
OSV.dev API парсер
Использует официальный API: https://google.github.io/osv.dev/get-v1-vulns/
"""
import logging
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class OSVAPIParser:
    """Парсер уязвимостей из OSV.dev через API"""
    
    def __init__(self):
        self.base_url = "https://api.osv.dev/v1"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; VulnerabilityParser/1.0)'
        })
    
    def query_vulnerabilities(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Получить список уязвимостей через OSV API
        
        Args:
            limit: Максимальное количество уязвимостей
            
        Returns:
            Список словарей с данными об уязвимостях
        """
        try:
            logger.info(f"🔍 Запрос уязвимостей из OSV.dev API (лимит: {limit})")
            
            # OSV API query endpoint
            url = f"{self.base_url}/query"
            
            # Запрашиваем последние уязвимости
            # OSV API работает через POST запрос с query
            payload = {
                "page_token": "",
                "page_size": min(limit, 1000)  # Максимум 1000 за раз
            }
            
            response = self.session.post(url, json=payload, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            vulns = data.get('vulns', [])
            
            logger.info(f"✅ Получено {len(vulns)} уязвимостей из OSV.dev API")
            
            # Преобразуем в унифицированный формат
            parsed_vulns = []
            for vuln in vulns[:limit]:
                try:
                    parsed_vuln = self._parse_vulnerability(vuln)
                    if parsed_vuln:
                        parsed_vulns.append(parsed_vuln)
                except Exception as e:
                    logger.warning(f"Ошибка парсинга уязвимости OSV: {e}")
                    continue
            
            return parsed_vulns
            
        except Exception as e:
            logger.error(f"❌ Ошибка при запросе OSV API: {e}", exc_info=True)
            return []
    
    def _parse_vulnerability(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Парсинг одной уязвимости из OSV формата"""
        try:
            # Извлекаем основные данные
            vuln_id = vuln_data.get('id', '')
            
            # Ищем CVE ID
            cve_id = None
            if vuln_id.startswith('CVE-'):
                cve_id = vuln_id
            else:
                # Ищем CVE в aliases
                aliases = vuln_data.get('aliases', [])
                for alias in aliases:
                    if alias.startswith('CVE-'):
                        cve_id = alias
                        break
            
            # Если CVE нет, используем OSV ID
            if not cve_id:
                cve_id = vuln_id
            
            # Извлекаем описание
            summary = vuln_data.get('summary', '')
            details = vuln_data.get('details', '')
            description = details if details else summary
            
            # Извлекаем дату публикации
            published = vuln_data.get('published')
            if published:
                try:
                    published_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                except:
                    published_date = datetime.now()
            else:
                published_date = datetime.now()
            
            # Извлекаем severity из database_specific или используем default
            severity = 'medium'
            cvss_score = 0.0
            
            # Пытаемся найти CVSS в database_specific
            db_specific = vuln_data.get('database_specific', {})
            if db_specific:
                cvss_v3 = db_specific.get('cvss3_score', 0.0)
                if cvss_v3:
                    cvss_score = float(cvss_v3)
                    if cvss_score >= 9.0:
                        severity = 'critical'
                    elif cvss_score >= 7.0:
                        severity = 'high'
                    elif cvss_score >= 4.0:
                        severity = 'medium'
                    else:
                        severity = 'low'
            
            # Извлекаем ссылки
            references = vuln_data.get('references', [])
            links = [ref.get('url', '') for ref in references if ref.get('url')]
            
            return {
                'source': 'osv',
                'cve_id': cve_id,
                'title': f"OSV: {vuln_id}" + (f" ({cve_id})" if cve_id != vuln_id else ""),
                'description': description or summary or f"Уязвимость {vuln_id}",
                'severity': severity,
                'cvss_score': cvss_score,
                'published_date': published_date.isoformat(),
                'url': f"https://osv.dev/vulnerability/{vuln_id}",
                'references': links,
                'osv_id': vuln_id,
                'affected_packages': self._extract_affected_packages(vuln_data)
            }
            
        except Exception as e:
            logger.error(f"Ошибка парсинга уязвимости OSV: {e}", exc_info=True)
            return None
    
    def _extract_affected_packages(self, vuln_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Извлечение затронутых пакетов"""
        packages = []
        try:
            affected = vuln_data.get('affected', [])
            for item in affected:
                package = item.get('package', {})
                if package:
                    packages.append({
                        'name': package.get('name', ''),
                        'ecosystem': package.get('ecosystem', ''),
                        'purl': package.get('purl', '')
                    })
        except:
            pass
        return packages

