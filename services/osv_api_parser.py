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
            
            # OSV API не поддерживает прямой запрос списка всех уязвимостей
            # Используем альтернативный подход: запрашиваем уязвимости по известным пакетам
            # или используем батч-запросы для получения последних CVE
            
            # Попробуем получить через батч-запросы популярных пакетов
            parsed_vulns = []
            
            # Популярные пакеты для запроса
            popular_packages = [
                {'name': 'linux', 'ecosystem': 'Debian'},
                {'name': 'openssl', 'ecosystem': 'Debian'},
                {'name': 'nginx', 'ecosystem': 'Debian'},
                {'name': 'python', 'ecosystem': 'PyPI'},
                {'name': 'node', 'ecosystem': 'npm'}
            ]
            
            for pkg in popular_packages[:min(5, limit // 20)]:
                try:
                    url = f"{self.base_url}/query"
                    payload = {
                        "package": pkg
                    }
                    
                    response = self.session.post(url, json=payload, timeout=30)
                    response.raise_for_status()
                    
                    data = response.json()
                    vulns = data.get('vulns', [])
                    
                    for vuln in vulns:
                        if len(parsed_vulns) >= limit:
                            break
                        try:
                            parsed_vuln = self._parse_vulnerability(vuln)
                            if parsed_vuln and parsed_vuln.get('cve_id', '').startswith('CVE-'):
                                # Проверяем, нет ли уже такой уязвимости
                                if not any(v.get('cve_id') == parsed_vuln.get('cve_id') for v in parsed_vulns):
                                    parsed_vulns.append(parsed_vuln)
                        except Exception as e:
                            logger.debug(f"Ошибка парсинга уязвимости OSV: {e}")
                            continue
                    
                    if len(parsed_vulns) >= limit:
                        break
                        
                except Exception as e:
                    logger.warning(f"Ошибка запроса OSV для пакета {pkg}: {e}")
                    continue
            
            logger.info(f"✅ Получено {len(parsed_vulns)} уязвимостей из OSV.dev API")
            return parsed_vulns[:limit]
            
        except Exception as e:
            logger.error(f"❌ Ошибка при запросе OSV API: {e}", exc_info=True)
            return []
    
    def _parse_vulnerability(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Парсинг одной уязвимости из OSV формата с полными данными"""
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
            
            # Если CVE нет, пропускаем (нам нужны только CVE)
            if not cve_id:
                return None
            
            # Извлекаем полное описание
            summary = vuln_data.get('summary', '')
            details = vuln_data.get('details', '')
            description = details if details else summary
            if not description:
                description = summary
            
            # Извлекаем дату публикации
            published = vuln_data.get('published')
            published_date = datetime.now()
            if published:
                try:
                    published_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                except:
                    try:
                        published_date = datetime.fromisoformat(published)
                    except:
                        published_date = datetime.now()
            
            # Извлекаем дату последнего изменения
            modified = vuln_data.get('modified')
            modified_date = published_date
            if modified:
                try:
                    modified_date = datetime.fromisoformat(modified.replace('Z', '+00:00'))
                except:
                    try:
                        modified_date = datetime.fromisoformat(modified)
                    except:
                        modified_date = published_date
            
            # Извлекаем severity и CVSS из database_specific
            severity = 'medium'
            cvss_score = 0.0
            cvss_v3_data = None
            
            # Пытаемся найти CVSS в database_specific
            db_specific = vuln_data.get('database_specific', {})
            if db_specific:
                cvss_v3_score = db_specific.get('cvss3_score') or db_specific.get('cvss_score')
                if cvss_v3_score:
                    cvss_score = float(cvss_v3_score)
                    if cvss_score >= 9.0:
                        severity = 'critical'
                    elif cvss_score >= 7.0:
                        severity = 'high'
                    elif cvss_score >= 4.0:
                        severity = 'medium'
                    else:
                        severity = 'low'
                
                # Извлекаем полные CVSS данные
                cvss_v3_data = db_specific.get('cvss_v3') or db_specific.get('cvss3')
            
            # Извлекаем severity из severity поля
            severity_field = vuln_data.get('severity', [])
            if isinstance(severity_field, list) and len(severity_field) > 0:
                first_severity = str(severity_field[0]).lower()
                if 'critical' in first_severity:
                    severity = 'critical'
                elif 'high' in first_severity:
                    severity = 'high'
                elif 'medium' in first_severity:
                    severity = 'medium'
                elif 'low' in first_severity:
                    severity = 'low'
            
            # Извлекаем ссылки с полной информацией
            references = []
            refs_data = vuln_data.get('references', [])
            for ref in refs_data:
                if isinstance(ref, dict):
                    references.append({
                        'url': str(ref.get('url', '')),
                        'description': str(ref.get('type', 'External reference'))
                    })
                elif isinstance(ref, str):
                    references.append({
                        'url': str(ref),
                        'description': 'External reference'
                    })
            
            # Извлекаем затронутые пакеты
            affected_packages = self._extract_affected_packages(vuln_data)
            
            # Извлекаем CWE
            cwe = None
            if 'database_specific' in vuln_data:
                cwe_list = db_specific.get('cwe_ids', [])
                if cwe_list and len(cwe_list) > 0:
                    cwe = str(cwe_list[0])
            
            # Формируем заголовок
            title = f"{cve_id}"
            if summary:
                title = f"{cve_id}: {summary[:100]}"
            
            return {
                'source': 'osv',
                'cve_id': cve_id,
                'title': title,
                'description': description or summary or f"Уязвимость {cve_id}",
                'severity': severity,
                'cvss_score': cvss_score,
                'cvss_v3': cvss_v3_data,
                'published_date': published_date.isoformat(),
                'modified_date': modified_date.isoformat(),
                'url': f"https://osv.dev/vulnerability/{vuln_id}",
                'references': references,
                'osv_id': vuln_id,
                'affected_packages': affected_packages,
                'cwe': cwe,
                'withdrawn': vuln_data.get('withdrawn', False)
            }
            
        except Exception as e:
            logger.error(f"Ошибка парсинга уязвимости OSV: {e}", exc_info=True)
            return None
    
    def _extract_affected_packages(self, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Извлечение затронутых пакетов с полной информацией"""
        packages = []
        try:
            affected = vuln_data.get('affected', [])
            for item in affected:
                if not isinstance(item, dict):
                    continue
                
                package = item.get('package', {})
                if package:
                    package_info = {
                        'name': str(package.get('name', '')),
                        'ecosystem': str(package.get('ecosystem', '')),
                        'purl': str(package.get('purl', ''))
                    }
                    
                    # Извлекаем диапазоны версий
                    ranges = item.get('ranges', [])
                    versions = item.get('versions', [])
                    
                    if ranges:
                        package_info['version_ranges'] = []
                        for range_item in ranges:
                            if isinstance(range_item, dict):
                                range_info = {
                                    'type': str(range_item.get('type', '')),
                                    'events': range_item.get('events', [])
                                }
                                package_info['version_ranges'].append(range_info)
                    
                    if versions:
                        package_info['affected_versions'] = [str(v) for v in versions]
                    
                    # Извлекаем информацию о исправлениях
                    database_specific = item.get('database_specific', {})
                    if database_specific:
                        package_info['database_specific'] = database_specific
                    
                    packages.append(package_info)
        except Exception as e:
            logger.debug(f"Ошибка извлечения пакетов OSV: {e}")
        return packages

