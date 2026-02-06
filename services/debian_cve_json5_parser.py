"""
Debian парсер с поддержкой официального формата CVE JSON 5.x
Интегрирует данные из Debian Security Tracker в формат CVE JSON 5.x
"""
import logging
import json
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
from bs4 import BeautifulSoup
import re

from services.cve_json5_adapter import cve_json5_adapter
from schema.cve_json5.validators.cve_json5_validator import cve_json5_validator

logger = logging.getLogger(__name__)


class DebianCVEJSON5Parser:
    """
    Парсер Debian CVE с преобразованием в официальный формат CVE JSON 5.x
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.base_url = "https://security-tracker.debian.org/tracker"
        self.api_url = "https://security-tracker.debian.org/tracker/data/json"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Vulnerability-Manager/1.0 (Debian CVE Parser)'
        })
        self.timeout = 60
    
    def parse_debian_cve_to_json5(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Парсинг Debian CVE и преобразование в формат CVE JSON 5.x
        
        Args:
            cve_id: CVE ID (например, CVE-2024-1234)
            
        Returns:
            CVE запись в формате JSON 5.x или None при ошибке
        """
        try:
            # Получаем данные из Debian API
            debian_data = self._fetch_debian_data(cve_id)
            if not debian_data:
                return None
            
            # Преобразуем в CVE JSON 5.x формат
            cve_json5 = self._convert_to_cve_json5(cve_id, debian_data)
            
            # Валидируем результат
            is_valid, errors = cve_json5_validator.validate(cve_json5)
            if not is_valid:
                self.logger.warning(f"⚠️ CVE {cve_id} не прошла валидацию: {errors}")
                # Продолжаем, но логируем ошибки
            
            return cve_json5
            
        except Exception as e:
            self.logger.error(f"❌ Ошибка парсинга Debian CVE {cve_id}: {e}", exc_info=True)
            return None
    
    def _fetch_debian_data(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Получение данных о CVE из Debian Security Tracker
        
        Args:
            cve_id: CVE ID
            
        Returns:
            Dict с данными Debian или None
        """
        try:
            # Пробуем получить из API
            response = self.session.get(self.api_url, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            
            if isinstance(data, dict) and cve_id in data:
                return data[cve_id]
            
            # Если не найдено в API, пробуем HTML парсинг
            return self._fetch_from_html(cve_id)
            
        except Exception as e:
            self.logger.debug(f"Ошибка получения данных из Debian API для {cve_id}: {e}")
            return self._fetch_from_html(cve_id)
    
    def _fetch_from_html(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Получение данных из HTML страницы Debian
        
        Args:
            cve_id: CVE ID
            
        Returns:
            Dict с данными или None
        """
        try:
            url = f"{self.base_url}/{cve_id}"
            response = self.session.get(url, timeout=30)
            
            if response.status_code == 404:
                self.logger.debug(f"⚠️ CVE {cve_id} не найден на Debian tracker (404)")
                return None
            
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Извлекаем данные из HTML
            data = {
                'cve_id': cve_id,
                'description': self._extract_description(soup),
                'severity': self._extract_severity(soup),
                'packages': self._extract_packages(soup),
                'references': self._extract_references(soup),
                'url': url
            }
            
            return data
            
        except Exception as e:
            self.logger.debug(f"Ошибка HTML парсинга для {cve_id}: {e}")
            return None
    
    def _extract_description(self, soup: BeautifulSoup) -> str:
        """Извлечение описания из HTML"""
        try:
            # Способ 1: Ищем элемент с текстом "Description"
            desc_elem = soup.find('td', string=re.compile(r'Description', re.I))
            if desc_elem:
                desc_content = desc_elem.find_next('td')
                if desc_content:
                    desc_text = desc_content.get_text(strip=True)
                    if desc_text and len(desc_text) > 10:
                        return desc_text
            
            # Способ 2: Ищем в тексте страницы
            page_text = str(soup.get_text())
            desc_match = re.search(r'Description\s*:?\s*(.+?)(?:\n\s*\n|\Z)', page_text, re.I | re.S)
            if desc_match:
                desc_text = desc_match.group(1).strip()
                desc_text = re.sub(r'\s+', ' ', desc_text)
                if desc_text and len(desc_text) > 10:
                    return desc_text
        except Exception as e:
            self.logger.debug(f"Ошибка извлечения описания: {e}")
        
        return ""
    
    def _extract_severity(self, soup: BeautifulSoup) -> str:
        """Извлечение уровня серьезности"""
        try:
            page_text = str(soup.get_text()).lower()
            if 'critical' in page_text:
                return 'critical'
            elif 'high' in page_text:
                return 'high'
            elif 'medium' in page_text or 'moderate' in page_text:
                return 'medium'
            elif 'low' in page_text:
                return 'low'
        except:
            pass
        return 'medium'
    
    def _extract_packages(self, soup: BeautifulSoup) -> List[Dict[str, Any]]:
        """Извлечение затронутых пакетов"""
        packages = []
        try:
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows[1:]:  # Пропускаем заголовок
                    cells = row.find_all(['td', 'th'])
                    if len(cells) >= 3:
                        package_info = {
                            'name': cells[0].get_text(strip=True) if cells[0] else '',
                            'release': cells[1].get_text(strip=True) if len(cells) > 1 else '',
                            'status': cells[2].get_text(strip=True) if len(cells) > 2 else ''
                        }
                        if package_info['name']:
                            packages.append(package_info)
        except Exception as e:
            self.logger.debug(f"Ошибка извлечения пакетов: {e}")
        return packages
    
    def _extract_references(self, soup: BeautifulSoup) -> List[Dict[str, str]]:
        """Извлечение ссылок"""
        references = []
        try:
            links = soup.find_all('a', href=True)
            for link in links:
                href = link.get('href', '')
                text = link.get_text(strip=True)
                if href and href.startswith('http'):
                    references.append({
                        'url': href,
                        'name': text or 'External reference'
                    })
        except Exception as e:
            self.logger.debug(f"Ошибка извлечения ссылок: {e}")
        return references
    
    def _convert_to_cve_json5(self, cve_id: str, debian_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Преобразование данных Debian в формат CVE JSON 5.x
        
        Args:
            cve_id: CVE ID
            debian_data: Данные из Debian Security Tracker
            
        Returns:
            CVE запись в формате JSON 5.x
        """
        # Извлекаем компоненты CVE ID
        cve_parts = cve_id.split('-')
        year = cve_parts[1] if len(cve_parts) > 1 else datetime.now().year
        
        # Формируем CVE JSON 5.x структуру
        cve_json5 = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.2",
            "cveMetadata": {
                "cveId": cve_id,
                "assignerOrgId": "00000000-0000-0000-0000-000000000000",  # Debian CNA ID (нужно получить реальный)
                "state": "PUBLISHED"
            },
            "containers": {
                "cna": {
                    "providerMetadata": {
                        "orgId": "00000000-0000-0000-0000-000000000000",  # Debian CNA ID
                        "shortName": "debian"
                    },
                    "descriptions": [],
                    "affected": [],
                    "references": []
                }
            }
        }
        
        # Описания
        description = debian_data.get('description', '')
        if description:
            cve_json5["containers"]["cna"]["descriptions"].append({
                "lang": "en",
                "value": description
            })
        else:
            # Базовое описание, если не найдено
            cve_json5["containers"]["cna"]["descriptions"].append({
                "lang": "en",
                "value": f"Security vulnerability {cve_id} in Debian packages. See {debian_data.get('url', '')} for details."
            })
        
        # Затронутые продукты (пакеты)
        packages = debian_data.get('packages', [])
        if packages:
            # Группируем пакеты по имени
            packages_by_name = {}
            for pkg in packages:
                pkg_name = pkg.get('name', '')
                if pkg_name:
                    if pkg_name not in packages_by_name:
                        packages_by_name[pkg_name] = {
                            "vendor": "Debian",
                            "product": pkg_name,
                            "versions": []
                        }
                    
                    # Добавляем информацию о версии
                    release = pkg.get('release', '')
                    status = pkg.get('status', '').lower()
                    
                    if release:
                        packages_by_name[pkg_name]["versions"].append({
                            "version": release,
                            "status": status if status in ['affected', 'unaffected', 'unknown'] else 'affected'
                        })
            
            cve_json5["containers"]["cna"]["affected"] = list(packages_by_name.values())
        
        # Ссылки
        references = debian_data.get('references', [])
        for ref in references:
            cve_json5["containers"]["cna"]["references"].append({
                "url": ref.get('url', ''),
                "name": ref.get('name', '')
            })
        
        # Добавляем ссылку на Debian tracker
        if debian_data.get('url'):
            cve_json5["containers"]["cna"]["references"].append({
                "url": debian_data['url'],
                "name": f"Debian Security Tracker: {cve_id}"
            })
        
        # Метрики (если есть severity)
        severity = debian_data.get('severity', 'medium')
        if severity:
            # Преобразуем severity в базовый CVSS score (приблизительно)
            cvss_score = self._severity_to_cvss(severity)
            if cvss_score > 0:
                cve_json5["containers"]["cna"]["metrics"] = [{
                    "cvssV3_1": {
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": cvss_score,
                            "baseSeverity": severity.capitalize()
                        }
                    }
                }]
        
        return cve_json5
    
    def _severity_to_cvss(self, severity: str) -> float:
        """Преобразование severity в приблизительный CVSS score"""
        severity_map = {
            'critical': 9.5,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5
        }
        return severity_map.get(severity.lower(), 5.0)
    
    def parse_multiple_cves(self, cve_ids: List[str]) -> List[Dict[str, Any]]:
        """
        Парсинг нескольких CVE
        
        Args:
            cve_ids: Список CVE ID
            
        Returns:
            Список CVE записей в формате JSON 5.x
        """
        results = []
        for cve_id in cve_ids:
            cve_json5 = self.parse_debian_cve_to_json5(cve_id)
            if cve_json5:
                results.append(cve_json5)
        return results


# Глобальный экземпляр
_debian_cve_json5_parser_instance = None

def get_debian_cve_json5_parser():
    """Получить экземпляр DebianCVEJSON5Parser"""
    global _debian_cve_json5_parser_instance
    if _debian_cve_json5_parser_instance is None:
        _debian_cve_json5_parser_instance = DebianCVEJSON5Parser()
    return _debian_cve_json5_parser_instance

debian_cve_json5_parser = get_debian_cve_json5_parser()

