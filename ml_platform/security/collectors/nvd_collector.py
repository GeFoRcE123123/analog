"""
Сборщик данных из NVD (National Vulnerability Database)
"""

import requests
import time
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json

from ml_platform.core.logger import PlatformLogger


class NVDCollector:
    """Сборщик данных из NVD API"""
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_LIMIT_DELAY = 6  # секунд между запросами (NVD лимит: 5 запросов/30 сек)
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Инициализация сборщика NVD
        
        Args:
            api_key: API ключ NVD (опционально, для увеличения лимитов)
        """
        self.api_key = api_key
        self.logger = PlatformLogger.get_logger()
        self.last_request_time = 0
    
    def _rate_limit(self):
        """Ограничение частоты запросов"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.RATE_LIMIT_DELAY:
            sleep_time = self.RATE_LIMIT_DELAY - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _make_request(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Выполнение запроса к NVD API
        
        Args:
            params: Параметры запроса
            
        Returns:
            Ответ API
        """
        self._rate_limit()
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Ошибка запроса к NVD API: {e}")
            raise
    
    def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Получение CVE по идентификатору
        
        Args:
            cve_id: Идентификатор CVE (например, CVE-2024-0001)
            
        Returns:
            Данные CVE или None
        """
        params = {
            "cveId": cve_id
        }
        
        try:
            response = self._make_request(params)
            if response.get("vulnerabilities"):
                return response["vulnerabilities"][0]["cve"]
            return None
        except Exception as e:
            self.logger.error(f"Ошибка получения CVE {cve_id}: {e}")
            return None
    
    def get_cves_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime,
        results_per_page: int = 2000
    ) -> List[Dict[str, Any]]:
        """
        Получение CVE за период времени
        
        Args:
            start_date: Начальная дата
            end_date: Конечная дата
            results_per_page: Количество результатов на страницу
            
        Returns:
            Список CVE
        """
        all_cves = []
        start_index = 0
        
        params = {
            "pubStartDate": start_date.isoformat(),
            "pubEndDate": end_date.isoformat(),
            "resultsPerPage": results_per_page,
            "startIndex": start_index
        }
        
        while True:
            try:
                response = self._make_request(params)
                vulnerabilities = response.get("vulnerabilities", [])
                
                if not vulnerabilities:
                    break
                
                cves = [vuln["cve"] for vuln in vulnerabilities]
                all_cves.extend(cves)
                
                total_results = response.get("totalResults", 0)
                start_index += len(vulnerabilities)
                
                if start_index >= total_results:
                    break
                
                params["startIndex"] = start_index
                
                self.logger.info(f"Загружено {len(all_cves)}/{total_results} CVE")
                
            except Exception as e:
                self.logger.error(f"Ошибка получения CVE за период: {e}")
                break
        
        return all_cves
    
    def get_recent_cves(self, days: int = 7) -> List[Dict[str, Any]]:
        """
        Получение недавних CVE
        
        Args:
            days: Количество дней назад
            
        Returns:
            Список недавних CVE
        """
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        return self.get_cves_by_date_range(start_date, end_date)
    
    def get_cves_by_keyword(self, keyword: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Поиск CVE по ключевому слову
        
        Args:
            keyword: Ключевое слово для поиска
            limit: Максимальное количество результатов
            
        Returns:
            Список найденных CVE
        """
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(limit, 2000)
        }
        
        try:
            response = self._make_request(params)
            vulnerabilities = response.get("vulnerabilities", [])
            return [vuln["cve"] for vuln in vulnerabilities[:limit]]
        except Exception as e:
            self.logger.error(f"Ошибка поиска CVE по ключевому слову: {e}")
            return []
    
    def normalize_cve_data(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Нормализация данных CVE для единого формата
        
        Args:
            cve_data: Сырые данные CVE из NVD
            
        Returns:
            Нормализованные данные
        """
        cve_id = cve_data.get("id", "")
        
        # Извлечение описания
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        
        # Извлечение CVSS
        metrics = cve_data.get("metrics", {})
        cvss_v3 = None
        cvss_v2 = None
        
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]
            cvss_v3 = {
                "version": "3.1",
                "base_score": cvss_data.get("cvssData", {}).get("baseScore"),
                "vector_string": cvss_data.get("cvssData", {}).get("vectorString"),
                "severity": cvss_data.get("cvssData", {}).get("baseSeverity"),
                "exploitability_score": cvss_data.get("exploitabilityScore"),
                "impact_score": cvss_data.get("impactScore")
            }
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]
            cvss_v3 = {
                "version": "3.0",
                "base_score": cvss_data.get("cvssData", {}).get("baseScore"),
                "vector_string": cvss_data.get("cvssData", {}).get("vectorString"),
                "severity": cvss_data.get("cvssData", {}).get("baseSeverity"),
                "exploitability_score": cvss_data.get("exploitabilityScore"),
                "impact_score": cvss_data.get("impactScore")
            }
        
        if "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]
            cvss_v2 = {
                "version": "2.0",
                "base_score": cvss_data.get("cvssData", {}).get("baseScore"),
                "vector_string": cvss_data.get("cvssData", {}).get("vectorString"),
                "severity": cvss_data.get("baseSeverity")
            }
        
        # Извлечение CWE
        weaknesses = cve_data.get("weaknesses", [])
        cwe_list = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwe_id = desc.get("value", "")
                    if cwe_id.startswith("CWE-"):
                        cwe_list.append(cwe_id)
        
        # Извлечение CPE конфигураций
        configurations = cve_data.get("configurations", [])
        affected_products = []
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for match in cpe_matches:
                    if match.get("vulnerable", False):
                        affected_products.append({
                            "cpe": match.get("criteria", ""),
                            "version_start_including": match.get("versionStartIncluding"),
                            "version_end_including": match.get("versionEndIncluding"),
                            "version_start_excluding": match.get("versionStartExcluding"),
                            "version_end_excluding": match.get("versionEndExcluding")
                        })
        
        # Даты
        published = cve_data.get("published", "")
        last_modified = cve_data.get("lastModified", "")
        
        return {
            "cve_id": cve_id,
            "description": description,
            "published_date": published,
            "last_modified": last_modified,
            "cvss_v3": cvss_v3,
            "cvss_v2": cvss_v2,
            "cwe_ids": cwe_list,
            "affected_products": affected_products,
            "source": "NVD",
            "raw_data": cve_data
        }
