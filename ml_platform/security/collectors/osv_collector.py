"""
Сборщик данных из OSV (Open Source Vulnerabilities)
"""

import requests
from typing import List, Dict, Any, Optional
import json

from ml_platform.core.logger import PlatformLogger


class OSVCollector:
    """Сборщик данных из OSV API"""
    
    BASE_URL = "https://api.osv.dev/v1"
    
    def __init__(self):
        """Инициализация сборщика OSV"""
        self.logger = PlatformLogger.get_logger()
    
    def get_vulnerability_by_id(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """
        Получение уязвимости по идентификатору
        
        Args:
            vuln_id: Идентификатор уязвимости (CVE, GHSA, etc.)
            
        Returns:
            Данные уязвимости или None
        """
        try:
            response = requests.get(
                f"{self.BASE_URL}/vulns/{vuln_id}",
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Ошибка получения уязвимости {vuln_id} из OSV: {e}")
            return None
    
    def query_by_package(
        self,
        package_name: str,
        ecosystem: str,
        version: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Поиск уязвимостей по пакету
        
        Args:
            package_name: Название пакета
            ecosystem: Экосистема (npm, pypi, maven, etc.)
            version: Версия пакета (опционально)
            
        Returns:
            Список уязвимостей
        """
        query = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }
        
        if version:
            query["version"] = version
        
        try:
            response = requests.post(
                f"{self.BASE_URL}/query",
                json=query,
                timeout=30
            )
            response.raise_for_status()
            result = response.json()
            return result.get("vulns", [])
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Ошибка запроса уязвимостей для {package_name}: {e}")
            return []
    
    def query_by_commit(self, commit_hash: str, repo_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Поиск уязвимостей по коммиту
        
        Args:
            commit_hash: Хеш коммита
            repo_url: URL репозитория (опционально)
            
        Returns:
            Список уязвимостей
        """
        query = {
            "commit": commit_hash
        }
        
        if repo_url:
            query["repo"] = repo_url
        
        try:
            response = requests.post(
                f"{self.BASE_URL}/query",
                json=query,
                timeout=30
            )
            response.raise_for_status()
            result = response.json()
            return result.get("vulns", [])
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Ошибка запроса уязвимостей по коммиту: {e}")
            return []
    
    def normalize_vuln_data(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Нормализация данных уязвимости OSV
        
        Args:
            vuln_data: Сырые данные уязвимости из OSV
            
        Returns:
            Нормализованные данные
        """
        vuln_id = vuln_data.get("id", "")
        
        # Извлечение описания
        summary = vuln_data.get("summary", "")
        details = vuln_data.get("details", "")
        description = details if details else summary
        
        # Извлечение CVSS
        database_specific = vuln_data.get("database_specific", {})
        severity = database_specific.get("severity", "")
        
        # Извлечение CWE
        cwe_list = []
        if "cwe" in database_specific:
            cwe_list = database_specific["cwe"]
        
        # Извлечение затронутых версий
        affected = vuln_data.get("affected", [])
        affected_products = []
        for item in affected:
            package = item.get("package", {})
            ranges = item.get("ranges", [])
            
            for range_item in ranges:
                events = range_item.get("events", [])
                for event in events:
                    if "introduced" in event:
                        affected_products.append({
                            "package": package.get("name", ""),
                            "ecosystem": package.get("ecosystem", ""),
                            "introduced": event.get("introduced"),
                            "fixed": event.get("fixed")
                        })
        
        # Даты
        published = vuln_data.get("published", "")
        modified = vuln_data.get("modified", "")
        
        return {
            "vuln_id": vuln_id,
            "description": description,
            "published_date": published,
            "last_modified": modified,
            "severity": severity,
            "cwe_ids": cwe_list,
            "affected_products": affected_products,
            "source": "OSV",
            "raw_data": vuln_data
        }
