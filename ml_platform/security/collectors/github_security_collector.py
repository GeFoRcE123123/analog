"""
Сборщик данных из GitHub Security Advisories
"""

import requests
from typing import List, Dict, Any, Optional
from datetime import datetime

from ml_platform.core.logger import PlatformLogger


class GitHubSecurityCollector:
    """Сборщик данных из GitHub Security Advisories"""
    
    BASE_URL = "https://api.github.com"
    
    def __init__(self, token: Optional[str] = None):
        """
        Инициализация сборщика GitHub Security
        
        Args:
            token: GitHub Personal Access Token (для увеличения лимитов)
        """
        self.token = token
        self.logger = PlatformLogger.get_logger()
    
    def _get_headers(self) -> Dict[str, str]:
        """Получение заголовков для запросов"""
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        return headers
    
    def get_advisory_by_ghsa_id(self, ghsa_id: str) -> Optional[Dict[str, Any]]:
        """
        Получение advisory по GHSA ID
        
        Args:
            ghsa_id: GitHub Security Advisory ID (например, GHSA-xxxx-xxxx-xxxx)
            
        Returns:
            Данные advisory или None
        """
        try:
            response = requests.get(
                f"{self.BASE_URL}/advisories/{ghsa_id}",
                headers=self._get_headers(),
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Ошибка получения advisory {ghsa_id}: {e}")
            return None
    
    def get_advisories_by_ecosystem(
        self,
        ecosystem: str,
        per_page: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Получение advisories по экосистеме
        
        Args:
            ecosystem: Экосистема (npm, maven, nuget, etc.)
            per_page: Количество результатов на страницу
            
        Returns:
            Список advisories
        """
        all_advisories = []
        page = 1
        
        while True:
            try:
                response = requests.get(
                    f"{self.BASE_URL}/advisories",
                    params={
                        "ecosystem": ecosystem,
                        "per_page": per_page,
                        "page": page
                    },
                    headers=self._get_headers(),
                    timeout=30
                )
                response.raise_for_status()
                
                advisories = response.json()
                if not advisories:
                    break
                
                all_advisories.extend(advisories)
                
                # Проверка наличия следующей страницы
                if "next" not in response.links:
                    break
                
                page += 1
                
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Ошибка получения advisories для {ecosystem}: {e}")
                break
        
        return all_advisories
    
    def normalize_advisory_data(self, advisory_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Нормализация данных advisory
        
        Args:
            advisory_data: Сырые данные advisory из GitHub
            
        Returns:
            Нормализованные данные
        """
        ghsa_id = advisory_data.get("ghsa_id", "")
        summary = advisory_data.get("summary", "")
        description = advisory_data.get("description", "")
        
        # Извлечение CVSS
        cvss = advisory_data.get("cvss", {})
        cvss_score = cvss.get("score")
        cvss_vector = cvss.get("vector_string")
        
        # Извлечение CWE
        cwe_list = []
        cwes = advisory_data.get("cwes", [])
        for cwe in cwes:
            cwe_id = cwe.get("cwe_id", "")
            if cwe_id:
                cwe_list.append(cwe_id)
        
        # Извлечение затронутых пакетов
        affected_products = []
        vulnerabilities = advisory_data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            package = vuln.get("package", {})
            affected_products.append({
                "package": package.get("name", ""),
                "ecosystem": package.get("ecosystem", ""),
                "severity": vuln.get("severity", ""),
                "vulnerable_version_range": vuln.get("vulnerable_version_range", "")
            })
        
        # Даты
        published = advisory_data.get("published_at", "")
        updated = advisory_data.get("updated_at", "")
        
        return {
            "ghsa_id": ghsa_id,
            "cve_id": advisory_data.get("cve_id"),
            "description": description or summary,
            "published_date": published,
            "last_modified": updated,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cwe_ids": cwe_list,
            "affected_products": affected_products,
            "source": "GitHub Security",
            "raw_data": advisory_data
        }
