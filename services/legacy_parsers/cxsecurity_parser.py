"""
Парсер уязвимостей CXSecurity
Адаптирован из pars/CXSecurity.txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class CXSecurityParser(BaseLegacyParser):
    """
    Парсер уязвимостей CXSecurity
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("CXSecurity", vulnerability_repo)
        self.base_url = 'https://cxsecurity.com/cvemap'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей CXSecurity
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг CXSecurity (limit={limit})")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            vulnerabilities = []
            
            links = []
            identifiers = []
            descriptions = []
            
            # Парсим несколько страниц
            for page_num in range(1, 6):  # Первые 5 страниц
                url = f'{self.base_url}/{page_num}'
                
                try:
                    response = requests.get(url, timeout=30)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')
                except Exception as e:
                    self.logger.debug(f"⚠️ Не удалось получить страницу {page_num}: {e}")
                    continue
                
                # Парсим данные
                for quote in soup.find_all('h6'):
                    try:
                        lines = quote.findNext('a').findNext('a').text
                        description = self._clean_text(lines)
                        
                        lines1 = quote.findNext('a').text
                        cve_id = self._normalize_cve_id(lines1)
                        
                        if cve_id:
                            identifiers.append(cve_id)
                            links.append(f'https://cxsecurity.com/cveshow/{cve_id}')
                            descriptions.append(description)
                    except:
                        continue
                
                # Ограничиваем количество
                if len(identifiers) >= limit:
                    break
            
            # Ограничиваем до limit
            identifiers = identifiers[:limit]
            links = links[:len(identifiers)]
            descriptions = descriptions[:len(identifiers)]
            
            # Фильтруем по ключевым словам (если есть словарь)
            # Пока пропускаем фильтрацию, так как словарь не реализован
            
            # Создаем уязвимости
            for i in range(len(identifiers)):
                cve_id = identifiers[i]
                description = descriptions[i] if i < len(descriptions) else ''
                link = links[i] if i < len(links) else ''
                
                # Проверяем, существует ли уже
                existing = self.vulnerability_repo.get_by_cve_id(cve_id)
                if existing:
                    self.logger.debug(f"⚠️ Уязвимость {cve_id} уже существует, пропускаем")
                    continue
                
                vuln = self._create_vulnerability(
                    cve_id=cve_id,
                    title=f"CXSecurity: {cve_id}",
                    description=description or f"CXSecurity vulnerability {cve_id}",
                    cvss_score=5.0,  # CXSecurity не всегда предоставляет CVSS
                    source='cxsecurity',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ CXSecurity: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга CXSecurity: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

