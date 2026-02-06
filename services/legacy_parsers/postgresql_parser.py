"""
Парсер уязвимостей PostgreSQL
Адаптирован из pars/PostgreSQL.txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class PostgreSQLParser(BaseLegacyParser):
    """
    Парсер уязвимостей PostgreSQL
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("PostgreSQL", vulnerability_repo)
        self.base_url = 'https://www.postgresql.org/support/security'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей PostgreSQL
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг PostgreSQL (limit={limit})")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            vulnerabilities = []
            
            try:
                response = requests.get(self.base_url, timeout=30)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
            except Exception as e:
                self.logger.warning(f"⚠️ Не удалось получить данные: {e}")
                return {
                    'parsed': 0,
                    'saved': 0,
                    'errors': [f'Не удалось получить данные: {e}']
                }
            
            # Получаем описания
            etc_ = []
            for quote in soup.find_all('td'):
                if quote is not None:
                    try:
                        lines = quote.next_sibling
                        if lines:
                            etc_.append(str(lines))
                    except:
                        pass
            
            # Фильтруем и очищаем описания
            etc_ = list(filter(None, etc_))
            www = [s for s in etc_ if "more details" in s]
            
            etc = []
            left = '<td>'
            right = '<br/><br/><a'
            for x in www:
                if left in x and right in x:
                    x_ = x[x.index(left)+len(left):x.index(right)]
                    etc.append(self._clean_text(x_))
            
            # Получаем CVE identifiers
            identifiers = []
            for quote in soup.find_all('nobr'):
                lines = quote.find('a')
                if lines is not None:
                    cve_id = self._normalize_cve_id(lines.text)
                    if cve_id:
                        identifiers.append(cve_id)
            
            # Получаем ссылки
            links = []
            for quote in soup.find_all('nobr'):
                lines = quote.find('a')
                if lines is not None and 'href' in lines.attrs:
                    href = lines.attrs['href']
                    if href.startswith('http'):
                        links.append(href)
                    else:
                        links.append(f'https://www.postgresql.org{href}')
            
            # Получаем CVSS scores
            cvss_scores = []
            for quote in soup.find_all("a", href=re.compile("nvd")):
                lines = quote.text
                cvss = self._extract_cvss_from_text(lines)
                cvss_scores.append(cvss)
            
            # Ограничиваем количество
            min_len = min(len(identifiers), len(etc), len(cvss_scores), len(links), limit)
            
            # Создаем уязвимости
            for i in range(min_len):
                cve_id = identifiers[i]
                description = etc[i] if i < len(etc) else ''
                link = links[i] if i < len(links) else ''
                cvss = cvss_scores[i] if i < len(cvss_scores) else 5.0
                
                # Проверяем, существует ли уже
                existing = self.vulnerability_repo.get_by_cve_id(cve_id)
                if existing:
                    self.logger.debug(f"⚠️ Уязвимость {cve_id} уже существует, пропускаем")
                    continue
                
                vuln = self._create_vulnerability(
                    cve_id=cve_id,
                    title=f"PostgreSQL Security Advisory: {cve_id}",
                    description=description or f"PostgreSQL security advisory for {cve_id}",
                    cvss_score=cvss,
                    source='PostgreSQL',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ PostgreSQL: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга PostgreSQL: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

