"""
Парсер уязвимостей Red Hat
Адаптирован из pars/RedHat.txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class RedHatParser(BaseLegacyParser):
    """
    Парсер уязвимостей Red Hat
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("RedHat", vulnerability_repo)
        self.base_url = 'https://access.redhat.com/security/security-updates/#/cve'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей Red Hat
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг Red Hat (limit={limit})")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            vulnerabilities = []
            
            # Используем API Red Hat вместо Selenium
            url = f'{self.base_url}?q=&p=1&sort=cve_publicDate%20desc&rows={limit}&documentKind=Cve'
            
            # Пробуем получить данные через requests
            try:
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
            except Exception as e:
                self.logger.warning(f"⚠️ Не удалось получить данные через requests: {e}")
                # Если не получилось, возвращаем пустой результат
                return {
                    'parsed': 0,
                    'saved': 0,
                    'errors': [f'Не удалось получить данные: {e}']
                }
            
            # Парсинг данных
            etc_list = []
            for quote in soup.find_all('span', {'ng-bind-html': 'result.cve_details'}):
                lines = quote.text
                etc_list.append(self._clean_text(lines))
            
            # CVSS scores
            cvss_list = []
            for quote in soup.find_all('td', {'class': 'td-impact'}):
                lines = quote.text
                cvss_list.append(lines)
            
            # Конвертация CVSS
            cvss_scores = []
            for x in cvss_list:
                x = x.replace('Impact', '').replace('\n', '').replace('Moderate', '5').replace('Low', '3').replace('Important', '9').replace('Critical', '10')
                if x != '':
                    try:
                        cvss_scores.append(float(x))
                    except:
                        cvss_scores.append(5.0)
                else:
                    cvss_scores.append(0.0)
            
            # CVE identifiers
            identifiers = []
            for quote in soup.find_all('span', {'class': 'cell-content'}):
                lines = quote.find('a')
                if lines is not None:
                    cve_id = self._normalize_cve_id(lines.text)
                    if cve_id:
                        identifiers.append(cve_id)
            
            # Links
            links = []
            for quote in soup.find_all('tr', {'pagination-id': 'CVE'}):
                lines = quote.find('a')
                if lines is not None and 'href' in lines.attrs:
                    href = lines.attrs['href']
                    if href.startswith('http'):
                        links.append(href)
                    else:
                        links.append(f'https://access.redhat.com{href}')
            
            # Создаем уязвимости
            min_len = min(len(identifiers), len(etc_list), len(cvss_scores), len(links))
            
            for i in range(min_len):
                cve_id = identifiers[i]
                description = etc_list[i] if i < len(etc_list) else ''
                cvss = cvss_scores[i] if i < len(cvss_scores) else 5.0
                link = links[i] if i < len(links) else ''
                
                # Проверяем, существует ли уже
                existing = self.vulnerability_repo.get_by_cve_id(cve_id)
                if existing:
                    self.logger.debug(f"⚠️ Уязвимость {cve_id} уже существует, пропускаем")
                    continue
                
                vuln = self._create_vulnerability(
                    cve_id=cve_id,
                    title=f"Red Hat Security Advisory: {cve_id}",
                    description=description or f"Security vulnerability {cve_id}",
                    cvss_score=cvss,
                    source='RedHat',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ Red Hat: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга Red Hat: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

