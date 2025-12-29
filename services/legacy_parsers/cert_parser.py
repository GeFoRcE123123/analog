"""
Парсер уязвимостей US-CERT
Адаптирован из pars/Cert.txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class CertParser(BaseLegacyParser):
    """
    Парсер уязвимостей US-CERT ICS Advisories
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("US-CERT", vulnerability_repo)
        self.base_url = 'https://us-cert.cisa.gov/ics/advisories'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей US-CERT
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг US-CERT (limit={limit})")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            vulnerabilities = []
            
            url = f'{self.base_url}?items_per_page=25'
            
            try:
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
            except Exception as e:
                self.logger.warning(f"⚠️ Не удалось получить данные: {e}")
                return {
                    'parsed': 0,
                    'saved': 0,
                    'errors': [f'Не удалось получить данные: {e}']
                }
            
            # Находим ссылки на advisories
            advisory_links = []
            for quote in soup.find_all('a', href=re.compile("/ics/advisories")):
                if quote is not None and 'href' in quote.attrs:
                    href = quote.attrs['href']
                    if href.startswith('http'):
                        advisory_links.append(href)
                    else:
                        advisory_links.append(f'https://us-cert.cisa.gov{href}')
            
            # Ограничиваем количество
            advisory_links = advisory_links[:limit]
            
            links = []
            identifiers = []
            descriptions = []
            cvss_scores = []
            
            # Парсим каждую advisory страницу
            for advisory_url in advisory_links:
                try:
                    r = requests.get(advisory_url, timeout=30)
                    r.raise_for_status()
                    soup_page = BeautifulSoup(r.text, 'lxml')
                    
                    # Ищем CVE ссылки
                    for quote in soup_page.find_all('a', href=re.compile("CVE-")):
                        if quote is not None:
                            cve_id = self._normalize_cve_id(quote.text)
                            if cve_id:
                                links.append(advisory_url)
                                identifiers.append(cve_id)
                                
                                # Ищем CVSS score
                                try:
                                    s = quote.next_sibling
                                    result = re.search('A CVSS v3 base score of (.*) has been', str(s))
                                    if result:
                                        cvss = self._extract_cvss_from_text(result.group(1))
                                    else:
                                        cvss = 5.0
                                except:
                                    cvss = 5.0
                                
                                cvss_scores.append(cvss)
                                
                                # Ищем описание
                                try:
                                    s = quote.find_parent().previous_sibling
                                    if s:
                                        description = self._clean_text(str(s).replace('</p>', '').replace('<p>', ''))
                                    else:
                                        description = f"US-CERT ICS Advisory for {cve_id}"
                                except:
                                    description = f"US-CERT ICS Advisory for {cve_id}"
                                
                                descriptions.append(description)
                
                except Exception as e:
                    self.logger.debug(f"⚠️ Ошибка парсинга advisory {advisory_url}: {e}")
                    continue
            
            # Создаем уязвимости
            for i in range(len(identifiers)):
                cve_id = identifiers[i]
                description = descriptions[i] if i < len(descriptions) else ''
                link = links[i] if i < len(links) else ''
                cvss = cvss_scores[i] if i < len(cvss_scores) else 5.0
                
                # Проверяем, существует ли уже
                existing = self.vulnerability_repo.get_by_cve_id(cve_id)
                if existing:
                    self.logger.debug(f"⚠️ Уязвимость {cve_id} уже существует, пропускаем")
                    continue
                
                vuln = self._create_vulnerability(
                    cve_id=cve_id,
                    title=f"US-CERT ICS Advisory: {cve_id}",
                    description=description,
                    cvss_score=cvss,
                    source='us-cert',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ US-CERT: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга US-CERT: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

