"""
Парсер уязвимостей SUSE
Адаптирован из pars/SUSE.txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class SUSEParser(BaseLegacyParser):
    """
    Парсер уязвимостей SUSE
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("SUSE", vulnerability_repo)
        self.base_url = 'https://www.suse.com/security/cve'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей SUSE
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг SUSE (limit={limit})")
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
            
            # Находим CVE ссылки (ищем CVE-2021- и новее)
            links = []
            identifiers = []
            
            for quote in soup.find_all('a', href=re.compile("CVE-202")):
                lines = quote.text
                cve_id = self._normalize_cve_id(lines)
                if cve_id:
                    # Проверяем, существует ли уже
                    existing = self.vulnerability_repo.get_by_cve_id(cve_id)
                    if not existing:
                        identifiers.append(cve_id)
                        link = f"{self.base_url}/{cve_id}"
                        links.append(link)
            
            # Ограничиваем количество
            identifiers = identifiers[:limit]
            links = links[:len(identifiers)]
            
            # Парсим каждую страницу CVE для получения описания и CVSS
            descriptions = []
            cvss_scores = []
            
            for link in links:
                try:
                    r = requests.get(link, timeout=30)
                    r.raise_for_status()
                    soup_page = BeautifulSoup(r.text, 'lxml')
                    
                    # Ищем описание
                    try:
                        title = soup_page.find('div', {'class': 'standard-pad white-bg'}).find('h4').next_sibling
                        if title:
                            description = self._clean_text(str(title).replace('\n', ''))
                        else:
                            description = ''
                    except:
                        description = ''
                    
                    # Ищем CVSS score
                    try:
                        title_ = soup_page.find('table', {'border': '1'}).findNext('tr').findNext('tr').findNext('td').findNext('td').text
                        cvss = self._extract_cvss_from_text(title_)
                    except:
                        cvss = 0.0
                    
                    descriptions.append(description)
                    cvss_scores.append(cvss if cvss > 0 else 5.0)
                
                except Exception as e:
                    self.logger.debug(f"⚠️ Ошибка парсинга страницы {link}: {e}")
                    descriptions.append('')
                    cvss_scores.append(5.0)
            
            # Создаем уязвимости
            for i in range(len(identifiers)):
                cve_id = identifiers[i]
                description = descriptions[i] if i < len(descriptions) else ''
                link = links[i] if i < len(links) else ''
                cvss = cvss_scores[i] if i < len(cvss_scores) else 5.0
                
                vuln = self._create_vulnerability(
                    cve_id=cve_id,
                    title=f"SUSE Security Advisory: {cve_id}",
                    description=description or f"SUSE security advisory for {cve_id}",
                    cvss_score=cvss,
                    source='SUSE',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ SUSE: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга SUSE: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

