"""
Парсер уязвимостей Juniper
Адаптирован из pars/Juniper.txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class JuniperParser(BaseLegacyParser):
    """
    Парсер уязвимостей Juniper
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("Juniper", vulnerability_repo)
        self.base_url = 'https://kb.juniper.net/InfoCenter'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей Juniper
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг Juniper (limit={limit})")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            vulnerabilities = []
            
            links = []
            identifiers = []
            descriptions = []
            cvss_scores = []
            
            # Парсим несколько страниц RSS
            for offset in range(0, 60, 15):  # 0, 15, 30, 45
                url = f'{self.base_url}/index?page=content&channel=SECURITY_ADVISORIES&cat=SIRT_1&actp=&sort=datemodified&dir=descending&max=1000&batch=15&rss=true&itData.offset={offset}'
                
                try:
                    response = requests.get(url, timeout=30)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')
                except Exception as e:
                    self.logger.debug(f"⚠️ Не удалось получить страницу offset={offset}: {e}")
                    continue
                
                # Находим ссылки на advisories
                links_ = []
                for quote in soup.find_all('a', href=re.compile("LIST&showDraft")):
                    if quote is not None and 'href' in quote.attrs:
                        href = quote.attrs['href']
                        if href.startswith('http'):
                            links_.append(href)
                        else:
                            links_.append(f'{self.base_url}/{href}')
                
                # Парсим каждую advisory страницу
                for advisory_url in links_:
                    try:
                        r = requests.get(advisory_url, timeout=30)
                        r.raise_for_status()
                        soup_page = BeautifulSoup(r.text, 'lxml')
                        
                        # Ищем CVE ссылки
                        for quote_ in soup_page.find_all('a', href=re.compile("cve.mitre")):
                            if re.search('at cve.mitre', str(quote_)) is None:
                                cve_id = self._normalize_cve_id(quote_.text)
                                if cve_id:
                                    links.append(advisory_url)
                                    identifiers.append(cve_id)
                                    
                                    # Ищем описание
                                    try:
                                        etc_elem = soup_page.find('div', {'class': 'content nonfileattachment'})
                                        description = self._clean_text(etc_elem.text.rstrip())
                                    except:
                                        description = f"Juniper security advisory for {cve_id}"
                                    
                                    descriptions.append(description)
                                    
                                    # Ищем severity для CVSS
                                    try:
                                        severity_elem = soup_page.find('div', {'class': 'content contentlist'})
                                        severity_text = severity_elem.text
                                        
                                        if 'Low' in severity_text:
                                            cvss = 3.0
                                        elif 'Medium' in severity_text:
                                            cvss = 5.0
                                        elif 'High' in severity_text:
                                            cvss = 8.0
                                        elif 'Critical' in severity_text:
                                            cvss = 10.0
                                        else:
                                            cvss = 1.0
                                    except:
                                        cvss = 5.0
                                    
                                    cvss_scores.append(cvss)
                        
                        # Ищем таблицу с CVE
                        quote_table = soup_page.find('table', {'class': 'striped'})
                        if quote_table is not None:
                            try:
                                tbody = quote_table.find('tbody')
                                if tbody:
                                    rows = tbody.findChildren('tr')
                                    for i in range(1, len(rows)):  # Пропускаем заголовок
                                        try:
                                            cells = rows[i].findChildren('td')
                                            if len(cells) >= 3:
                                                s1 = cells[0].text
                                                s2 = cells[1].text[:3]
                                                s3 = cells[2].text
                                                
                                                cve_id = self._normalize_cve_id(s1)
                                                if cve_id:
                                                    identifiers.append(cve_id)
                                                    links.append(advisory_url)
                                                    
                                                    cvss = self._extract_cvss_from_text(s2)
                                                    if cvss == 0 or cvss == '\xa0':
                                                        cvss = 1.0
                                                    
                                                    cvss_scores.append(cvss)
                                                    descriptions.append(self._clean_text(s3))
                                        except:
                                            continue
                            except:
                                pass
                    
                    except Exception as e:
                        self.logger.debug(f"⚠️ Ошибка парсинга advisory {advisory_url}: {e}")
                        continue
                    
                    # Ограничиваем количество
                    if len(identifiers) >= limit:
                        break
                
                if len(identifiers) >= limit:
                    break
            
            # Ограничиваем до limit
            identifiers = identifiers[:limit]
            links = links[:len(identifiers)]
            descriptions = descriptions[:len(identifiers)]
            cvss_scores = cvss_scores[:len(identifiers)]
            
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
                    title=f"Juniper Security Advisory: {cve_id}",
                    description=description,
                    cvss_score=cvss,
                    source='juniper',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ Juniper: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга Juniper: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

