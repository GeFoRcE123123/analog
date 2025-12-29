"""
Парсер уязвимостей Cisco
Адаптирован из pars/Cisco (API).txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class CiscoParser(BaseLegacyParser):
    """
    Парсер уязвимостей Cisco через RSS/XML
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("Cisco", vulnerability_repo)
        self.rss_url = 'https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей Cisco
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг Cisco (limit={limit})")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            vulnerabilities = []
            
            # Получаем RSS feed
            try:
                response = requests.get(self.rss_url, timeout=30)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'xml')
            except Exception as e:
                self.logger.warning(f"⚠️ Не удалось получить RSS feed: {e}")
                return {
                    'parsed': 0,
                    'saved': 0,
                    'errors': [f'Не удалось получить RSS feed: {e}']
                }
            
            # Парсим описания
            descriptions = []
            for quote in soup.find_all('description')[1:]:  # Пропускаем первый (описание канала)
                descriptions.append(self._clean_text(quote.text))
            
            # Парсим ссылки
            links = []
            for quote in soup.find_all('link')[2:]:  # Пропускаем первые два
                links.append(quote.text)
            
            # Извлекаем CVE из текста
            identifiers = []
            for quote in soup.find_all('item'):
                w = quote.text
                cves = re.findall(r"CVE-2\d{3}-\d{4,}", w)
                cves = list(set(cves))  # Убираем дубликаты
                identifiers.append(cves)
            
            # Создаем плоский список
            flat_identifiers = []
            flat_links = []
            flat_descriptions = []
            
            for y, x, w in zip(links, identifiers, descriptions):
                for z in x:
                    flat_identifiers.append(z)
                    flat_links.append(y)
                    flat_descriptions.append(w)
            
            # Ограничиваем количество
            flat_identifiers = flat_identifiers[:limit]
            flat_links = flat_links[:len(flat_identifiers)]
            flat_descriptions = flat_descriptions[:len(flat_identifiers)]
            
            # Получаем CVSS scores со страниц уязвимостей
            cvss_scores = []
            for link in flat_links[:limit]:  # Ограничиваем для скорости
                try:
                    r = requests.get(link, timeout=30)
                    r.raise_for_status()
                    soup_page = BeautifulSoup(r.text, 'html.parser')
                    
                    try:
                        cvss_elem = soup_page.find('div', {'class': 'udheadercol1'}).find('div', {'class': 'flexcol'}).find('div', {'class': 'ud-CVSSScore divPaddingTen'}).find('div', {'class': 'divLabelContent'}).find('div').find('a', text=re.compile("."))
                        cvss_text = cvss_elem.text
                        cvss_score = self._extract_cvss_from_text(cvss_text)
                    except:
                        cvss_score = 0.0
                    
                    cvss_scores.append(cvss_score)
                except Exception as e:
                    self.logger.debug(f"⚠️ Не удалось получить CVSS для {link}: {e}")
                    cvss_scores.append(0.0)
            
            # Дополняем CVSS scores до нужной длины
            while len(cvss_scores) < len(flat_identifiers):
                cvss_scores.append(0.0)
            
            # Создаем уязвимости
            for i in range(len(flat_identifiers)):
                cve_id = flat_identifiers[i]
                description = flat_descriptions[i] if i < len(flat_descriptions) else ''
                link = flat_links[i] if i < len(flat_links) else ''
                cvss = cvss_scores[i] if i < len(cvss_scores) else 0.0
                
                # Проверяем, существует ли уже
                existing = self.vulnerability_repo.get_by_cve_id(cve_id)
                if existing:
                    self.logger.debug(f"⚠️ Уязвимость {cve_id} уже существует, пропускаем")
                    continue
                
                vuln = self._create_vulnerability(
                    cve_id=cve_id,
                    title=f"Cisco Security Advisory: {cve_id}",
                    description=description or f"Cisco security advisory for {cve_id}",
                    cvss_score=cvss if cvss > 0 else 5.0,
                    source='cisco',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ Cisco: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга Cisco: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

