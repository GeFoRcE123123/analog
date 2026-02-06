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
        # CISA moved ICS advisories under /news-events/ics-advisories
        self.base_url = 'https://www.cisa.gov/news-events/ics-advisories'
    
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
            # На странице много ссылок, нам нужны только карточки advisory вида /news-events/ics-advisories/icsa-XX-XXX-XX
            adv_re = re.compile(r"/news-events/ics-advisories/(icsa|icsma|icsm|icsd)-", re.IGNORECASE)
            for quote in soup.find_all('a', href=adv_re):
                if quote is not None and 'href' in quote.attrs:
                    href = quote.attrs['href']
                    if href.startswith('http'):
                        advisory_links.append(href)
                    else:
                        advisory_links.append(f'https://www.cisa.gov{href}')
            # уникализируем
            seen = set()
            advisory_links = [x for x in advisory_links if not (x in seen or seen.add(x))]
            
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
                    soup_page = BeautifulSoup(r.text, 'html.parser')
                    
                    # Ищем CVE в ссылках и в тексте (на новых страницах CVE могут быть без href)
                    page_text = soup_page.get_text(" ", strip=True).upper()
                    cve_candidates = set()
                    for a in soup_page.find_all('a'):
                        t = (a.get_text(" ", strip=True) or "").upper()
                        if "CVE-" in t:
                            for x in re.findall(r"CVE-\\d{4}-\\d{4,7}", t):
                                cve_candidates.add(x)
                    for x in re.findall(r"CVE-\\d{4}-\\d{4,7}", page_text):
                        cve_candidates.add(x)

                    # Заголовок advisory как базовое описание
                    page_title = ""
                    h1 = soup_page.find('h1')
                    if h1:
                        page_title = self._clean_text(h1.get_text(" ", strip=True))

                    for cve_raw in sorted(cve_candidates):
                        cve_id = self._normalize_cve_id(cve_raw)
                        if not cve_id:
                            continue
                        links.append(advisory_url)
                        identifiers.append(cve_id)
                        cvss_scores.append(5.0)
                        descriptions.append(page_title or f"US-CERT ICS Advisory: {advisory_url} ({cve_id})")
                
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

