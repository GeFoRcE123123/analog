"""
Парсер уязвимостей Zero Day Initiative
Адаптирован из pars/Zero Day Initiative.txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class ZeroDayInitiativeParser(BaseLegacyParser):
    """
    Парсер уязвимостей Zero Day Initiative
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("ZeroDayInitiative", vulnerability_repo)
        self.base_url = 'https://www.zerodayinitiative.com/advisories'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей Zero Day Initiative
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг Zero Day Initiative (limit={limit})")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            vulnerabilities = []
            
            # Получаем список существующих CVE из БД
            existing_cves = set()
            try:
                with self.vulnerability_repo.connection.cursor() as cursor:
                    cursor.execute("SELECT cve FROM turn WHERE cve IS NOT NULL")
                    records = cursor.fetchall()
                    existing_cves = {re.sub(r"[^а-яА-ЯёЁa-zA-Z0-9- ]", "", str(x[0]).replace('\xa0', '').replace('xa0', '')) for x in records if x[0]}
            except:
                self.logger.warning("⚠️ Не удалось получить список существующих CVE")
            
            url = f'{self.base_url}/published/'
            
            try:
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'xml')
            except Exception as e:
                self.logger.warning(f"⚠️ Не удалось получить данные: {e}")
                return {
                    'parsed': 0,
                    'saved': 0,
                    'errors': [f'Не удалось получить данные: {e}']
                }
            
            # Извлекаем CVE и ZDI идентификаторы
            identifiers_cve = []
            identifiers_zdi = []
            
            for quote in soup.find_all('td', text=re.compile("CVE-2")):
                cve_text = quote.text
                cve_id = self._normalize_cve_id(cve_text)
                if cve_id and cve_id not in existing_cves:
                    identifiers_cve.append(cve_id)
                    # Получаем ZDI идентификатор
                    try:
                        zdi_id = quote.previous_element.previous_element.previous_element.previous_element.previous_element
                        identifiers_zdi.append(str(zdi_id).strip())
                    except:
                        identifiers_zdi.append('')
            
            # Ограничиваем количество
            identifiers_cve = identifiers_cve[:limit]
            identifiers_zdi = identifiers_zdi[:len(identifiers_cve)]
            
            # Создаем ссылки
            links_ = [f"{self.base_url}/{zdi_id}" for zdi_id in identifiers_zdi]
            
            links = []
            identifiers = []
            descriptions = []
            cvss_scores = []
            
            # Парсим каждую страницу advisory
            for link in links_:
                try:
                    r = requests.get(link, timeout=30)
                    r.raise_for_status()
                    soup_page = BeautifulSoup(r.text, 'lxml')
                    
                    links.append(link)
                    
                    # Ищем CVE ID
                    cve_text = soup_page.find(text=re.compile("CVE-2"))
                    cve_id = self._normalize_cve_id(cve_text) if cve_text else None
                    identifiers.append(cve_id or '')
                    
                    # Ищем CVSS score
                    try:
                        quote = soup_page.find(href=re.compile("http://nvd.nist.gov/"))
                        if quote:
                            cvss_text = quote.previous_element
                            cvss = self._extract_cvss_from_text(str(cvss_text))
                        else:
                            cvss = 5.0
                    except:
                        cvss = 5.0
                    
                    cvss_scores.append(cvss)
                    
                    # Ищем описание
                    try:
                        desc_text = soup_page.find(text=re.compile("This vulnerability"))
                        description = self._clean_text(desc_text) if desc_text else ''
                    except:
                        description = ''
                    
                    descriptions.append(description)
                
                except Exception as e:
                    self.logger.debug(f"⚠️ Ошибка парсинга advisory {link}: {e}")
                    continue
            
            # Создаем уязвимости
            for i in range(len(identifiers)):
                cve_id = identifiers[i]
                if not cve_id:
                    continue
                
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
                    title=f"Zero Day Initiative: {cve_id}",
                    description=description or f"Zero Day Initiative advisory for {cve_id}",
                    cvss_score=cvss,
                    source='zerodayinitiative',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ Zero Day Initiative: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга Zero Day Initiative: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

