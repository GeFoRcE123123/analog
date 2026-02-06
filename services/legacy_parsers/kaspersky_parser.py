"""
Парсер уязвимостей Kaspersky
Адаптирован из pars/Kaspersky.txt и pars/Kaspersky Stat (keywords).txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class KasperskyParser(BaseLegacyParser):
    """
    Парсер уязвимостей Kaspersky
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("Kaspersky", vulnerability_repo)
        self.base_url = 'https://support.kaspersky.ru/general/vulnerability.aspx?el=12430'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей Kaspersky
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг Kaspersky (limit={limit})")
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
            
            links = []
            identifiers = []
            descriptions = []
            
            # Парсим данные
            try:
                block = soup.find('div', {'class': 'block cur'})
                if block:
                    for quote in block.find_all('div', {'class': 'wincont_c3'}):
                        try:
                            lines = quote.find('div', {'class': 'w_cont'}).find('a', {'class': 'open'}, href=True)
                            if lines is not None and 'href' in lines.attrs:
                                href = lines.attrs['href']
                                identifiers.append(href)  # В оригинале это href, не CVE
                                links.append(f'{self.base_url}{href}')
                        except:
                            continue
                    
                    # Получаем описания
                    etc_ = []
                    for quote in block.find_all('div', {'class': 'wincont_c3'}):
                        try:
                            lines = quote.find('div', {'id': 'note'})
                            if lines is not None:
                                etc_.append(self._clean_text(lines.text.replace('\n', ' ')))
                        except:
                            continue
                    
                    descriptions = etc_[:len(identifiers)]
            except Exception as e:
                self.logger.warning(f"⚠️ Ошибка парсинга структуры страницы: {e}")
            
            # Создаем уязвимости (Kaspersky использует свои идентификаторы, не CVE)
            for i in range(min(len(identifiers), limit)):
                identifier = identifiers[i]
                description = descriptions[i] if i < len(descriptions) else ''
                link = links[i] if i < len(links) else ''
                
                # Kaspersky не всегда использует CVE, создаем уникальный идентификатор
                cve_id = f"KASPERSKY-{identifier.replace('/', '-').replace('?', '').replace('=', '-')}"
                
                # Проверяем, существует ли уже
                existing = self.vulnerability_repo.get_by_cve_id(cve_id)
                if existing:
                    self.logger.debug(f"⚠️ Уязвимость {cve_id} уже существует, пропускаем")
                    continue
                
                vuln = self._create_vulnerability(
                    cve_id=cve_id,
                    title=f"Kaspersky Vulnerability: {identifier}",
                    description=description or f"Kaspersky vulnerability {identifier}",
                    cvss_score=10.0,  # В оригинале всегда 10.0
                    source='kaspersky',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ Kaspersky: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга Kaspersky: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }


class KasperskyStatParser(BaseLegacyParser):
    """
    Парсер уязвимостей Kaspersky Statistics
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("KasperskyStat", vulnerability_repo)
        self.base_url = 'https://statistics.securelist.com/ru/vulnerability-scan'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей Kaspersky Statistics
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг Kaspersky Statistics (limit={limit})")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            vulnerabilities = []
            
            urls = [
                f'{self.base_url}/week',
                f'{self.base_url}/day',
                f'{self.base_url}/month'
            ]
            
            links = []
            identifiers = []
            descriptions = []
            
            # Парсим каждую страницу статистики
            for url in urls:
                try:
                    response = requests.get(url, timeout=30)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')
                except Exception as e:
                    self.logger.debug(f"⚠️ Не удалось получить {url}: {e}")
                    continue
                
                # Ищем CVE ссылки
                for quote in soup.find_all('a', href=re.compile("CVE")):
                    if quote is not None and 'href' in quote.attrs:
                        href = quote.attrs['href']
                        links.append(href)
                        
                        # Извлекаем CVE ID из ссылки
                        a = href
                        cve_id = self._normalize_cve_id(a[a.find("CVE"):a.find(".")] if a.find("CVE") != -1 else a)
                        if cve_id:
                            identifiers.append(cve_id)
                            
                            # Получаем описание с cve.mitre.org
                            try:
                                mitre_url = f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}'
                                r = requests.get(mitre_url, timeout=30)
                                r.raise_for_status()
                                soup_mitre = BeautifulSoup(r.text, 'html.parser')
                                
                                try:
                                    a_elem = soup_mitre.find('div', {'id': 'GeneratedTable'}).find('table').find('tbody').findChildren('tr')[3].find('td')
                                    description = self._clean_text(a_elem.text.replace('\n', ''))
                                except:
                                    description = f"Kaspersky statistics vulnerability {cve_id}"
                            except:
                                description = f"Kaspersky statistics vulnerability {cve_id}"
                            
                            descriptions.append(description)
                
                # Ограничиваем количество
                if len(identifiers) >= limit:
                    break
            
            # Ограничиваем до limit
            identifiers = identifiers[:limit]
            links = links[:len(identifiers)]
            descriptions = descriptions[:len(identifiers)]
            
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
                    title=f"Kaspersky Statistics: {cve_id}",
                    description=description,
                    cvss_score=9.0,  # В оригинале всегда 9.0
                    source='kaspersky',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ Kaspersky Statistics: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга Kaspersky Statistics: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

