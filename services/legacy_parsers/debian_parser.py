"""
Парсер уязвимостей Debian
Адаптирован из pars/Debian.txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class DebianParser(BaseLegacyParser):
    """
    Парсер уязвимостей Debian
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("Debian", vulnerability_repo)
        self.base_url = 'https://www.debian.org/security'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей Debian
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг Debian (limit={limit})")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            vulnerabilities = []
            
            # Получаем список DSA (Debian Security Advisories)
            current_year = 2024  # Можно сделать динамическим
            url = f'{self.base_url}/{current_year}/'
            
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
            
            # Находим ссылки на DSA
            dsa_links = []
            for quote in soup.find_all('strong'):
                lines = quote.find('a', href=re.compile("dsa"))
                if lines is not None and 'href' in lines.attrs:
                    href = lines.attrs['href']
                    if href.startswith('http'):
                        dsa_links.append(href)
                    else:
                        dsa_links.append(f'{self.base_url}/{current_year}/{href}')
            
            # Ограничиваем количество ссылок
            dsa_links = dsa_links[:limit]
            
            links = []
            identifiers = []
            descriptions = []
            
            # Парсим каждую DSA страницу
            for dsa_url in dsa_links:
                try:
                    r = requests.get(dsa_url, timeout=30)
                    r.raise_for_status()
                    soup = BeautifulSoup(r.text, 'lxml')
                    
                    # Ищем CVE ссылки
                    for quote in soup.find_all('a', href=re.compile("CVE")):
                        if quote is not None:
                            cve_id = self._normalize_cve_id(quote.text)
                            if cve_id:
                                links.append(dsa_url)
                                identifiers.append(cve_id)
                                
                                # Ищем описание
                                description = ''
                                for desc_quote in soup.find_all('dd'):
                                    desc_lines = desc_quote.find('p')
                                    if desc_lines is not None:
                                        description = self._clean_text(desc_lines.text)
                                        break
                                
                                descriptions.append(description or f"Debian security advisory for {cve_id}")
                    
                    # Если не нашли CVE, ищем bug ссылки
                    if not identifiers:
                        for quote in soup.find_all('a', href=re.compile("bug")):
                            if quote is not None:
                                bug_id = quote.text
                                links.append(dsa_url)
                                identifiers.append(f"DEBIAN-{bug_id}")
                                
                                description = ''
                                for desc_quote in soup.find_all('dd'):
                                    desc_lines = desc_quote.find('p')
                                    if desc_lines is not None:
                                        description = self._clean_text(desc_lines.text)
                                        break
                                
                                descriptions.append(description or f"Debian security advisory for bug {bug_id}")
                
                except Exception as e:
                    self.logger.warning(f"⚠️ Ошибка парсинга DSA {dsa_url}: {e}")
                    continue
            
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
                    title=f"Debian Security Advisory: {cve_id}",
                    description=description,
                    cvss_score=5.0,  # Debian не всегда предоставляет CVSS
                    source='Debian',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ Debian: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга Debian: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

