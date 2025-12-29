"""
Парсер уязвимостей FortiGuard
Адаптирован из pars/Forti Guard.txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class FortiGuardParser(BaseLegacyParser):
    """
    Парсер уязвимостей FortiGuard Zero Day
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("FortiGuard", vulnerability_repo)
        self.base_url = 'https://www.fortiguard.com/zeroday'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей FortiGuard
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг FortiGuard (limit={limit})")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            vulnerabilities = []
            
            try:
                response = requests.get(self.base_url, timeout=30)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'lxml')
            except Exception as e:
                self.logger.warning(f"⚠️ Не удалось получить данные: {e}")
                return {
                    'parsed': 0,
                    'saved': 0,
                    'errors': [f'Не удалось получить данные: {e}']
                }
            
            # Получаем ссылки
            links = []
            for quote in soup.find_all('div', {'class': 'title'}):
                lines = quote.find('a')
                if lines is not None and 'href' in lines.attrs:
                    href = lines.attrs['href']
                    if href.startswith('http'):
                        links.append(href)
                    else:
                        links.append(f'https://www.fortiguard.com{href}')
            
            # Получаем CVE identifiers
            identifiers = []
            for quote in soup.find_all('div', {'class': 'line'}):
                lines = quote.find('a', href=re.compile("http://cve.mitre.org/"))
                if lines is not None:
                    cve_id = self._normalize_cve_id(lines.text)
                    if cve_id:
                        identifiers.append(cve_id)
            
            # Получаем описания
            etc = []
            for quote in soup.find_all('div', {'class': 'title'}):
                lines = quote.a.find_next_sibling('a')
                if lines is not None:
                    etc.append(self._clean_text(lines.text))
            
            # Получаем CVSS scores (из ссылок)
            w = []
            for quote in soup.find_all('div', {'class': 'line'}):
                lines = quote.find('a')
                if lines is not None and 'href' in lines.attrs:
                    w.append(lines.attrs['href'])
            
            # Извлекаем числа из ссылок для CVSS
            w_ = []
            for x in w:
                numbers = re.sub(r'\D', '', x)
                if numbers:
                    try:
                        w_.append(float(numbers) * 2)  # Умножаем на 2 как в оригинале
                    except:
                        w_.append(5.0)
                else:
                    w_.append(5.0)
            
            cvss_scores = w_[:len(identifiers)]
            
            # Ограничиваем количество
            min_len = min(len(identifiers), len(etc), len(cvss_scores), len(links), limit)
            
            # Создаем уязвимости
            for i in range(min_len):
                cve_id = identifiers[i]
                description = etc[i] if i < len(etc) else ''
                link = links[i] if i < len(links) else ''
                cvss = cvss_scores[i] if i < len(cvss_scores) else 5.0
                
                # Ограничиваем CVSS до 10.0
                cvss = min(10.0, cvss)
                
                # Проверяем, существует ли уже
                existing = self.vulnerability_repo.get_by_cve_id(cve_id)
                if existing:
                    self.logger.debug(f"⚠️ Уязвимость {cve_id} уже существует, пропускаем")
                    continue
                
                vuln = self._create_vulnerability(
                    cve_id=cve_id,
                    title=f"FortiGuard Zero Day: {cve_id}",
                    description=description or f"FortiGuard zero day vulnerability {cve_id}",
                    cvss_score=cvss,
                    source='fortiguard',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ FortiGuard: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга FortiGuard: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

