"""
Парсер уязвимостей Palo Alto Networks
Адаптирован из pars/Palo Alto.txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class PaloAltoParser(BaseLegacyParser):
    """
    Парсер уязвимостей Palo Alto Networks
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("PaloAlto", vulnerability_repo)
        self.base_url = 'https://security.paloaltonetworks.com'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей Palo Alto
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг Palo Alto (limit={limit})")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            vulnerabilities = []
            
            url = f'{self.base_url}/?sort=-date&limit={limit}'
            
            try:
                response = requests.get(url, timeout=30)
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
            links_ = []
            for quote in soup.find_all('a', href=re.compile("CVE|PAN-SA")):
                lines = quote.get('href')
                if lines:
                    if lines.startswith('http'):
                        links_.append(lines)
                    else:
                        links_.append(f'{self.base_url}{lines}')
            
            # Получаем identifiers
            identifiers_ = []
            for quote in soup.find_all('a', href=re.compile("CVE|PAN-SA")):
                lines = quote.get('href')
                if lines:
                    x = lines.replace('/', '')
                    identifiers_.append(x)
            
            # Получаем описания
            etc_ = []
            for quote in soup.find_all('a', href=re.compile("CVE|PAN-SA")):
                lines = quote.text
                etc_.append(self._clean_text(lines))
            
            # Получаем CVSS scores
            lst_CVSSS_ = []
            for quote in soup.find_all('b'):
                lines = quote.text
                lst_CVSSS_.append(lines)
            
            # Фильтруем записи с CVSS = 0
            z = ([i for i, j in enumerate(lst_CVSSS_) if j == '0'])
            
            lst_CVSSS = [val for n, val in enumerate(lst_CVSSS_) if n not in z]
            etc = [val for n, val in enumerate(etc_) if n not in z]
            identifiers = [val for n, val in enumerate(identifiers_) if n not in z]
            links = [val for n, val in enumerate(links_) if n not in z]
            
            # Конвертируем CVSS в числа
            cvss_scores = []
            for cvss_text in lst_CVSSS:
                cvss = self._extract_cvss_from_text(cvss_text)
                cvss_scores.append(cvss if cvss > 0 else 5.0)
            
            # Ограничиваем количество
            min_len = min(len(identifiers), len(etc), len(cvss_scores), len(links), limit)
            
            # Создаем уязвимости
            for i in range(min_len):
                identifier = identifiers[i]
                description = etc[i] if i < len(etc) else ''
                link = links[i] if i < len(links) else ''
                cvss = cvss_scores[i] if i < len(cvss_scores) else 5.0
                
                # Извлекаем CVE ID из identifier
                cve_id = self._normalize_cve_id(identifier)
                if not cve_id:
                    # Если не CVE, используем identifier как есть
                    cve_id = identifier
                
                # Проверяем, существует ли уже
                existing = self.vulnerability_repo.get_by_cve_id(cve_id)
                if existing:
                    self.logger.debug(f"⚠️ Уязвимость {cve_id} уже существует, пропускаем")
                    continue
                
                vuln = self._create_vulnerability(
                    cve_id=cve_id,
                    title=f"Palo Alto Security Advisory: {identifier}",
                    description=description or f"Palo Alto security advisory for {identifier}",
                    cvss_score=cvss,
                    source='paloalto',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ Palo Alto: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга Palo Alto: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

