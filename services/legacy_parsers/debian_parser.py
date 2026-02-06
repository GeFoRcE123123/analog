"""
Парсер уязвимостей Debian
Адаптирован из pars/Debian.txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests
from datetime import datetime

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
            
            # Получаем список DSA с основной страницы безопасности Debian.
            # Важно: /security/<year>/ индексы могут отсутствовать (404), поэтому берем из /security/.
            list_url = f"{self.base_url}/"
            try:
                response = requests.get(list_url, timeout=30)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
            except Exception as e:
                self.logger.warning(f"⚠️ Не удалось получить список DSA: {e}")
                return {'parsed': 0, 'saved': 0, 'errors': [f'Не удалось получить список DSA: {e}']}
            
            # Находим ссылки на DSA (security-tracker)
            dsa_links: List[str] = []
            for a in soup.find_all('a', href=True):
                href = a.get('href', '')
                if 'security-tracker.debian.org/tracker/DSA-' in href:
                    dsa_links.append(href)
            # Уникализируем, сохраняя порядок
            seen = set()
            dsa_links = [x for x in dsa_links if not (x in seen or seen.add(x))]
            
            # Ограничиваем количество ссылок
            dsa_links = dsa_links[:limit]
            
            links = []
            identifiers = []
            descriptions = []
            
            # Парсим каждую DSA страницу (security-tracker)
            for dsa_url in dsa_links:
                try:
                    r = requests.get(dsa_url, timeout=30)
                    r.raise_for_status()
                    # Не используем lxml, чтобы не зависеть от дополнительного пакета в контейнере
                    soup = BeautifulSoup(r.text, 'html.parser')
                    
                    page_identifiers: List[str] = []
                    page_descriptions: List[str] = []
                    page_links: List[str] = []

                    # Ищем CVE ссылки/тексты на странице DSA
                    for quote in soup.find_all('a', href=re.compile("CVE", re.IGNORECASE)):
                        if quote is not None:
                            cve_id = self._normalize_cve_id(quote.text)
                            if cve_id:
                                page_links.append(dsa_url)
                                page_identifiers.append(cve_id)
                                
                                # Ищем описание
                                description = ''
                                for desc_quote in soup.find_all('dd'):
                                    desc_lines = desc_quote.find('p')
                                    if desc_lines is not None:
                                        description = self._clean_text(desc_lines.text)
                                        break
                                
                                # На tracker-странице DSA описание может быть коротким — но лучше, чем пусто.
                                page_descriptions.append(description or f"Debian security advisory {dsa_url.split('/')[-1]} for {cve_id}")
                    
                    # Если не нашли CVE на этой странице — ищем bug ссылки
                    if not page_identifiers:
                        for quote in soup.find_all('a', href=re.compile("bug")):
                            if quote is not None:
                                bug_id = quote.text
                                page_links.append(dsa_url)
                                page_identifiers.append(f"DEBIAN-{bug_id}")
                                
                                description = ''
                                for desc_quote in soup.find_all('dd'):
                                    desc_lines = desc_quote.find('p')
                                    if desc_lines is not None:
                                        description = self._clean_text(desc_lines.text)
                                        break
                                
                                page_descriptions.append(description or f"Debian security advisory for bug {bug_id}")

                    # Добавляем результаты страницы в общий список
                    links.extend(page_links)
                    identifiers.extend(page_identifiers)
                    descriptions.extend(page_descriptions)
                
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
                    link=link,
                    etc_data={
                        "references": ([{"url": link, "type": "advisory", "label": "Debian Security Advisory"}] if link else []),
                        "raw": {"debian_link": link} if link else {}
                    }
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

