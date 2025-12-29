"""
Парсер уязвимостей IBM
Адаптирован из pars/IBM.txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class IBMParser(BaseLegacyParser):
    """
    Парсер уязвимостей IBM PSIRT
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("IBM", vulnerability_repo)
        self.base_url = 'https://www.ibm.com/blogs/psirt'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей IBM
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг IBM (limit={limit})")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            vulnerabilities = []
            
            links = []
            identifiers = []
            descriptions = []
            cvss_scores = []
            
            # Парсим несколько страниц блога
            for page_num in range(1, 6):  # Первые 5 страниц
                url = f'{self.base_url}/page/{page_num}'
                
                try:
                    response = requests.get(url, timeout=30)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')
                except Exception as e:
                    self.logger.debug(f"⚠️ Не удалось получить страницу {page_num}: {e}")
                    continue
                
                # Находим ссылки на статьи
                article_links = []
                for quote in soup.find_all('a', {'class': 'ibm-blog__header-link'}):
                    if quote is not None and 'href' in quote.attrs:
                        href = quote.attrs['href']
                        if href.startswith('http'):
                            article_links.append(href)
                        else:
                            article_links.append(f'https://www.ibm.com{href}')
                
                # Парсим каждую статью
                for article_url in article_links:
                    try:
                        r = requests.get(article_url, timeout=30)
                        r.raise_for_status()
                        soup_article = BeautifulSoup(r.text, 'lxml')
                        
                        # Ищем CVE ссылки
                        for quote_ in soup_article.find_all('a', href=re.compile("cve.mitre")):
                            if quote_ is not None:
                                cve_id = self._normalize_cve_id(quote_.text)
                                if cve_id:
                                    links.append(article_url)
                                    identifiers.append(cve_id)
                                    
                                    # Ищем описание
                                    try:
                                        etc_elem = soup_article.find('div', {'class': 'ibm-blog__article-main'}).findChildren('p')[4]
                                        description = self._clean_text(etc_elem.text)
                                    except:
                                        description = f"IBM PSIRT advisory for {cve_id}"
                                    
                                    descriptions.append(description)
                                    
                                    # Ищем severity для CVSS
                                    try:
                                        severity_elem = soup_article.find('div', {'class': 'ibm-blog__article-main'}).findChildren('p')[1]
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
                    
                    except Exception as e:
                        self.logger.debug(f"⚠️ Ошибка парсинга статьи {article_url}: {e}")
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
                    title=f"IBM PSIRT Advisory: {cve_id}",
                    description=description,
                    cvss_score=cvss,
                    source='IBM',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ IBM: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга IBM: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

