"""
Парсер уязвимостей CyberSecurity Help
Адаптирован из pars/CyberSecurity (API).txt
"""
import logging
import re
from typing import Dict, Any, List
from bs4 import BeautifulSoup
import requests

from .base_legacy_parser import BaseLegacyParser
from models.entities import Vulnerability

logger = logging.getLogger(__name__)


class CyberSecurityParser(BaseLegacyParser):
    """
    Парсер уязвимостей CyberSecurity Help
    """
    
    def __init__(self, vulnerability_repo):
        super().__init__("CyberSecurity", vulnerability_repo)
        self.base_url = 'https://www.cybersecurity-help.cz/vdb'
    
    def parse(self, limit: int = 100, **kwargs) -> Dict[str, Any]:
        """
        Парсинг уязвимостей CyberSecurity Help
        
        Args:
            limit: Максимальное количество уязвимостей для парсинга
            
        Returns:
            Dict с результатами парсинга
        """
        self.logger.info(f"🔍 Начинаем парсинг CyberSecurity Help (limit={limit})")
        self.parsed_count = 0
        self.saved_count = 0
        self.errors = []
        
        try:
            vulnerabilities = []
            
            url = f'{self.base_url}/list.php'
            
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
            
            # Находим ссылки на уязвимости
            links = []
            for quote in soup.find_all('span', {'class': 'cvp_title'}):
                lines = quote.find('a', href=re.compile("/vdb/"))
                if lines is not None and 'href' in lines.attrs:
                    href = lines.attrs['href']
                    if href.startswith('http'):
                        links.append(href)
                    else:
                        links.append(f'https://www.cybersecurity-help.cz{href}')
            
            # Ограничиваем количество
            links = links[:limit]
            
            descriptions = []
            cve_list = []
            cvss_list = []
            
            # Парсим каждую страницу уязвимости
            for link in links:
                try:
                    r = requests.get(link, timeout=30)
                    r.raise_for_status()
                    soup_page = BeautifulSoup(r.text, 'lxml')
                    
                    # Ищем CVE
                    for quote in soup_page.find_all('div', {'class': 'cve'}):
                        try:
                            CVE = quote.find('p').findNext('p').findNext('p').find(text=re.compile('CVE-2'))
                            if CVE:
                                a = CVE.strip()
                                
                                if 'CVE' in a:
                                    cve_id = self._normalize_cve_id(a)
                                    if cve_id:
                                        cve_list.append(cve_id)
                                        
                                        # Ищем описание
                                        try:
                                            Description = quote.find('b', text=re.compile('Description')).findNext('p').findNext('p')
                                            decs_dop = soup_page.find('div', {'class': 'x_title'}).find('h2')
                                            description = f"{decs_dop.text} {Description.text}".replace('\r', '').replace('\n', '').replace('\t', '')
                                        except:
                                            description = f"CyberSecurity Help vulnerability {cve_id}"
                                        
                                        descriptions.append(self._clean_text(description))
                                        
                                        # Ищем CVSS
                                        try:
                                            CVSS = quote.find('p').findNext('p').find('a', text=re.compile('CVSS'))
                                            cvss = self._extract_cvss_from_text(CVSS.text[0:3])
                                        except:
                                            cvss = 5.0
                                        
                                        cvss_list.append(cvss)
                        except:
                            continue
                
                except Exception as e:
                    self.logger.debug(f"⚠️ Ошибка парсинга страницы {link}: {e}")
                    continue
            
            # Создаем уязвимости
            for i in range(len(cve_list)):
                cve_id = cve_list[i]
                description = descriptions[i] if i < len(descriptions) else ''
                link = links[i] if i < len(links) else ''
                cvss = cvss_list[i] if i < len(cvss_list) else 5.0
                
                # Проверяем, существует ли уже
                existing = self.vulnerability_repo.get_by_cve_id(cve_id)
                if existing:
                    self.logger.debug(f"⚠️ Уязвимость {cve_id} уже существует, пропускаем")
                    continue
                
                vuln = self._create_vulnerability(
                    cve_id=cve_id,
                    title=f"CyberSecurity Help: {cve_id}",
                    description=description,
                    cvss_score=cvss,
                    source='cybersecurity-help',
                    link=link
                )
                
                vulnerabilities.append(vuln)
                self.parsed_count += 1
            
            # Сохраняем
            if vulnerabilities:
                self.saved_count = self._save_vulnerabilities(vulnerabilities)
            
            self.logger.info(f"✅ CyberSecurity Help: спарсено {self.parsed_count}, сохранено {self.saved_count}")
            
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }
            
        except Exception as e:
            error_msg = f"Ошибка парсинга CyberSecurity Help: {e}"
            self.logger.error(error_msg, exc_info=True)
            self.errors.append(error_msg)
            return {
                'parsed': self.parsed_count,
                'saved': self.saved_count,
                'errors': self.errors
            }

