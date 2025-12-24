"""
Парсеры для различных источников уязвимостей
Адаптированы из старой системы для работы с новой архитектурой
"""
import logging
import re
import requests
import json
import zipfile
from datetime import datetime
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

logger = logging.getLogger(__name__)


class VendorParsers:
    """
    Парсеры для различных вендоров и источников уязвимостей
    Все парсеры возвращают список словарей в стандартном формате
    """
    
    def __init__(self, use_selenium: bool = False):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.use_selenium = use_selenium and SELENIUM_AVAILABLE
        self.driver = None
        
        if self.use_selenium:
            try:
                chrome_options = Options()
                chrome_options.add_argument('headless')
                chrome_options.add_argument('window-size=1920x1080')
                chrome_options.add_argument("disable-gpu")
                chrome_options.add_argument('--no-sandbox')
                chrome_options.add_argument('--disable-dev-shm-usage')
                self.driver = webdriver.Chrome(options=chrome_options)
            except Exception as e:
                logger.warning(f"Selenium не доступен: {e}. Будут использоваться только requests.")
                self.use_selenium = False
    
    def __del__(self):
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
    
    def _normalize_vulnerability(self, cve_id: str, title: str, description: str, 
                                 cvss_score: float, source: str, link: str, 
                                 affected_packages: Optional[List[str]] = None) -> Dict[str, Any]:
        """Нормализация уязвимости в стандартный формат"""
        return {
            'cve_id': cve_id,
            'title': title or cve_id,
            'description': description or '',
            'cvss_score': cvss_score,
            'severity': self._cvss_to_severity(cvss_score),
            'source': source,
            'source_identifier': source,
            'url': link,
            'affected_packages': affected_packages or [],
            'references': [link] if link else [],
            'published_date': datetime.now(),
            'last_modified': datetime.now()
        }
    
    def _cvss_to_severity(self, cvss: float) -> str:
        """Преобразование CVSS в severity"""
        if cvss >= 9.0:
            return 'critical'
        elif cvss >= 7.0:
            return 'high'
        elif cvss >= 4.0:
            return 'medium'
        else:
            return 'low'
    
    def parse_cvedetails_keywords(self) -> List[Dict[str, Any]]:
        """
        Парсинг ключевых слов с cvedetails.com для обновления словаря
        Возвращает список продуктов с их оценками
        """
        vulnerabilities = []
        
        try:
            url = 'https://www.cvedetails.com/top-50-product-cvssscore-distribution.php'
            
            if self.use_selenium and self.driver:
                self.driver.get(url)
                page = self.driver.page_source
            else:
                response = self.session.get(url, timeout=30)
                response.raise_for_status()
                page = response.text
            
            soup = BeautifulSoup(page, 'html.parser')
            
            products = []
            scores = []
            
            table = soup.find('table', {'class': 'grid'})
            if table:
                tbody = table.find('tbody')
                if tbody:
                    rows = tbody.findChildren('tr')
                    for row in rows[2:]:  # Пропускаем заголовки
                        try:
                            product_cell = row.findChildren('td')[1]
                            product_link = product_cell.find('a')
                            if product_link:
                                products.append(product_link.text.strip())
                            
                            score_cell = row.findChildren('td')[14]
                            if score_cell:
                                scores.append(float(score_cell.text.strip()) * 10)
                        except (IndexError, ValueError, AttributeError):
                            continue
            
            # Возвращаем данные для обновления словаря
            # (это не уязвимости, а продукты для словаря)
            for product, score in zip(products, scores):
                vulnerabilities.append({
                    'keyword': product,
                    'price': score,
                    'source': 'cvedetails'
                })
            
            logger.info(f"CVEDetails: найдено {len(products)} продуктов")
        except Exception as e:
            logger.error(f"Ошибка парсинга CVEDetails: {e}", exc_info=True)
        
        return vulnerabilities
    
    def parse_cxsecurity(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Парсинг с cxsecurity.com"""
        vulnerabilities = []
        
        try:
            for page_num in range(1, min(6, (limit // 10) + 2)):  # Примерно 10 на страницу
                url = f'https://cxsecurity.com/cvemap/{page_num}'
                
                if self.use_selenium and self.driver:
                    self.driver.get(url)
                    page = self.driver.page_source
                else:
                    response = self.session.get(url, timeout=30)
                    response.raise_for_status()
                    page = response.text
                
                soup = BeautifulSoup(page, 'html.parser')
                
                for quote in soup.find_all('h6'):
                    try:
                        cve_link = quote.findNext('a')
                        if not cve_link:
                            continue
                        
                        cve_id = cve_link.text.strip()
                        if not cve_id.startswith('CVE-'):
                            continue
                        
                        description_elem = quote.findNext('a').findNext('a')
                        description = description_elem.text if description_elem else ''
                        link = 'https://cxsecurity.com/cveshow/' + cve_id
                        
                        vuln = self._normalize_vulnerability(
                            cve_id=cve_id,
                            title=cve_id,
                            description=description,
                            cvss_score=5.0,  # По умолчанию
                            source='cxsecurity',
                            link=link
                        )
                        vulnerabilities.append(vuln)
                        
                        if len(vulnerabilities) >= limit:
                            break
                    except Exception as e:
                        logger.warning(f"Ошибка обработки элемента cxsecurity: {e}")
                        continue
                
                if len(vulnerabilities) >= limit:
                    break
            
            logger.info(f"CXSecurity: спарсено {len(vulnerabilities)} уязвимостей")
        except Exception as e:
            logger.error(f"Ошибка парсинга CXSecurity: {e}", exc_info=True)
        
        return vulnerabilities[:limit]
    
    def parse_cert(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Парсинг с us-cert.cisa.gov/ics/advisories"""
        vulnerabilities = []
        
        try:
            url = 'https://us-cert.cisa.gov/ics/advisories?items_per_page=25'
            
            if self.use_selenium and self.driver:
                self.driver.get(url)
                page = self.driver.page_source
            else:
                response = self.session.get(url, timeout=30)
                response.raise_for_status()
                page = response.text
            
            soup = BeautifulSoup(page, 'html.parser')
            
            advisory_links = []
            for link in soup.find_all('a', href=re.compile("/ics/advisories")):
                if link.get('href'):
                    advisory_links.append('https://us-cert.cisa.gov' + link['href'])
            
            # Ограничиваем количество
            advisory_links = advisory_links[:min(len(advisory_links), limit // 2)]
            
            for advisory_url in advisory_links:
                try:
                    response = self.session.get(advisory_url, timeout=30)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    for quote in soup.find_all('a', href=re.compile("CVE-")):
                        cve_id = quote.text.strip()
                        if not cve_id.startswith('CVE-'):
                            continue
                        
                        # Извлечение CVSS
                        cvss_score = 5.0
                        try:
                            next_sibling = quote.next_sibling
                            if next_sibling:
                                cvss_match = re.search(r'A CVSS v3 base score of ([\d.]+)', str(next_sibling))
                                if cvss_match:
                                    cvss_score = float(cvss_match.group(1))
                        except:
                            pass
                        
                        # Извлечение описания
                        description = ''
                        try:
                            parent = quote.find_parent()
                            if parent:
                                prev_sibling = parent.previous_sibling
                                if prev_sibling:
                                    description = str(prev_sibling).replace('&lt;/p&gt;', '').replace('&lt;p&gt;', '')
                        except:
                            pass
                        
                        vuln = self._normalize_vulnerability(
                            cve_id=cve_id,
                            title=cve_id,
                            description=description,
                            cvss_score=cvss_score,
                            source='us-cert',
                            link=advisory_url
                        )
                        vulnerabilities.append(vuln)
                        
                        if len(vulnerabilities) >= limit:
                            break
                except Exception as e:
                    logger.warning(f"Ошибка обработки advisory {advisory_url}: {e}")
                    continue
                
                if len(vulnerabilities) >= limit:
                    break
            
            logger.info(f"US-CERT: спарсено {len(vulnerabilities)} уязвимостей")
        except Exception as e:
            logger.error(f"Ошибка парсинга US-CERT: {e}", exc_info=True)
        
        return vulnerabilities[:limit]
    
    def parse_cisco(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Парсинг с tools.cisco.com"""
        vulnerabilities = []
        
        try:
            url = 'https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml'
            
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'xml')
            
            descriptions = []
            links = []
            cve_lists = []
            
            for desc in soup.find_all('description')[1:]:
                descriptions.append(desc.text)
            
            for link in soup.find_all('link')[2:]:
                links.append(link.text)
            
            for item in soup.find_all('item'):
                text = item.text
                cves = re.findall(r"CVE-\d{4}-\d+", text)
                cve_lists.append(list(set(cves)))
            
            # Извлечение CVSS для каждого advisory
            cvss_scores = []
            for link_url in links:
                try:
                    if self.use_selenium and self.driver:
                        self.driver.get(link_url)
                        page = self.driver.page_source
                    else:
                        response = self.session.get(link_url, timeout=30)
                        response.raise_for_status()
                        page = response.text
                    
                    soup_page = BeautifulSoup(page, 'html.parser')
                    cvss_elem = soup_page.find('div', {'class': 'udheadercol1'})
                    if cvss_elem:
                        cvss_link = cvss_elem.find('a', text=re.compile(r'\d+\.\d+'))
                        if cvss_link:
                            cvss_text = re.sub(r"[^0-9.]", "", cvss_link.text)
                            cvss_scores.append(float(cvss_text) if cvss_text else 5.0)
                        else:
                            cvss_scores.append(5.0)
                    else:
                        cvss_scores.append(5.0)
                except Exception as e:
                    logger.warning(f"Ошибка получения CVSS для {link_url}: {e}")
                    cvss_scores.append(5.0)
            
            # Объединение данных
            for link_url, cves, desc, cvss in zip(links, cve_lists, descriptions, cvss_scores):
                for cve_id in cves:
                    if len(vulnerabilities) >= limit:
                        break
                    
                    vuln = self._normalize_vulnerability(
                        cve_id=cve_id,
                        title=cve_id,
                        description=desc,
                        cvss_score=cvss,
                        source='cisco',
                        link=link_url
                    )
                    vulnerabilities.append(vuln)
            
            logger.info(f"Cisco: спарсено {len(vulnerabilities)} уязвимостей")
        except Exception as e:
            logger.error(f"Ошибка парсинга Cisco: {e}", exc_info=True)
        
        return vulnerabilities[:limit]
    
    def parse_cybersecurity_help(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Парсинг с cybersecurity-help.cz"""
        vulnerabilities = []
        
        try:
            url = 'https://www.cybersecurity-help.cz/vdb/list.php'
            
            if self.use_selenium and self.driver:
                self.driver.get(url)
                page = self.driver.page_source
            else:
                response = self.session.get(url, timeout=30)
                response.raise_for_status()
                page = response.text
            
            soup = BeautifulSoup(page, 'html.parser')
            
            links = []
            for quote in soup.find_all('span', {'class': 'cvp_title'}):
                link_elem = quote.find('a', href=re.compile("/vdb/"))
                if link_elem and link_elem.get('href'):
                    links.append('https://www.cybersecurity-help.cz' + link_elem['href'])
            
            links = links[:min(len(links), limit)]
            
            for link_url in links:
                try:
                    response = self.session.get(link_url, timeout=30)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    for quote in soup.find_all('div', {'class': 'cve'}):
                        cve_elem = quote.find('p')
                        if not cve_elem:
                            continue
                        
                        cve_text = None
                        for p in quote.find_all('p'):
                            text = p.get_text()
                            cve_match = re.search(r'CVE-\d{4}-\d+', text)
                            if cve_match:
                                cve_text = cve_match.group()
                                break
                        
                        if not cve_text:
                            continue
                        
                        # Описание
                        description = ''
                        try:
                            desc_elem = quote.find('b', text=re.compile('Description'))
                            if desc_elem:
                                desc_p = desc_elem.findNext('p')
                                if desc_p:
                                    description = desc_p.get_text()
                            
                            title_elem = soup.find('div', {'class': 'x_title'})
                            if title_elem:
                                title_h2 = title_elem.find('h2')
                                if title_h2:
                                    description = title_h2.get_text() + ' ' + description
                        except:
                            pass
                        
                        # CVSS
                        cvss_score = 5.0
                        try:
                            cvss_elem = quote.find('a', text=re.compile('CVSS'))
                            if cvss_elem:
                                cvss_text = re.sub(r"[^0-9.]", "", cvss_elem.text[:3])
                                if cvss_text:
                                    cvss_score = float(cvss_text)
                        except:
                            pass
                        
                        vuln = self._normalize_vulnerability(
                            cve_id=cve_text,
                            title=cve_text,
                            description=description.replace('\r', '').replace('\n', '').replace('\t', ''),
                            cvss_score=cvss_score,
                            source='cybersecurity-help',
                            link=link_url
                        )
                        vulnerabilities.append(vuln)
                        
                        if len(vulnerabilities) >= limit:
                            break
                except Exception as e:
                    logger.warning(f"Ошибка обработки {link_url}: {e}")
                    continue
                
                if len(vulnerabilities) >= limit:
                    break
            
            logger.info(f"Cybersecurity-Help: спарсено {len(vulnerabilities)} уязвимостей")
        except Exception as e:
            logger.error(f"Ошибка парсинга Cybersecurity-Help: {e}", exc_info=True)
        
        return vulnerabilities[:limit]
    
    def parse_fortiguard(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Парсинг с fortiguard.com/zeroday"""
        vulnerabilities = []
        
        try:
            url = 'https://www.fortiguard.com/zeroday'
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            links = []
            for quote in soup.find_all('div', {'class': 'title'}):
                link_elem = quote.find('a')
                if link_elem and link_elem.get('href'):
                    links.append('https://www.fortiguard.com' + link_elem['href'])
            
            identifiers = []
            for quote in soup.find_all('div', {'class': 'line'}):
                cve_link = quote.find('a', href=re.compile("http://cve.mitre.org/"))
                if cve_link:
                    identifiers.append(cve_link.text.strip())
            
            descriptions = []
            for quote in soup.find_all('div', {'class': 'title'}):
                desc_elem = quote.a.find_next_sibling('a')
                if desc_elem:
                    descriptions.append(desc_elem.text.strip())
            
            # CVSS из ID (используется как множитель)
            cvss_scores = []
            for quote in soup.find_all('div', {'class': 'line'}):
                link_elem = quote.find('a')
                if link_elem and link_elem.get('href'):
                    href = link_elem['href']
                    number = re.sub(r'\D', '', href)
                    if number:
                        cvss_scores.append(float(number) * 2)
                    else:
                        cvss_scores.append(5.0)
            
            # Очистка описаний
            descriptions = [re.sub(r"[^а-яА-ЯёЁa-zA-Z0-9-./#!?@: ]", "", str(d)) for d in descriptions]
            
            for link, cve_id, desc, cvss in zip(links, identifiers, descriptions, cvss_scores):
                if len(vulnerabilities) >= limit:
                    break
                
                if not cve_id.startswith('CVE-'):
                    continue
                
                vuln = self._normalize_vulnerability(
                    cve_id=cve_id,
                    title=cve_id,
                    description=desc,
                    cvss_score=min(cvss, 10.0),  # Ограничиваем до 10
                    source='fortiguard',
                    link=link
                )
                vulnerabilities.append(vuln)
            
            logger.info(f"FortiGuard: спарсено {len(vulnerabilities)} уязвимостей")
        except Exception as e:
            logger.error(f"Ошибка парсинга FortiGuard: {e}", exc_info=True)
        
        return vulnerabilities[:limit]
    
    def parse_ibm(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Парсинг с ibm.com/blogs/psirt"""
        vulnerabilities = []
        
        try:
            blog_links = []
            
            for page_num in range(1, min(6, (limit // 10) + 2)):
                url = f'https://www.ibm.com/blogs/psirt/page/{page_num}'
                
                if self.use_selenium and self.driver:
                    self.driver.get(url)
                    page = self.driver.page_source
                else:
                    response = self.session.get(url, timeout=30)
                    response.raise_for_status()
                    page = response.text
                
                soup = BeautifulSoup(page, 'html.parser')
                
                for quote in soup.find_all('a', {'class': 'ibm-blog__header-link'}):
                    if quote.get('href'):
                        blog_links.append(quote['href'])
            
            blog_links = blog_links[:min(len(blog_links), limit // 2)]
            
            for blog_url in blog_links:
                try:
                    response = self.session.get(blog_url, timeout=30)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    for quote in soup.find_all('a', href=re.compile("cve.mitre")):
                        cve_id = quote.text.strip()
                        if not cve_id.startswith('CVE-'):
                            continue
                        
                        # Описание
                        description = ''
                        try:
                            main_div = soup.find('div', {'class': 'ibm-blog__article-main'})
                            if main_div:
                                desc_p = main_div.findChildren('p')
                                if len(desc_p) > 4:
                                    description = desc_p[4].get_text()
                        except:
                            pass
                        
                        # Severity -> CVSS
                        cvss_score = 5.0
                        try:
                            main_div = soup.find('div', {'class': 'ibm-blog__article-main'})
                            if main_div:
                                severity_p = main_div.findChildren('p')
                                if len(severity_p) > 1:
                                    severity_text = severity_p[1].get_text()
                                    if 'Critical' in severity_text:
                                        cvss_score = 10.0
                                    elif 'High' in severity_text:
                                        cvss_score = 8.0
                                    elif 'Medium' in severity_text:
                                        cvss_score = 5.0
                                    elif 'Low' in severity_text:
                                        cvss_score = 3.0
                        except:
                            pass
                        
                        vuln = self._normalize_vulnerability(
                            cve_id=cve_id,
                            title=cve_id,
                            description=description,
                            cvss_score=cvss_score,
                            source='IBM',
                            link=blog_url
                        )
                        vulnerabilities.append(vuln)
                        
                        if len(vulnerabilities) >= limit:
                            break
                except Exception as e:
                    logger.warning(f"Ошибка обработки IBM blog {blog_url}: {e}")
                    continue
                
                if len(vulnerabilities) >= limit:
                    break
            
            logger.info(f"IBM: спарсено {len(vulnerabilities)} уязвимостей")
        except Exception as e:
            logger.error(f"Ошибка парсинга IBM: {e}", exc_info=True)
        
        return vulnerabilities[:limit]
    
    def parse_juniper(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Парсинг с kb.juniper.net"""
        vulnerabilities = []
        
        try:
            advisory_links = []
            
            for offset in range(0, min(60, limit * 2), 15):
                url = f'https://kb.juniper.net/InfoCenter/index?page=content&channel=SECURITY_ADVISORIES&cat=SIRT_1&actp=&sort=datemodified&dir=descending&max=1000&batch=15&rss=true&itData.offset={offset}'
                
                if self.use_selenium and self.driver:
                    self.driver.get(url)
                    page = self.driver.page_source
                else:
                    response = self.session.get(url, timeout=30)
                    response.raise_for_status()
                    page = response.text
                
                soup = BeautifulSoup(page, 'html.parser')
                
                for quote in soup.find_all('a', href=re.compile("LIST&showDraft")):
                    if quote.get('href'):
                        advisory_links.append('https://kb.juniper.net/InfoCenter/' + quote['href'])
            
            advisory_links = advisory_links[:min(len(advisory_links), limit // 2)]
            
            for advisory_url in advisory_links:
                try:
                    response = self.session.get(advisory_url, timeout=30)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Поиск CVE ссылок
                    for quote in soup.find_all('a', href=re.compile("cve.mitre")):
                        if re.search('at cve.mitre', str(quote)):
                            continue
                        
                        cve_text = quote.text.strip()
                        if ':' in cve_text:
                            cve_id = cve_text.split(':')[0]
                        else:
                            cve_id = cve_text
                        
                        if not cve_id.startswith('CVE-'):
                            continue
                        
                        # Описание
                        description = ''
                        try:
                            content_div = soup.find('div', {'class': 'content nonfileattachment'})
                            if content_div:
                                description = content_div.get_text().rstrip()
                        except:
                            pass
                        
                        # Severity -> CVSS
                        cvss_score = 5.0
                        try:
                            contentlist_div = soup.find('div', {'class': 'content contentlist'})
                            if contentlist_div:
                                severity_text = contentlist_div.get_text()
                                if 'Critical' in severity_text:
                                    cvss_score = 10.0
                                elif 'High' in severity_text:
                                    cvss_score = 8.0
                                elif 'Medium' in severity_text:
                                    cvss_score = 5.0
                                elif 'Low' in severity_text:
                                    cvss_score = 3.0
                        except:
                            pass
                        
                        vuln = self._normalize_vulnerability(
                            cve_id=cve_id,
                            title=cve_id,
                            description=description,
                            cvss_score=cvss_score,
                            source='juniper',
                            link=advisory_url
                        )
                        vulnerabilities.append(vuln)
                    
                    # Поиск в таблице
                    table = soup.find('table', {'class': 'striped'})
                    if table:
                        tbody = table.find('tbody')
                        if tbody:
                            rows = tbody.findChildren('tr')
                            for row in rows[1:]:  # Пропускаем заголовок
                                try:
                                    cells = row.findChildren('td')
                                    if len(cells) >= 3:
                                        cve_cell = cells[0]
                                        cvss_cell = cells[1]
                                        desc_cell = cells[2]
                                        
                                        cve_text = cve_cell.get_text().strip()
                                        if ':' in cve_text:
                                            cve_id = cve_text.split(':')[0]
                                        else:
                                            cve_id = cve_text
                                        
                                        if not cve_id.startswith('CVE-'):
                                            continue
                                        
                                        cvss_text = cvss_cell.get_text()[:3].strip()
                                        if cvss_text and cvss_text != '\xa0':
                                            cvss_score = float(cvss_text)
                                        else:
                                            cvss_score = 1.0
                                        
                                        description = desc_cell.get_text().strip()
                                        
                                        vuln = self._normalize_vulnerability(
                                            cve_id=cve_id,
                                            title=cve_id,
                                            description=description,
                                            cvss_score=cvss_score,
                                            source='juniper',
                                            link=advisory_url
                                        )
                                        vulnerabilities.append(vuln)
                                        
                                        if len(vulnerabilities) >= limit:
                                            break
                                except Exception as e:
                                    logger.warning(f"Ошибка обработки строки таблицы Juniper: {e}")
                                    continue
                except Exception as e:
                    logger.warning(f"Ошибка обработки Juniper advisory {advisory_url}: {e}")
                    continue
                
                if len(vulnerabilities) >= limit:
                    break
            
            logger.info(f"Juniper: спарсено {len(vulnerabilities)} уязвимостей")
        except Exception as e:
            logger.error(f"Ошибка парсинга Juniper: {e}", exc_info=True)
        
        return vulnerabilities[:limit]
    
    def parse_kaspersky_stat(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Парсинг с statistics.securelist.com"""
        vulnerabilities = []
        
        try:
            urls = [
                'https://statistics.securelist.com/ru/vulnerability-scan/week',
                'https://statistics.securelist.com/ru/vulnerability-scan/day',
                'https://statistics.securelist.com/ru/vulnerability-scan/month'
            ]
            
            all_cves = set()
            
            for url in urls:
                if self.use_selenium and self.driver:
                    self.driver.get(url)
                    page = self.driver.page_source
                else:
                    response = self.session.get(url, timeout=30)
                    response.raise_for_status()
                    page = response.text
                
                soup = BeautifulSoup(page, 'html.parser')
                
                for quote in soup.find_all('a', href=re.compile("CVE")):
                    if quote.get('href'):
                        href = quote['href']
                        cve_match = re.search(r'CVE-\d{4}-\d+', href)
                        if cve_match:
                            all_cves.add(cve_match.group())
            
            # Получение описаний с CVE.mitre.org
            for cve_id in list(all_cves)[:limit]:
                try:
                    url = f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}'
                    
                    if self.use_selenium and self.driver:
                        self.driver.get(url)
                        page = self.driver.page_source
                    else:
                        response = self.session.get(url, timeout=30)
                        response.raise_for_status()
                        page = response.text
                    
                    soup = BeautifulSoup(page, 'html.parser')
                    
                    description = ''
                    try:
                        table = soup.find('div', {'id': 'GeneratedTable'})
                        if table:
                            tbody = table.find('table').find('tbody')
                            if tbody:
                                rows = tbody.findChildren('tr')
                                if len(rows) > 3:
                                    desc_cell = rows[3].find('td')
                                    if desc_cell:
                                        description = desc_cell.get_text().replace('\n', '')
                    except:
                        pass
                    
                    vuln = self._normalize_vulnerability(
                        cve_id=cve_id,
                        title=cve_id,
                        description=description,
                        cvss_score=9.0,  # Высокий приоритет
                        source='kaspersky',
                        link=f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}'
                    )
                    vulnerabilities.append(vuln)
                except Exception as e:
                    logger.warning(f"Ошибка получения описания для {cve_id}: {e}")
                    continue
            
            logger.info(f"Kaspersky Stat: спарсено {len(vulnerabilities)} уязвимостей")
        except Exception as e:
            logger.error(f"Ошибка парсинга Kaspersky Stat: {e}", exc_info=True)
        
        return vulnerabilities[:limit]
    
    def parse_kaspersky(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Парсинг с support.kaspersky.ru"""
        vulnerabilities = []
        
        try:
            url = 'https://support.kaspersky.ru/general/vulnerability.aspx?el=12430'
            
            if self.use_selenium and self.driver:
                self.driver.get(url)
                page = self.driver.page_source
            else:
                response = self.session.get(url, timeout=30)
                response.raise_for_status()
                page = response.text
            
            soup = BeautifulSoup(page, 'html.parser')
            
            cve_ids = []
            links = []
            descriptions = []
            
            block = soup.find('div', {'class': 'block cur'})
            if block:
                for quote in block.find_all('div', {'class': 'wincont_c3'}):
                    link_elem = quote.find('div', {'class': 'w_cont'}).find('a', {'class': 'open'}, href=True)
                    if link_elem and link_elem.get('href'):
                        cve_id = link_elem['href'].strip()
                        cve_ids.append(cve_id)
                        links.append('https://support.kaspersky.ru/general/vulnerability.aspx?el=12430' + link_elem['href'])
                
                for quote in block.find_all('div', {'class': 'wincont_c3'}):
                    note_div = quote.find('div', {'id': 'note'})
                    if note_div:
                        descriptions.append(note_div.get_text().replace('\n', ' '))
            
            for cve_id, link, desc in zip(cve_ids[:limit], links[:limit], descriptions[:limit]):
                vuln = self._normalize_vulnerability(
                    cve_id=cve_id,
                    title=cve_id,
                    description=desc,
                    cvss_score=10.0,  # Критический приоритет
                    source='kaspersky',
                    link=link
                )
                vulnerabilities.append(vuln)
            
            logger.info(f"Kaspersky: спарсено {len(vulnerabilities)} уязвимостей")
        except Exception as e:
            logger.error(f"Ошибка парсинга Kaspersky: {e}", exc_info=True)
        
        return vulnerabilities[:limit]
    
    def parse_paloalto(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Парсинг с security.paloaltonetworks.com"""
        vulnerabilities = []
        
        try:
            url = 'https://security.paloaltonetworks.com/?sort=-date&limit=100'
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            links = []
            identifiers = []
            descriptions = []
            cvss_scores = []
            
            for quote in soup.find_all('a', href=re.compile("CVE|PAN-SA")):
                href = quote.get('href')
                if href:
                    links.append('https://security.paloaltonetworks.com' + href)
                    identifiers.append(href.replace('/', ''))
                    descriptions.append(quote.get_text().strip())
            
            # CVSS из тегов <b>
            for quote in soup.find_all('b'):
                text = quote.get_text().strip()
                try:
                    cvss_scores.append(float(text))
                except ValueError:
                    pass
            
            # Фильтрация (убираем записи с CVSS 0)
            filtered_data = []
            for link, ident, desc, cvss in zip(links, identifiers, descriptions, cvss_scores):
                if cvss > 0:
                    filtered_data.append((link, ident, desc, cvss))
            
            for link, ident, desc, cvss in filtered_data[:limit]:
                vuln = self._normalize_vulnerability(
                    cve_id=ident if ident.startswith('CVE-') else ident,
                    title=ident,
                    description=desc,
                    cvss_score=cvss,
                    source='paloalto',
                    link=link
                )
                vulnerabilities.append(vuln)
            
            logger.info(f"Palo Alto: спарсено {len(vulnerabilities)} уязвимостей")
        except Exception as e:
            logger.error(f"Ошибка парсинга Palo Alto: {e}", exc_info=True)
        
        return vulnerabilities[:limit]
    
    def parse_postgresql(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Парсинг с postgresql.org/support/security"""
        vulnerabilities = []
        
        try:
            url = 'https://www.postgresql.org/support/security/'
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            
            descriptions = []
            for quote in soup.find_all('td'):
                if quote:
                    next_sibling = quote.next_sibling
                    if next_sibling:
                        descriptions.append(str(next_sibling))
            
            # Фильтрация описаний
            filtered_descriptions = []
            for desc in descriptions:
                if desc and 'more details' in desc.lower():
                    left_marker = '&lt;td&gt;'
                    right_marker = '&lt;br/&gt;&lt;br/&gt;&lt;a'
                    if left_marker in desc and right_marker in desc:
                        start = desc.index(left_marker) + len(left_marker)
                        end = desc.index(right_marker)
                        filtered_descriptions.append(desc[start:end])
            
            cve_ids = []
            links = []
            for quote in soup.find_all('nobr'):
                link_elem = quote.find('a')
                if link_elem:
                    cve_ids.append(link_elem.get_text().strip())
                    if link_elem.get('href'):
                        links.append('https://www.postgresql.org' + link_elem['href'])
            
            cvss_scores = []
            for quote in soup.find_all("a", href=re.compile("nvd")):
                cvss_text = quote.get_text().strip()
                try:
                    cvss_scores.append(float(cvss_text))
                except ValueError:
                    cvss_scores.append(5.0)
            
            for cve_id, link, desc, cvss in zip(cve_ids[:limit], links[:limit], filtered_descriptions[:limit], cvss_scores[:limit]):
                if not cve_id.startswith('CVE-'):
                    continue
                
                vuln = self._normalize_vulnerability(
                    cve_id=cve_id,
                    title=cve_id,
                    description=desc,
                    cvss_score=cvss,
                    source='PostgreSQL',
                    link=link
                )
                vulnerabilities.append(vuln)
            
            logger.info(f"PostgreSQL: спарсено {len(vulnerabilities)} уязвимостей")
        except Exception as e:
            logger.error(f"Ошибка парсинга PostgreSQL: {e}", exc_info=True)
        
        return vulnerabilities[:limit]
    
    def parse_suse(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Парсинг с suse.com/security/cve"""
        vulnerabilities = []
        
        try:
            url = 'https://www.suse.com/security/cve/'
            
            if self.use_selenium and self.driver:
                self.driver.get(url)
                page = self.driver.page_source
            else:
                response = self.session.get(url, timeout=30)
                response.raise_for_status()
                page = response.text
            
            soup = BeautifulSoup(page, 'html.parser')
            
            cve_ids = []
            links = []
            
            for quote in soup.find_all('a', href=re.compile("CVE-202")):
                cve_id = quote.get_text().strip()
                if cve_id.startswith('CVE-'):
                    cve_ids.append(cve_id)
                    links.append('https://www.suse.com/security/cve/' + cve_id)
            
            cve_ids = cve_ids[:limit]
            links = links[:limit]
            
            descriptions = []
            cvss_scores = []
            
            for link_url in links:
                try:
                    response = self.session.get(link_url, timeout=30)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Описание
                    description = ''
                    try:
                        pad_div = soup.find('div', {'class': 'standard-pad white-bg'})
                        if pad_div:
                            h4 = pad_div.find('h4')
                            if h4:
                                description = h4.next_sibling.replace('\n', '') if h4.next_sibling else ''
                    except:
                        pass
                    descriptions.append(description)
                    
                    # CVSS из таблицы
                    cvss_score = 5.0
                    try:
                        table = soup.find('table', {'border': '1'})
                        if table:
                            rows = table.find_all('tr')
                            if len(rows) > 2:
                                row = rows[2]
                                cells = row.find_all('td')
                                if len(cells) > 1:
                                    cvss_cell = cells[1]
                                    cvss_text = cvss_cell.get_text()[:3]
                                    if cvss_text:
                                        cvss_score = float(cvss_text)
                    except:
                        pass
                    cvss_scores.append(cvss_score)
                except Exception as e:
                    logger.warning(f"Ошибка обработки SUSE {link_url}: {e}")
                    descriptions.append('')
                    cvss_scores.append(5.0)
            
            for cve_id, link, desc, cvss in zip(cve_ids, links, descriptions, cvss_scores):
                vuln = self._normalize_vulnerability(
                    cve_id=cve_id,
                    title=cve_id,
                    description=desc,
                    cvss_score=cvss,
                    source='SUSE',
                    link=link
                )
                vulnerabilities.append(vuln)
            
            logger.info(f"SUSE: спарсено {len(vulnerabilities)} уязвимостей")
        except Exception as e:
            logger.error(f"Ошибка парсинга SUSE: {e}", exc_info=True)
        
        return vulnerabilities[:limit]
    
    def parse_zerodayinitiative(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Парсинг с zerodayinitiative.com"""
        vulnerabilities = []
        
        try:
            url = 'https://www.zerodayinitiative.com/advisories/published/'
            
            if self.use_selenium and self.driver:
                self.driver.get(url)
                page = self.driver.page_source
            else:
                response = self.session.get(url, timeout=30)
                response.raise_for_status()
                page = response.text
            
            soup = BeautifulSoup(page, 'xml')
            
            cve_ids = []
            zdi_ids = []
            
            for quote in soup.find_all('td', text=re.compile("CVE-")):
                cve_id = quote.get_text().strip()
                if cve_id.startswith('CVE-'):
                    cve_ids.append(cve_id)
                    # Получение ZDI ID
                    prev_elem = quote.previous_element
                    for _ in range(5):
                        if prev_elem and hasattr(prev_elem, 'get_text'):
                            text = prev_elem.get_text()
                            if 'ZDI-' in text:
                                zdi_ids.append(text.strip())
                                break
                        prev_elem = getattr(prev_elem, 'previous_element', None)
                    else:
                        zdi_ids.append('')
            
            advisory_links = ['https://www.zerodayinitiative.com/advisories/' + zdi_id for zdi_id in zdi_ids]
            
            for cve_id, advisory_url in zip(cve_ids[:limit], advisory_links[:limit]):
                try:
                    response = self.session.get(advisory_url, timeout=30)
                    response.raise_for_status()
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # CVSS из ссылки на NVD
                    cvss_score = 5.0
                    try:
                        nvd_link = soup.find('a', href=re.compile("http://nvd.nist.gov/"))
                        if nvd_link:
                            prev_text = nvd_link.previous_element
                            if prev_text:
                                cvss_match = re.search(r'[\d.]+', str(prev_text))
                                if cvss_match:
                                    cvss_score = float(cvss_match.group())
                    except:
                        pass
                    
                    # Описание
                    description = ''
                    try:
                        desc_text = soup.find(text=re.compile("This vulnerability"))
                        if desc_text:
                            description = desc_text.strip()
                    except:
                        pass
                    
                    vuln = self._normalize_vulnerability(
                        cve_id=cve_id,
                        title=cve_id,
                        description=description,
                        cvss_score=cvss_score,
                        source='zerodayinitiative',
                        link=advisory_url
                    )
                    vulnerabilities.append(vuln)
                except Exception as e:
                    logger.warning(f"Ошибка обработки Zero Day Initiative {advisory_url}: {e}")
                    continue
            
            logger.info(f"Zero Day Initiative: спарсено {len(vulnerabilities)} уязвимостей")
        except Exception as e:
            logger.error(f"Ошибка парсинга Zero Day Initiative: {e}", exc_info=True)
        
        return vulnerabilities[:limit]
    
    def parse_nvd_by_keywords(self, keywords: List[str], limit: int = 50) -> List[Dict[str, Any]]:
        """
        Парсинг NVD по ключевым словам
        Загружает recent JSON и фильтрует по ключевым словам
        """
        vulnerabilities = []
        
        try:
            # Загрузка recent NVD JSON
            url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip'
            response = self.session.get(url, stream=True, timeout=60)
            response.raise_for_status()
            
            # Сохранение во временный файл
            with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
                tmp_file.write(response.content)
                tmp_path = tmp_file.name
            
            try:
                # Распаковка и парсинг
                with zipfile.ZipFile(tmp_path, 'r') as archive:
                    json_files = [f for f in archive.namelist() if f.endswith('.json')]
                    if json_files:
                        json_content = archive.read(json_files[0])
                        json_data = json.loads(json_content)
                        
                        # Фильтрация по ключевым словам
                        keywords_lower = [kw.lower() for kw in keywords]
                        
                        for item in json_data.get('CVE_Items', []):
                            if len(vulnerabilities) >= limit:
                                break
                            
                            cve_id = item.get('cve', {}).get('CVE_data_meta', {}).get('ID', '')
                            if not cve_id:
                                continue
                            
                            # Описание
                            description = ''
                            try:
                                desc_data = item.get('cve', {}).get('description', {}).get('description_data', [])
                                if desc_data:
                                    description = desc_data[0].get('value', '')
                            except:
                                pass
                            
                            # Проверка ключевых слов в описании
                            description_lower = description.lower()
                            if any(kw in description_lower for kw in keywords_lower):
                                # CVSS
                                cvss_score = 3.0
                                try:
                                    impact = item.get('impact', {})
                                    base_metric = impact.get('baseMetricV3', {})
                                    cvss_data = base_metric.get('cvssV3', {})
                                    cvss_score = float(cvss_data.get('baseScore', 3.0))
                                except:
                                    pass
                                
                                vuln = self._normalize_vulnerability(
                                    cve_id=cve_id,
                                    title=cve_id,
                                    description=description,
                                    cvss_score=cvss_score,
                                    source='NVD',
                                    link=f'https://nvd.nist.gov/vuln/detail/{cve_id}'
                                )
                                vulnerabilities.append(vuln)
            finally:
                # Удаление временного файла
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            
            logger.info(f"NVD (by keywords): спарсено {len(vulnerabilities)} уязвимостей")
        except Exception as e:
            logger.error(f"Ошибка парсинга NVD (by keywords): {e}", exc_info=True)
        
        return vulnerabilities[:limit]


# Глобальный экземпляр
vendor_parsers = VendorParsers(use_selenium=False)  # По умолчанию без Selenium

