"""
Адаптивный HTML парсер для мониторинга сайтов
Автоматически определяет структуру страницы и адаптируется под неё
"""
import logging
import requests
from bs4 import BeautifulSoup
from typing import Dict, Any, List, Optional
import re

logger = logging.getLogger(__name__)


class AdaptiveHTMLParser:
    """
    Адаптивный парсер HTML страниц
    Автоматически определяет структуру и извлекает данные об уязвимостях
    """
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def parse_page(self, url: str, config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Парсинг страницы с уязвимостями
        
        Args:
            url: URL страницы
            config: Конфигурация парсера (селекторы, если известны)
            
        Returns:
            Список уязвимостей
        """
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Если есть конфигурация, используем её
            if config and config.get('selectors'):
                return self._parse_with_config(soup, config['selectors'])
            
            # Иначе автоматически определяем структуру
            return self._auto_detect_and_parse(soup, url)
        except Exception as e:
            logger.error(f"Ошибка парсинга {url}: {e}")
            return []
    
    def _parse_with_config(self, soup: BeautifulSoup, selectors: Dict[str, str]) -> List[Dict[str, Any]]:
        """Парсинг с использованием конфигурации"""
        vulnerabilities = []
        
        # Находим список уязвимостей
        list_selector = selectors.get('vulnerability_list', 'article, .vulnerability, .cve-item')
        items = soup.select(list_selector)
        
        for item in items:
            try:
                vuln = {
                    'title': self._extract_text(item, selectors.get('title', 'h1, h2, .title')),
                    'description': self._extract_text(item, selectors.get('description', '.description, p')),
                    'cve_id': self._extract_text(item, selectors.get('cve_id', '.cve, [class*="cve"]')),
                    'url': self._extract_url(item, selectors.get('link', 'a'))
                }
                
                if vuln.get('cve_id') or vuln.get('title'):
                    vulnerabilities.append(vuln)
            except Exception as e:
                logger.warning(f"Ошибка парсинга элемента: {e}")
                continue
        
        return vulnerabilities
    
    def _auto_detect_and_parse(self, soup: BeautifulSoup, url: str) -> List[Dict[str, Any]]:
        """Автоматическое определение структуры и парсинг"""
        vulnerabilities = []
        
        # Поиск CVE ID в тексте
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
        
        # Ищем статьи, карточки, списки
        potential_items = soup.find_all(['article', 'div'], class_=re.compile(r'vuln|cve|security', re.I))
        
        if not potential_items:
            # Пробуем найти таблицы
            tables = soup.find_all('table')
            for table in tables:
                rows = table.find_all('tr')
                for row in rows:
                    text = row.get_text()
                    cve_match = cve_pattern.search(text)
                    if cve_match:
                        vulnerabilities.append({
                            'cve_id': cve_match.group(),
                            'title': text[:200],
                            'description': text,
                            'url': url
                        })
        else:
            for item in potential_items:
                text = item.get_text()
                cve_match = cve_pattern.search(text)
                if cve_match:
                    title_elem = item.find(['h1', 'h2', 'h3', 'h4'])
                    vulnerabilities.append({
                        'cve_id': cve_match.group(),
                        'title': title_elem.get_text() if title_elem else text[:200],
                        'description': text,
                        'url': url
                    })
        
        return vulnerabilities
    
    def _extract_text(self, element, selector: str) -> str:
        """Извлечение текста по селектору"""
        found = element.select_one(selector)
        return found.get_text(strip=True) if found else ''
    
    def _extract_url(self, element, selector: str) -> str:
        """Извлечение URL по селектору"""
        found = element.select_one(selector)
        if found:
            return found.get('href', '') or ''
        return ''

