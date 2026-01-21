"""
Парсер Grafana Security Advisories

Извлекает данные уязвимостей с https://grafana.com/security/security-advisories/
Интегрируется с БДУ ФСТЭК структурой
"""

import requests
from bs4 import BeautifulSoup
from datetime import datetime
from typing import Dict, List, Optional
import re
import time
from urllib.parse import urljoin
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GrafanaSecurityParser:
    """
    Парсер для Grafana Security Advisories
    
    Поддерживает:
    - Парсинг списка advisory
    - Парсинг детальных страниц CVE
    - Кэширование
    - Rate limiting
    - Фильтрацию по severity и product
    """
    
    BASE_URL = "https://grafana.com"
    ADVISORIES_URL = f"{BASE_URL}/security/security-advisories/"
    
    def __init__(self, cache_enabled=True, rate_limit_delay=1.0):
        """
        Инициализация парсера
        
        Args:
            cache_enabled: Включить кэширование
            rate_limit_delay: Задержка между запросами (секунды)
        """
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnerabilityManager/1.0 (Educational Purpose; +https://github.com/vulnerability-manager)'
        })
        
        self.cache_enabled = cache_enabled
        self.rate_limit_delay = rate_limit_delay
        self.last_request_time = None
        
        if cache_enabled:
            try:
                from .grafana_cache import GrafanaCache
                self.cache = GrafanaCache()
            except ImportError:
                logger.warning("⚠️  Cache module not available, running without cache")
                self.cache_enabled = False
        
        logger.info(f"🚀 Grafana Security Parser initialized (cache: {cache_enabled})")
    
    def _rate_limit(self):
        """Соблюдение rate limiting"""
        if self.last_request_time:
            elapsed = (datetime.now() - self.last_request_time).total_seconds()
            if elapsed < self.rate_limit_delay:
                sleep_time = self.rate_limit_delay - elapsed
                logger.debug(f"⏱️  Rate limiting: sleeping {sleep_time:.2f}s")
                time.sleep(sleep_time)
        
        self.last_request_time = datetime.now()
    
    def _fetch_url(self, url: str, use_cache=True) -> str:
        """
        Получить содержимое URL с кэшированием
        
        Args:
            url: URL для запроса
            use_cache: Использовать кэш
        
        Returns:
            HTML содержимое страницы
        """
        # Проверить кэш
        if use_cache and self.cache_enabled:
            cached = self.cache.get(url)
            if cached:
                logger.info(f"📦 Using cache for {url}")
                return cached
        
        # Запрос к серверу
        self._rate_limit()
        logger.info(f"🌐 Fetching {url}")
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            html = response.text
            
            # Сохранить в кэш
            if use_cache and self.cache_enabled:
                self.cache.set(url, html)
            
            return html
        
        except requests.RequestException as e:
            logger.error(f"❌ Error fetching {url}: {e}")
            raise
    
    def fetch_advisories_list(self, severity=None, product=None) -> List[Dict]:
        """
        Получить список всех advisory
        
        Args:
            severity: Фильтр по severity (critical, high, medium, low)
            product: Фильтр по продукту
        
        Returns:
            List[Dict] со структурой:
            {
                'cve_id': 'CVE-2025-41118',
                'severity_text': '● Critical (9.1)',
                'product': 'Pyroscope',
                'advisory_title': 'Exposure of Storage Secret in Pyroscope',
                'advisory_url': '/security/security-advisories/cve-2025-41118/',
                'updated_date': '2025-09-24'
            }
        """
        url = self.ADVISORIES_URL
        
        # Добавить параметры фильтрации (если поддерживаются)
        params = {}
        if severity:
            params['severity'] = severity.lower()
        if product:
            params['product'] = product.lower()
        
        if params:
            from urllib.parse import urlencode
            url = f"{url}?{urlencode(params)}"
        
        html = self._fetch_url(url)
        soup = BeautifulSoup(html, 'html.parser')
        
        advisories = []
        
        # Найти таблицу с advisory
        # Попробуем разные варианты селекторов
        table = soup.find('table')
        
        if not table:
            logger.warning("⚠️  Advisory table not found on page")
            # Попробуем альтернативный способ - поиск по ссылкам
            return self._parse_alternative_format(soup)
        
        rows = table.find_all('tr')
        
        # Пропустить заголовок
        data_rows = rows[1:] if len(rows) > 1 else []
        
        for row in data_rows:
            try:
                cells = row.find_all('td')
                
                if len(cells) < 4:
                    continue
                
                # Извлечь данные
                cve_id = cells[0].text.strip()
                severity_text = cells[1].text.strip()
                product = cells[2].text.strip()
                
                # Advisory title и URL
                title_cell = cells[3]
                title_link = title_cell.find('a')
                advisory_title = title_link.text.strip() if title_link else title_cell.text.strip()
                advisory_url = title_link['href'] if title_link else ''
                
                # Updated date (если есть)
                updated_date = cells[4].text.strip() if len(cells) > 4 else '—'
                
                advisories.append({
                    'cve_id': cve_id,
                    'severity_text': severity_text,
                    'product': product,
                    'advisory_title': advisory_title,
                    'advisory_url': advisory_url,
                    'updated_date': updated_date if updated_date != '—' else None
                })
            
            except Exception as e:
                logger.error(f"❌ Error parsing row: {e}")
                continue
        
        logger.info(f"✅ Parsed {len(advisories)} advisories from list")
        return advisories
    
    def _parse_alternative_format(self, soup) -> List[Dict]:
        """
        Альтернативный парсинг если таблица не найдена
        Ищет ссылки на advisory
        """
        logger.info("🔍 Trying alternative parsing method...")
        advisories = []
        
        # Поиск всех ссылок на CVE
        links = soup.find_all('a', href=re.compile(r'/security/security-advisories/cve-\d{4}-\d+'))
        
        for link in links:
            try:
                url = link['href']
                cve_match = re.search(r'(cve-\d{4}-\d+)', url, re.IGNORECASE)
                if cve_match:
                    cve_id = cve_match.group(1).upper().replace('CVE-', 'CVE-')
                    
                    advisories.append({
                        'cve_id': cve_id,
                        'severity_text': '',
                        'product': '',
                        'advisory_title': link.text.strip(),
                        'advisory_url': url,
                        'updated_date': None
                    })
            except Exception as e:
                logger.error(f"❌ Error parsing link: {e}")
                continue
        
        # Удалить дубликаты
        seen = set()
        unique_advisories = []
        for adv in advisories:
            if adv['cve_id'] not in seen:
                seen.add(adv['cve_id'])
                unique_advisories.append(adv)
        
        logger.info(f"✅ Found {len(unique_advisories)} advisories using alternative method")
        return unique_advisories
    
    def fetch_advisory_detail(self, advisory_url: str) -> Dict:
        """
        Получить детальную информацию об advisory
        
        Args:
            advisory_url: URL advisory (может быть относительным)
        
        Returns:
            Dict со структурой:
            {
                'published_date': '2026-01-02',
                'cvss_score': 9.1,
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
                'fixed_versions': ['>=1.15.2 <1.16.0', '>=1.16.1'],
                'summary': 'Full description...',
                'credits': 'Thanks to...'
            }
        """
        # Построить полный URL
        if not advisory_url.startswith('http'):
            url = urljoin(self.BASE_URL, advisory_url)
        else:
            url = advisory_url
        
        html = self._fetch_url(url)
        soup = BeautifulSoup(html, 'html.parser')
        
        data = {}
        
        # Парсинг метаданных
        # Вариант 1: Структурированные блоки с классами
        data.update(self._parse_metadata_structured(soup))
        
        # Вариант 2: Definition list
        if not data:
            data.update(self._parse_metadata_dl(soup))
        
        # Парсинг контента
        data.update(self._parse_content(soup))
        
        # Парсинг credits
        credits = self._parse_credits(soup)
        if credits:
            data['credits'] = credits
        
        logger.info(f"✅ Parsed advisory detail: {url}")
        return data
    
    def _parse_metadata_structured(self, soup) -> Dict:
        """Парсинг метаданных из структурированных блоков"""
        data = {}
        
        # Поиск элементов с метаданными
        for elem in soup.find_all(['div', 'span', 'p']):
            text = elem.get_text().strip()
            
            # Published date
            if 'published' in text.lower() and ':' in text:
                date_match = re.search(r'(\d{4}-\d{2}-\d{2})', text)
                if date_match:
                    data['published_date'] = date_match.group(1)
            
            # CVSS Score
            if 'cvss score' in text.lower() and ':' in text:
                score_match = re.search(r'(\d+\.\d+)', text)
                if score_match:
                    data['cvss_score'] = float(score_match.group(1))
            
            # CVSS Vector
            if 'cvss:' in text.lower() or 'cvss vector' in text.lower():
                vector_match = re.search(r'(CVSS:\d\.\d/[A-Z:/]+)', text, re.IGNORECASE)
                if vector_match:
                    data['cvss_vector'] = vector_match.group(1)
            
            # Fixed Versions
            if 'fixed' in text.lower() and 'version' in text.lower():
                versions = re.findall(r'>=[\d.]+(?:\s*<[\d.]+)?', text)
                if versions:
                    data['fixed_versions'] = versions
        
        return data
    
    def _parse_metadata_dl(self, soup) -> Dict:
        """Парсинг метаданных из definition list"""
        data = {}
        
        dl = soup.find('dl')
        if not dl:
            return data
        
        dts = dl.find_all('dt')
        dds = dl.find_all('dd')
        
        for dt, dd in zip(dts, dds):
            label = dt.text.strip().rstrip(':').lower()
            value = dd.text.strip()
            
            if 'published' in label:
                data['published_date'] = value
            elif 'cvss score' in label:
                try:
                    data['cvss_score'] = float(value)
                except ValueError:
                    pass
            elif 'cvss vector' in label:
                data['cvss_vector'] = value
            elif 'fixed' in label and 'version' in label:
                versions = [v.strip() for v in value.split(',')]
                data['fixed_versions'] = versions
        
        return data
    
    def _parse_content(self, soup) -> Dict:
        """Парсинг контента страницы"""
        data = {}
        
        # Поиск Summary секции
        summary_parts = []
        
        # Вариант 1: Заголовок Summary
        summary_heading = soup.find(['h1', 'h2', 'h3'], text=re.compile(r'Summary', re.I))
        if summary_heading:
            for sibling in summary_heading.find_next_siblings():
                if sibling.name in ['h1', 'h2', 'h3']:
                    break
                if sibling.name == 'p':
                    summary_parts.append(sibling.text.strip())
        
        # Вариант 2: Поиск всех параграфов если Summary не найдена
        if not summary_parts:
            paragraphs = soup.find_all('p')
            # Взять первые несколько содержательных параграфов
            for p in paragraphs[:5]:
                text = p.text.strip()
                if len(text) > 50:  # Только содержательные параграфы
                    summary_parts.append(text)
        
        if summary_parts:
            data['summary'] = '\n\n'.join(summary_parts)
        
        return data
    
    def _parse_credits(self, soup) -> Optional[str]:
        """Парсинг благодарностей"""
        # Поиск текста с "Thanks to"
        credits_elem = soup.find(text=re.compile(r'Thanks to', re.I))
        if credits_elem:
            parent = credits_elem.find_parent(['p', 'div', 'span'])
            if parent:
                return parent.text.strip()
        
        return None
    
    def fetch_all_advisories(self, severity=None, product=None, limit=None) -> List[Dict]:
        """
        Получить все advisory (с пагинацией)
        
        Args:
            severity: Фильтр по severity
            product: Фильтр по продукту
            limit: Максимальное количество advisory (None = все)
        
        Returns:
            List[Dict] полных данных advisory
        """
        logger.info("🚀 Starting full advisory fetch...")
        
        # Получить список
        advisory_list = self.fetch_advisories_list(severity, product)
        
        if limit:
            advisory_list = advisory_list[:limit]
        
        # Получить детали для каждого
        full_advisories = []
        
        for i, advisory_summary in enumerate(advisory_list, 1):
            logger.info(f"📄 Processing {i}/{len(advisory_list)}: {advisory_summary['cve_id']}")
            
            try:
                # Получить детали
                advisory_detail = self.fetch_advisory_detail(advisory_summary['advisory_url'])
                
                # Объединить данные
                full_advisory = {**advisory_summary, **advisory_detail}
                full_advisories.append(full_advisory)
            
            except Exception as e:
                logger.error(f"❌ Error processing {advisory_summary['cve_id']}: {e}")
                # Добавить хотя бы summary данные
                full_advisories.append(advisory_summary)
        
        logger.info(f"✅ Fetched {len(full_advisories)} full advisories")
        return full_advisories
    
    def parse_severity(self, severity_text: str) -> Dict:
        """
        Парсинг severity из текста
        
        Args:
            severity_text: "● Critical (9.1)"
        
        Returns:
            {"level": "Critical", "score": 9.1}
        """
        match = re.search(r'(\w+)\s*\((\d+\.\d+)\)', severity_text)
        if match:
            return {
                "level": match.group(1),
                "score": float(match.group(2))
            }
        
        return {"level": "UNKNOWN", "score": None}


# Утилитарные функции

def test_parser():
    """
    Простой тест парсера
    """
    logger.info("🧪 Testing Grafana Security Parser...")
    
    parser = GrafanaSecurityParser(cache_enabled=True, rate_limit_delay=1.0)
    
    # Тест 1: Получить список advisory
    logger.info("\n--- Test 1: Fetch advisories list ---")
    try:
        advisories = parser.fetch_advisories_list()
        logger.info(f"✅ Found {len(advisories)} advisories")
        if advisories:
            logger.info(f"First advisory: {advisories[0]['cve_id']} - {advisories[0]['advisory_title']}")
    except Exception as e:
        logger.error(f"❌ Test 1 failed: {e}")
    
    # Тест 2: Получить детали одного advisory
    if advisories:
        logger.info("\n--- Test 2: Fetch advisory detail ---")
        try:
            detail = parser.fetch_advisory_detail(advisories[0]['advisory_url'])
            logger.info(f"✅ Parsed detail: {detail.get('published_date', 'N/A')}")
            logger.info(f"CVSS Score: {detail.get('cvss_score', 'N/A')}")
            logger.info(f"Summary length: {len(detail.get('summary', ''))}")
        except Exception as e:
            logger.error(f"❌ Test 2 failed: {e}")
    
    logger.info("\n✅ Parser tests completed!")


if __name__ == '__main__':
    test_parser()

