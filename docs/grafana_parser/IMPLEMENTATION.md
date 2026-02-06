# 💻 Реализация парсера Grafana

**Полный код парсера с интеграцией в систему**

---

## 📁 Структура файлов

```
services/parsers/
├── __init__.py
├── grafana_parser.py          # Основной парсер
├── grafana_mapper.py           # Маппинг данных
└── grafana_cache.py            # Кэширование

scripts/
└── import_grafana_advisories.py  # Скрипт импорта
```

---

## 🔧 Файл: `services/parsers/grafana_parser.py`

```python
"""
Парсер Grafana Security Advisories

Извлекает данные уязвимостей с https://grafana.com/security/security-advisories/
"""

import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
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
            'User-Agent': 'VulnerabilityManager/1.0 (Educational Purpose; +https://github.com/yourusername/vulnerability_manager)'
        })
        
        self.cache_enabled = cache_enabled
        self.rate_limit_delay = rate_limit_delay
        self.last_request_time = None
        
        if cache_enabled:
            from .grafana_cache import GrafanaCache
            self.cache = GrafanaCache()
    
    def _rate_limit(self):
        """Соблюдение rate limiting"""
        if self.last_request_time:
            elapsed = (datetime.now() - self.last_request_time).total_seconds()
            if elapsed < self.rate_limit_delay:
                time.sleep(self.rate_limit_delay - elapsed)
        
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
                'updated_date': '—'
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
        # ПРИМЕЧАНИЕ: Селекторы нужно уточнить после изучения реальной HTML структуры
        table = soup.find('table')
        
        if not table:
            logger.warning("⚠️  Advisory table not found on page")
            return advisories
        
        rows = table.find_all('tr')[1:]  # Пропустить заголовок
        
        for row in rows:
            try:
                cells = row.find_all('td')
                
                if len(cells) < 5:
                    continue
                
                # Извлечь данные
                cve_id = cells[0].text.strip()
                severity_text = cells[1].text.strip()
                product = cells[2].text.strip()
                
                title_link = cells[3].find('a')
                advisory_title = title_link.text.strip() if title_link else cells[3].text.strip()
                advisory_url = title_link['href'] if title_link else ''
                
                updated_date = cells[4].text.strip()
                
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
        # ПРИМЕЧАНИЕ: Селекторы нужно уточнить после изучения реальной HTML структуры
        
        # Вариант 1: Метаданные в структурированных блоках
        meta_items = soup.find_all('div', class_='meta-item')
        for item in meta_items:
            label_elem = item.find('span', class_='label')
            value_elem = item.find('span', class_='value')
            
            if not label_elem or not value_elem:
                continue
            
            label = label_elem.text.strip().rstrip(':').lower()
            value = value_elem.text.strip()
            
            if 'published' in label:
                data['published_date'] = value
            elif 'cvss score' in label:
                data['cvss_score'] = float(value)
            elif 'cvss vector' in label:
                data['cvss_vector'] = value
            elif 'fixed versions' in label:
                # Парсинг версий (могут быть с <br>)
                versions_html = value_elem.decode_contents()
                versions = [v.strip() for v in re.split(r'<br\s*/?>', versions_html) if v.strip()]
                data['fixed_versions'] = versions
        
        # Вариант 2: Метаданные в definition list
        dl = soup.find('dl')
        if dl:
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
        
        # Парсинг контента
        # Summary section
        summary_heading = soup.find(['h2', 'h3'], text=re.compile(r'Summary', re.I))
        if summary_heading:
            summary_parts = []
            for sibling in summary_heading.find_next_siblings():
                if sibling.name in ['h2', 'h3']:
                    break
                if sibling.name == 'p':
                    summary_parts.append(sibling.text.strip())
            
            data['summary'] = '\n\n'.join(summary_parts)
        
        # Credits
        credits_elem = soup.find(text=re.compile(r'Thanks to', re.I))
        if credits_elem:
            # Найти родительский элемент
            parent = credits_elem.find_parent(['p', 'div'])
            if parent:
                data['credits'] = parent.text.strip()
        
        logger.info(f"✅ Parsed advisory detail: {url}")
        return data
    
    def fetch_all_advisories(self, severity=None, product=None) -> List[Dict]:
        """
        Получить все advisory (с пагинацией)
        
        Args:
            severity: Фильтр по severity
            product: Фильтр по продукту
        
        Returns:
            List[Dict] полных данных advisory
        """
        logger.info("🚀 Starting full advisory fetch...")
        
        # Получить список
        advisory_list = self.fetch_advisories_list(severity, product)
        
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
    
    def parse_cvss_vector(self, vector_string: str) -> Dict:
        """
        Парсинг CVSS вектора
        
        Args:
            vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        
        Returns:
            Dict с метриками CVSS
        """
        if not vector_string:
            return {}
        
        parts = vector_string.split('/')
        version = parts[0].split(':')[1]  # "3.1"
        
        metrics = {}
        for part in parts[1:]:
            if ':' in part:
                key, value = part.split(':')
                metrics[key] = value
        
        return {
            "version": version,
            "vectorString": vector_string,
            "metrics": metrics
        }


# Вспомогательные функции для маппинга

def expand_cvss_metric(metric_name: str, value: str) -> str:
    """
    Расшифровка сокращений CVSS
    """
    mappings = {
        'AV': {  # Attack Vector
            'N': 'NETWORK',
            'A': 'ADJACENT_NETWORK',
            'L': 'LOCAL',
            'P': 'PHYSICAL'
        },
        'AC': {  # Attack Complexity
            'L': 'LOW',
            'H': 'HIGH'
        },
        'PR': {  # Privileges Required
            'N': 'NONE',
            'L': 'LOW',
            'H': 'HIGH'
        },
        'UI': {  # User Interaction
            'N': 'NONE',
            'R': 'REQUIRED'
        },
        'S': {  # Scope
            'U': 'UNCHANGED',
            'C': 'CHANGED'
        },
        'C': {  # Confidentiality Impact
            'N': 'NONE',
            'L': 'LOW',
            'H': 'HIGH'
        },
        'I': {  # Integrity Impact
            'N': 'NONE',
            'L': 'LOW',
            'H': 'HIGH'
        },
        'A': {  # Availability Impact
            'N': 'NONE',
            'L': 'LOW',
            'H': 'HIGH'
        }
    }
    
    return mappings.get(metric_name, {}).get(value, value)


def calculate_severity_from_score(score: float) -> str:
    """
    Определение severity по CVSS score
    """
    if score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    else:
        return 'LOW'
```

---

## 🗺️ Файл: `services/parsers/grafana_mapper.py`

```python
"""
Маппинг данных Grafana на структуру БД
"""

from datetime import datetime
from typing import Dict, List, Optional
import re


class GrafanaDataMapper:
    """
    Маппер данных Grafana на структуру БД
    """
    
    @staticmethod
    def map_to_db_format(grafana_data: Dict) -> Dict:
        """
        Маппинг данных Grafana на структуру БД
        
        Args:
            grafana_data: Данные из парсера
        
        Returns:
            Dict для сохранения в БД
        """
        # Парсинг severity
        severity_info = GrafanaDataMapper._parse_severity(grafana_data.get('severity_text', ''))
        
        # Парсинг CVSS вектора
        cvss_metrics = GrafanaDataMapper._parse_cvss_vector(
            grafana_data.get('cvss_vector', ''),
            grafana_data.get('cvss_score') or severity_info.get('score')
        )
        
        # Формирование данных для БД
        db_data = {
            # Основные поля
            'cve_id': grafana_data['cve_id'],
            'title': grafana_data.get('advisory_title', ''),
            'description': grafana_data.get('summary', ''),
            
            # БДУ поля: Информация о ПО
            'vendor': 'Grafana Labs',
            'product_name': grafana_data.get('product', ''),
            'affected_versions': GrafanaDataMapper._format_affected_versions(
                grafana_data.get('fixed_versions', [])
            ),
            'software_type': GrafanaDataMapper._detect_software_type(
                grafana_data.get('product', '')
            ),
            
            # Оценка опасности
            'cvss_score': grafana_data.get('cvss_score') or severity_info.get('score'),
            'severity': GrafanaDataMapper._map_severity(severity_info.get('level', '')),
            'risk_level': GrafanaDataMapper._map_severity(severity_info.get('level', '')),
            'metrics': {
                'cvss_v3': cvss_metrics
            } if cvss_metrics else {},
            
            # Даты
            'published_date': GrafanaDataMapper._parse_date(grafana_data.get('published_date')),
            'last_modified_date': GrafanaDataMapper._parse_date(grafana_data.get('updated_date')),
            
            # БДУ поля: Устранение
            'remediation_method': 'Обновление ПО',
            'remediation_info': GrafanaDataMapper._format_remediation_info(grafana_data),
            'remediation_date': GrafanaDataMapper._parse_date(grafana_data.get('published_date')),
            
            # БДУ поля: Эксплуатация
            'exploit_available': False,  # Не указывается в Grafana advisory
            'exploitation_method': GrafanaDataMapper._extract_exploitation_method(
                grafana_data.get('summary', '')
            ),
            
            # Ссылки
            'references': GrafanaDataMapper._build_references(grafana_data),
            
            # Комментарии вендора
            'vendor_comments': {
                'credits': grafana_data.get('credits', ''),
                'source': 'Grafana Labs Security Advisory'
            },
            
            # Метаданные
            'source': 'grafana',
            'vuln_status': 'PUBLISHED'
        }
        
        return db_data
    
    @staticmethod
    def _parse_severity(severity_text: str) -> Dict:
        """Парсинг severity из текста"""
        match = re.search(r'(\w+)\s*\((\d+\.\d+)\)', severity_text)
        if match:
            return {
                "level": match.group(1),
                "score": float(match.group(2))
            }
        return {"level": "UNKNOWN", "score": None}
    
    @staticmethod
    def _map_severity(grafana_severity: str) -> str:
        """Маппинг severity на стандартные значения"""
        severity_map = {
            'critical': 'CRITICAL',
            'high': 'HIGH',
            'medium': 'MEDIUM',
            'low': 'LOW'
        }
        return severity_map.get(grafana_severity.lower(), 'UNKNOWN')
    
    @staticmethod
    def _parse_cvss_vector(vector_string: str, score: Optional[float]) -> Dict:
        """Парсинг CVSS вектора"""
        if not vector_string:
            return {}
        
        parts = vector_string.split('/')
        version = parts[0].split(':')[1]
        
        metrics = {}
        for part in parts[1:]:
            if ':' in part:
                key, value = part.split(':')
                metrics[key] = value
        
        # Расшифровка метрик
        return {
            "version": version,
            "vectorString": vector_string,
            "baseScore": score,
            "baseSeverity": GrafanaDataMapper._calculate_severity_from_score(score) if score else None,
            "attackVector": GrafanaDataMapper._expand_metric('AV', metrics.get('AV')),
            "attackComplexity": GrafanaDataMapper._expand_metric('AC', metrics.get('AC')),
            "privilegesRequired": GrafanaDataMapper._expand_metric('PR', metrics.get('PR')),
            "userInteraction": GrafanaDataMapper._expand_metric('UI', metrics.get('UI')),
            "scope": GrafanaDataMapper._expand_metric('S', metrics.get('S')),
            "confidentialityImpact": GrafanaDataMapper._expand_metric('C', metrics.get('C')),
            "integrityImpact": GrafanaDataMapper._expand_metric('I', metrics.get('I')),
            "availabilityImpact": GrafanaDataMapper._expand_metric('A', metrics.get('A'))
        }
    
    @staticmethod
    def _expand_metric(metric_name: str, value: str) -> str:
        """Расшифровка CVSS метрик"""
        mappings = {
            'AV': {'N': 'NETWORK', 'A': 'ADJACENT_NETWORK', 'L': 'LOCAL', 'P': 'PHYSICAL'},
            'AC': {'L': 'LOW', 'H': 'HIGH'},
            'PR': {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'},
            'UI': {'N': 'NONE', 'R': 'REQUIRED'},
            'S': {'U': 'UNCHANGED', 'C': 'CHANGED'},
            'C': {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'},
            'I': {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'},
            'A': {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'}
        }
        return mappings.get(metric_name, {}).get(value, value)
    
    @staticmethod
    def _calculate_severity_from_score(score: float) -> str:
        """Определение severity по score"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    @staticmethod
    def _detect_software_type(product_name: str) -> str:
        """Определение типа ПО"""
        product_lower = product_name.lower()
        
        if 'plugin' in product_lower:
            return 'Плагин'
        elif 'renderer' in product_lower:
            return 'Компонент'
        else:
            return 'Прикладное ПО'
    
    @staticmethod
    def _format_affected_versions(fixed_versions: List) -> str:
        """Форматирование информации о версиях"""
        if not fixed_versions:
            return "Информация о версиях отсутствует"
        
        versions_str = []
        for v in fixed_versions:
            if isinstance(v, dict):
                versions_str.append(v.get('range', str(v)))
            else:
                versions_str.append(str(v))
        
        return f"Исправлено в версиях: {', '.join(versions_str)}"
    
    @staticmethod
    def _format_remediation_info(grafana_data: Dict) -> str:
        """Форматирование информации об устранении"""
        parts = []
        
        if grafana_data.get('summary'):
            parts.append("## Описание уязвимости")
            parts.append(grafana_data['summary'])
            parts.append("")
        
        if grafana_data.get('fixed_versions'):
            parts.append("## Исправленные версии")
            for version in grafana_data['fixed_versions']:
                parts.append(f"- {version}")
            parts.append("")
        
        parts.append("## Рекомендации")
        parts.append("Рекомендуется обновить продукт до последней версии.")
        parts.append("")
        
        cve_id = grafana_data.get('cve_id', '').lower()
        parts.append("## Дополнительная информация")
        parts.append(f"Официальный advisory: https://grafana.com/security/security-advisories/{cve_id}/")
        
        return '\n'.join(parts)
    
    @staticmethod
    def _extract_exploitation_method(summary: str) -> Optional[str]:
        """Извлечение информации о методе эксплуатации"""
        # Поиск фраз о методе эксплуатации
        patterns = [
            r'To exploit[^.]*\.',
            r'An attacker[^.]*\.',
            r'Exploitation requires[^.]*\.'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, summary, re.IGNORECASE)
            if match:
                return match.group(0)
        
        return None
    
    @staticmethod
    def _build_references(grafana_data: Dict) -> List[Dict]:
        """Формирование списка ссылок"""
        cve_id = grafana_data.get('cve_id', '').lower()
        
        references = [
            {
                "url": f"https://grafana.com/security/security-advisories/{cve_id}/",
                "type": "vendor_advisory",
                "source": "Grafana Labs"
            }
        ]
        
        if grafana_data.get('credits'):
            references.append({
                "url": "https://grafana.com/security/bug-bounty/",
                "type": "bug_bounty",
                "source": "Grafana Labs"
            })
        
        return references
    
    @staticmethod
    def _parse_date(date_string: Optional[str]) -> Optional[datetime]:
        """Парсинг даты"""
        if not date_string or date_string == '—':
            return None
        
        try:
            return datetime.strptime(date_string, '%Y-%m-%d')
        except ValueError:
            pass
        
        # Другие форматы...
        try:
            return datetime.strptime(date_string, '%Y/%m/%d')
        except ValueError:
            pass
        
        return None
```

---

## 💾 Файл: `services/parsers/grafana_cache.py`

```python
"""
Кэширование для Grafana парсера
"""

import hashlib
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional


class GrafanaCache:
    """
    Простое файловое кэширование для парсера
    """
    
    def __init__(self, cache_dir='cache/grafana', max_age_hours=24):
        """
        Args:
            cache_dir: Директория для кэша
            max_age_hours: Максимальный возраст кэша (часы)
        """
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.max_age = timedelta(hours=max_age_hours)
    
    def _get_cache_path(self, url: str) -> Path:
        """Путь к файлу кэша для URL"""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return self.cache_dir / f"{url_hash}.json"
    
    def get(self, url: str) -> Optional[str]:
        """
        Получить данные из кэша
        
        Args:
            url: URL для поиска
        
        Returns:
            Кэшированные данные или None
        """
        cache_path = self._get_cache_path(url)
        
        if not cache_path.exists():
            return None
        
        # Проверить возраст кэша
        cache_age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
        if cache_age > self.max_age:
            return None
        
        # Загрузить данные
        with open(cache_path, 'r', encoding='utf-8') as f:
            cache_data = json.load(f)
        
        return cache_data.get('content')
    
    def set(self, url: str, content: str):
        """
        Сохранить данные в кэш
        
        Args:
            url: URL
            content: Содержимое для кэширования
        """
        cache_path = self._get_cache_path(url)
        
        cache_data = {
            'url': url,
            'content': content,
            'cached_at': datetime.now().isoformat()
        }
        
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, ensure_ascii=False, indent=2)
    
    def clear(self):
        """Очистить весь кэш"""
        for cache_file in self.cache_dir.glob('*.json'):
            cache_file.unlink()
    
    def clear_old(self):
        """Удалить устаревший кэш"""
        for cache_file in self.cache_dir.glob('*.json'):
            cache_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
            if cache_age > self.max_age:
                cache_file.unlink()
```

---

## 🚀 Файл: `scripts/import_grafana_advisories.py`

```python
#!/usr/bin/env python3
"""
Скрипт импорта уязвимостей Grafana

Usage:
    python scripts/import_grafana_advisories.py
    python scripts/import_grafana_advisories.py --severity critical
    python scripts/import_grafana_advisories.py --product grafana
"""

import sys
import argparse
from pathlib import Path

# Добавить корневую директорию в PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.parsers.grafana_parser import GrafanaSecurityParser
from services.parsers.grafana_mapper import GrafanaDataMapper
from services.vulnerability_service import VulnerabilityService
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def sync_grafana_advisories(severity=None, product=None, dry_run=False):
    """
    Синхронизация Grafana advisories с БД
    
    Args:
        severity: Фильтр по severity
        product: Фильтр по продукту
        dry_run: Режим тестирования (не сохранять в БД)
    """
    logger.info("🚀 Starting Grafana Security Advisories sync...")
    
    # Инициализация
    parser = GrafanaSecurityParser()
    mapper = GrafanaDataMapper()
    service = VulnerabilityService() if not dry_run else None
    
    stats = {
        'total': 0,
        'new': 0,
        'updated': 0,
        'skipped': 0,
        'errors': []
    }
    
    try:
        # Получить advisory
        logger.info("📋 Fetching advisories list...")
        advisories = parser.fetch_all_advisories(severity=severity, product=product)
        stats['total'] = len(advisories)
        
        logger.info(f"✅ Found {len(advisories)} advisories")
        
        # Обработать каждый advisory
        for i, grafana_data in enumerate(advisories, 1):
            cve_id = grafana_data['cve_id']
            logger.info(f"\n[{i}/{len(advisories)}] Processing {cve_id}...")
            
            try:
                # Маппинг на БД структуру
                db_data = mapper.map_to_db_format(grafana_data)
                
                if dry_run:
                    logger.info(f"   [DRY RUN] Would process: {cve_id}")
                    logger.info(f"   Vendor: {db_data.get('vendor')}")
                    logger.info(f"   Product: {db_data.get('product_name')}")
                    logger.info(f"   CVSS: {db_data.get('cvss_score')}")
                    stats['new'] += 1
                    continue
                
                # Проверить, существует ли в БД
                existing = service.get_by_cve_id(cve_id)
                
                if existing:
                    # Проверить, нужно ли обновить
                    if should_update(existing, db_data):
                        service.update_vulnerability(existing.id, db_data)
                        stats['updated'] += 1
                        logger.info(f"   ✏️  Updated")
                    else:
                        stats['skipped'] += 1
                        logger.info(f"   ⏭️  Skipped (no changes)")
                else:
                    # Создать новую запись
                    service.create_vulnerability(db_data)
                    stats['new'] += 1
                    logger.info(f"   ➕ Created")
            
            except Exception as e:
                stats['errors'].append(f"{cve_id}: {str(e)}")
                logger.error(f"   ❌ Error: {e}")
    
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        raise
    
    # Итоговая статистика
    print("\n" + "="*60)
    print("📊 Sync completed!")
    print(f"   Total:   {stats['total']}")
    print(f"   New:     {stats['new']}")
    print(f"   Updated: {stats['updated']}")
    print(f"   Skipped: {stats['skipped']}")
    print(f"   Errors:  {len(stats['errors'])}")
    
    if stats['errors']:
        print("\n❌ Errors:")
        for error in stats['errors'][:10]:  # Показать первые 10
            print(f"   - {error}")
        if len(stats['errors']) > 10:
            print(f"   ... and {len(stats['errors']) - 10} more")
    
    return stats


def should_update(existing, new_data):
    """
    Проверить, нужно ли обновлять запись
    """
    # Сравнить ключевые поля
    if existing.cvss_score != new_data.get('cvss_score'):
        return True
    
    if existing.title != new_data.get('title'):
        return True
    
    if existing.description != new_data.get('description'):
        return True
    
    return False


def main():
    parser = argparse.ArgumentParser(description='Import Grafana Security Advisories')
    parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low'],
                       help='Filter by severity')
    parser.add_argument('--product', help='Filter by product')
    parser.add_argument('--dry-run', action='store_true',
                       help='Test mode (do not save to database)')
    
    args = parser.parse_args()
    
    try:
        stats = sync_grafana_advisories(
            severity=args.severity,
            product=args.product,
            dry_run=args.dry_run
        )
        
        # Exit code
        if stats['errors']:
            sys.exit(1)
        else:
            sys.exit(0)
    
    except KeyboardInterrupt:
        logger.info("\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
```

---

## 🧪 Тестирование

### Файл: `tests/test_grafana_parser.py`

```python
import unittest
from services.parsers.grafana_parser import GrafanaSecurityParser
from services.parsers.grafana_mapper import GrafanaDataMapper


class TestGrafanaParser(unittest.TestCase):
    
    def setUp(self):
        self.parser = GrafanaSecurityParser(cache_enabled=False)
        self.mapper = GrafanaDataMapper()
    
    def test_parse_severity(self):
        """Тест парсинга severity"""
        result = self.parser.parse_severity("● Critical (9.1)")
        self.assertEqual(result['level'], 'Critical')
        self.assertEqual(result['score'], 9.1)
    
    def test_parse_cvss_vector(self):
        """Тест парсинга CVSS вектора"""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
        result = self.parser.parse_cvss_vector(vector)
        
        self.assertEqual(result['version'], '3.1')
        self.assertEqual(result['vectorString'], vector)
        self.assertIn('AV', result['metrics'])
        self.assertEqual(result['metrics']['AV'], 'N')
    
    def test_mapper_basic(self):
        """Тест базового маппинга"""
        grafana_data = {
            'cve_id': 'CVE-2025-41118',
            'advisory_title': 'Test Advisory',
            'product': 'Grafana',
            'severity_text': '● High (7.5)'
        }
        
        db_data = self.mapper.map_to_db_format(grafana_data)
        
        self.assertEqual(db_data['cve_id'], 'CVE-2025-41118')
        self.assertEqual(db_data['vendor'], 'Grafana Labs')
        self.assertEqual(db_data['product_name'], 'Grafana')
        self.assertEqual(db_data['source'], 'grafana')


if __name__ == '__main__':
    unittest.main()
```

---

## 📝 Использование

### Базовый импорт

```bash
# Импорт всех advisory
python scripts/import_grafana_advisories.py

# Тестовый режим (без сохранения в БД)
python scripts/import_grafana_advisories.py --dry-run

# Только критические
python scripts/import_grafana_advisories.py --severity critical

# Только для конкретного продукта
python scripts/import_grafana_advisories.py --product grafana

# Комбинация фильтров
python scripts/import_grafana_advisories.py --severity high --product pyroscope
```

### Программное использование

```python
from services.parsers.grafana_parser import GrafanaSecurityParser
from services.parsers.grafana_mapper import GrafanaDataMapper

# Инициализация
parser = GrafanaSecurityParser()
mapper = GrafanaDataMapper()

# Получить все advisory
advisories = parser.fetch_all_advisories()

# Обработать каждый
for advisory in advisories:
    db_data = mapper.map_to_db_format(advisory)
    # Сохранить в БД...
```

---

## ✅ Чек-лист реализации

- [ ] Создать файлы парсера
- [ ] Протестировать на примерах
- [ ] Уточнить HTML селекторы (после изучения реальной структуры)
- [ ] Добавить обработку ошибок
- [ ] Реализовать логирование
- [ ] Создать тесты
- [ ] Интегрировать с БД
- [ ] Добавить в cron для автоматического обновления

---

**Следующий документ:** [COMPARISON_WITH_BDU.md](COMPARISON_WITH_BDU.md)

