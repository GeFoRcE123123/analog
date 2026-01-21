# 📋 План парсинга Grafana Security Advisories

**Поэтапный план извлечения данных**

---

## 🎯 Этап 1: Анализ структуры сайта

### 1.1 URL структура

**Главная страница:**
```
https://grafana.com/security/security-advisories/
```

**Детальная страница CVE:**
```
https://grafana.com/security/security-advisories/cve-2025-41118/
https://grafana.com/security/security-advisories/cve-2025-41115/
```

**Паттерн:** `/security/security-advisories/{cve-id}/`

### 1.2 Формат данных

**Главная страница:**
- HTML таблица с уязвимостями
- Пагинация (если есть)
- Фильтры (severity, product)

**Детальная страница:**
- Структурированные блоки с информацией
- Markdown/HTML описание
- Метаданные в структурированном виде

---

## 🔍 Этап 2: Парсинг списка уязвимостей

### 2.1 Что извлекаем из таблицы

```python
{
    "cve_id": "CVE-2025-41118",
    "severity": "Critical",
    "cvss_score": 9.1,
    "product": "Pyroscope",
    "advisory_title": "Exposure of Storage Secret in Pyroscope",
    "advisory_url": "/security/security-advisories/cve-2025-41118/",
    "updated_date": "—"  # или конкретная дата
}
```

### 2.2 HTML структура (предположительная)

```html
<table>
  <thead>
    <tr>
      <th>CVE</th>
      <th>Severity (CVSS)</th>
      <th>Product</th>
      <th>Advisory Title</th>
      <th>Updated</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>CVE-2025-41118</td>
      <td>● Critical (9.1)</td>
      <td>Pyroscope</td>
      <td><a href="/security/security-advisories/cve-2025-41118/">Exposure of Storage Secret in Pyroscope</a></td>
      <td>—</td>
    </tr>
    <!-- ... -->
  </tbody>
</table>
```

### 2.3 Селекторы для парсинга

```python
# BeautifulSoup селекторы
table = soup.find('table')
rows = table.find_all('tr')[1:]  # Пропустить заголовок

for row in rows:
    cells = row.find_all('td')
    cve_id = cells[0].text.strip()
    severity_text = cells[1].text.strip()  # "● Critical (9.1)"
    product = cells[2].text.strip()
    title_link = cells[3].find('a')
    title = title_link.text.strip()
    url = title_link['href']
    updated = cells[4].text.strip()
```

### 2.4 Обработка severity

```python
import re

def parse_severity(severity_text):
    """
    Вход: "● Critical (9.1)"
    Выход: {"level": "Critical", "score": 9.1}
    """
    match = re.search(r'(\w+)\s*\((\d+\.\d+)\)', severity_text)
    if match:
        return {
            "level": match.group(1),
            "score": float(match.group(2))
        }
    return None
```

---

## 📄 Этап 3: Парсинг детальной страницы CVE

### 3.1 Что извлекаем

**Основная информация:**
```python
{
    "advisory_id": "CVE-2025-41118",
    "published_date": "2026-01-02",
    "product": "Pyroscope",
    "cvss_score": 9.1,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "fixed_versions": [">=1.15.2 <1.16.0", ">=1.16.1"]
}
```

**Описание:**
```python
{
    "summary": "Pyroscope is an open-source continuous profiling database...",
    "description": "If the database is configured to use Tencent COS...",
    "impact": "An attacker could extract the secret_key configuration value...",
    "exploitation": "To exploit this vulnerability, an attacker needs direct access...",
    "remediation": "This vulnerability is fixed in versions: 1.15.x: 1.15.2 and above..."
}
```

**Дополнительно:**
```python
{
    "credits": "Thanks to Théo Cusnir for reporting this vulnerability...",
    "references": [
        {"type": "bug_bounty", "url": "https://grafana.com/security/bug-bounty/"}
    ]
}
```

### 3.2 HTML структура детальной страницы

**Предположительная структура:**

```html
<div class="advisory-detail">
    <div class="advisory-header">
        <h1>Exposure of Storage Secret in Pyroscope</h1>
        <div class="advisory-meta">
            <div class="meta-item">
                <span class="label">Advisory ID:</span>
                <span class="value">CVE-2025-41118</span>
            </div>
            <div class="meta-item">
                <span class="label">Published:</span>
                <span class="value">2026-01-02</span>
            </div>
            <div class="meta-item">
                <span class="label">Product:</span>
                <span class="value">Pyroscope</span>
            </div>
            <div class="meta-item">
                <span class="label">CVSS Score:</span>
                <span class="value">9.1</span>
            </div>
            <div class="meta-item">
                <span class="label">CVSS Vector:</span>
                <span class="value">CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N</span>
            </div>
            <div class="meta-item">
                <span class="label">Fixed Versions:</span>
                <span class="value">>=1.15.2 <1.16.0<br>>=1.16.1</span>
            </div>
        </div>
    </div>
    
    <div class="advisory-content">
        <h2>Summary</h2>
        <p>Pyroscope is an open-source continuous profiling database...</p>
        
        <h2>Details</h2>
        <p>If the database is configured to use Tencent COS...</p>
        
        <h2>Remediation</h2>
        <p>This vulnerability is fixed in versions:...</p>
    </div>
    
    <div class="advisory-credits">
        <p>Thanks to <a href="#">Théo Cusnir</a> for reporting...</p>
    </div>
</div>
```

### 3.3 Селекторы для парсинга

```python
def parse_advisory_detail(html):
    soup = BeautifulSoup(html, 'html.parser')
    
    data = {}
    
    # Метаданные
    meta_items = soup.find_all('div', class_='meta-item')
    for item in meta_items:
        label = item.find('span', class_='label').text.strip().rstrip(':')
        value = item.find('span', class_='value').text.strip()
        
        if label == 'Advisory ID':
            data['advisory_id'] = value
        elif label == 'Published':
            data['published_date'] = value
        elif label == 'Product':
            data['product'] = value
        elif label == 'CVSS Score':
            data['cvss_score'] = float(value)
        elif label == 'CVSS Vector':
            data['cvss_vector'] = value
        elif label == 'Fixed Versions':
            data['fixed_versions'] = [v.strip() for v in value.split('<br>')]
    
    # Контент
    content_div = soup.find('div', class_='advisory-content')
    
    # Summary
    summary_section = content_div.find('h2', text='Summary')
    if summary_section:
        summary_p = summary_section.find_next_sibling('p')
        data['summary'] = summary_p.text.strip()
    
    # Details
    details_section = content_div.find('h2', text='Details')
    if details_section:
        details_text = []
        for sibling in details_section.find_next_siblings():
            if sibling.name == 'h2':
                break
            if sibling.name == 'p':
                details_text.append(sibling.text.strip())
        data['description'] = '\n\n'.join(details_text)
    
    # Credits
    credits_div = soup.find('div', class_='advisory-credits')
    if credits_div:
        data['credits'] = credits_div.text.strip()
    
    return data
```

---

## 🔄 Этап 4: Обработка CVSS вектора

### 4.1 Парсинг CVSS вектора

```python
def parse_cvss_vector(vector_string):
    """
    Вход: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    Выход: {
        "version": "3.1",
        "metrics": {
            "AV": "N",  # Attack Vector: Network
            "AC": "L",  # Attack Complexity: Low
            "PR": "N",  # Privileges Required: None
            "UI": "N",  # User Interaction: None
            "S": "U",   # Scope: Unchanged
            "C": "H",   # Confidentiality: High
            "I": "H",   # Integrity: High
            "A": "N"    # Availability: None
        }
    }
    """
    parts = vector_string.split('/')
    version = parts[0].split(':')[1]  # "3.1"
    
    metrics = {}
    for part in parts[1:]:
        key, value = part.split(':')
        metrics[key] = value
    
    return {
        "version": version,
        "metrics": metrics,
        "vector_string": vector_string
    }
```

### 4.2 Маппинг на БД структуру

```python
def map_to_db_format(cvss_data):
    """
    Маппинг на структуру metrics JSONB в БД
    """
    return {
        "cvss_v3": {
            "version": cvss_data["version"],
            "vectorString": cvss_data["vector_string"],
            "baseScore": cvss_data.get("score"),
            "baseSeverity": cvss_data.get("severity"),
            "attackVector": expand_metric("AV", cvss_data["metrics"]["AV"]),
            "attackComplexity": expand_metric("AC", cvss_data["metrics"]["AC"]),
            # ... остальные метрики
        }
    }

def expand_metric(metric_name, value):
    """
    Расшифровка сокращений CVSS
    """
    mappings = {
        "AV": {
            "N": "NETWORK",
            "A": "ADJACENT_NETWORK",
            "L": "LOCAL",
            "P": "PHYSICAL"
        },
        "AC": {
            "L": "LOW",
            "H": "HIGH"
        },
        # ... остальные маппинги
    }
    return mappings.get(metric_name, {}).get(value, value)
```

---

## 📦 Этап 5: Парсинг Fixed Versions

### 5.1 Форматы версий

Grafana использует разные форматы:

```
">=1.15.2 <1.16.0"  # Диапазон
">=1.16.1"          # От версии и выше
"1.15.x: 1.15.2 and above"  # Текстовое описание
```

### 5.2 Парсинг версий

```python
import re

def parse_fixed_versions(version_text):
    """
    Парсинг информации о исправленных версиях
    
    Вход: ">=1.15.2 <1.16.0\n>=1.16.1"
    Выход: [
        {"range": ">=1.15.2 <1.16.0", "min": "1.15.2", "max": "1.16.0"},
        {"range": ">=1.16.1", "min": "1.16.1", "max": None}
    ]
    """
    lines = version_text.split('\n')
    versions = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        # Паттерн: ">=X.Y.Z <A.B.C"
        match = re.match(r'>=(\S+)\s*<(\S+)', line)
        if match:
            versions.append({
                "range": line,
                "min": match.group(1),
                "max": match.group(2)
            })
            continue
        
        # Паттерн: ">=X.Y.Z"
        match = re.match(r'>=(\S+)', line)
        if match:
            versions.append({
                "range": line,
                "min": match.group(1),
                "max": None
            })
            continue
        
        # Текстовый формат: "1.15.x: 1.15.2 and above"
        match = re.match(r'([\d.x]+):\s*([\d.]+)\s+and above', line)
        if match:
            versions.append({
                "range": line,
                "branch": match.group(1),
                "min": match.group(2),
                "max": None
            })
    
    return versions
```

---

## 🌐 Этап 6: Обработка пагинации

### 6.1 Проверка наличия пагинации

```python
def has_pagination(soup):
    """
    Проверить, есть ли пагинация на странице
    """
    pagination = soup.find('nav', class_='pagination')
    return pagination is not None

def get_next_page_url(soup, current_url):
    """
    Получить URL следующей страницы
    """
    pagination = soup.find('nav', class_='pagination')
    if not pagination:
        return None
    
    next_link = pagination.find('a', text='Next')
    if next_link:
        return urljoin(current_url, next_link['href'])
    
    return None
```

### 6.2 Итерация по всем страницам

```python
def fetch_all_advisories():
    """
    Получить все уязвимости со всех страниц
    """
    base_url = "https://grafana.com/security/security-advisories/"
    current_url = base_url
    all_advisories = []
    
    while current_url:
        print(f"Fetching: {current_url}")
        response = requests.get(current_url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Парсинг таблицы
        advisories = parse_advisories_table(soup)
        all_advisories.extend(advisories)
        
        # Следующая страница
        current_url = get_next_page_url(soup, current_url)
        
        # Rate limiting
        time.sleep(1)
    
    return all_advisories
```

---

## 🔍 Этап 7: Фильтрация и поиск

### 7.1 Фильтры на сайте

Grafana предоставляет фильтры:
- **Severity:** All Severities, Critical, High, Medium, Low
- **Product:** All Products, Grafana, Pyroscope, Grafana Enterprise, плагины

### 7.2 URL параметры (предположительно)

```
https://grafana.com/security/security-advisories/?severity=critical
https://grafana.com/security/security-advisories/?product=grafana
https://grafana.com/security/security-advisories/?severity=critical&product=pyroscope
```

### 7.3 Использование фильтров в парсере

```python
def fetch_advisories_filtered(severity=None, product=None):
    """
    Получить уязвимости с фильтрами
    
    Args:
        severity: "critical", "high", "medium", "low"
        product: "grafana", "pyroscope", и т.д.
    """
    base_url = "https://grafana.com/security/security-advisories/"
    params = {}
    
    if severity:
        params['severity'] = severity.lower()
    if product:
        params['product'] = product.lower()
    
    response = requests.get(base_url, params=params)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    return parse_advisories_table(soup)
```

---

## 🚦 Этап 8: Rate Limiting и этика парсинга

### 8.1 Уважительный парсинг

```python
import time
from datetime import datetime, timedelta

class GrafanaParser:
    def __init__(self):
        self.last_request_time = None
        self.min_delay = 1.0  # секунды между запросами
        self.user_agent = 'VulnerabilityManager/1.0 (Educational Purpose)'
    
    def fetch_with_rate_limit(self, url):
        """
        Запрос с соблюдением rate limiting
        """
        # Задержка между запросами
        if self.last_request_time:
            elapsed = (datetime.now() - self.last_request_time).total_seconds()
            if elapsed < self.min_delay:
                time.sleep(self.min_delay - elapsed)
        
        headers = {
            'User-Agent': self.user_agent
        }
        
        response = requests.get(url, headers=headers)
        self.last_request_time = datetime.now()
        
        return response
```

### 8.2 Кэширование

```python
import hashlib
import json
from pathlib import Path

class CachedParser:
    def __init__(self, cache_dir='cache'):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
    
    def get_cache_path(self, url):
        """
        Путь к кэшу для URL
        """
        url_hash = hashlib.md5(url.encode()).hexdigest()
        return self.cache_dir / f"{url_hash}.json"
    
    def fetch_cached(self, url, max_age_hours=24):
        """
        Получить данные с кэшированием
        """
        cache_path = self.get_cache_path(url)
        
        # Проверить кэш
        if cache_path.exists():
            cache_age = datetime.now() - datetime.fromtimestamp(cache_path.stat().st_mtime)
            if cache_age < timedelta(hours=max_age_hours):
                print(f"📦 Using cache for {url}")
                with open(cache_path, 'r') as f:
                    return json.load(f)
        
        # Запрос к серверу
        print(f"🌐 Fetching {url}")
        response = self.fetch_with_rate_limit(url)
        data = response.text
        
        # Сохранить в кэш
        with open(cache_path, 'w') as f:
            json.dump(data, f)
        
        return data
```

---

## 🔄 Этап 9: Инкрементальное обновление

### 9.1 Стратегия обновления

```python
def sync_grafana_advisories():
    """
    Синхронизация уязвимостей Grafana
    
    Стратегия:
    1. Получить список всех CVE с сайта
    2. Проверить, какие уже есть в БД
    3. Добавить новые
    4. Обновить существующие (если changed)
    """
    from services.vulnerability_service import VulnerabilityService
    
    service = VulnerabilityService()
    parser = GrafanaParser()
    
    # Получить все advisory с сайта
    print("🔍 Fetching advisories from Grafana...")
    advisories = parser.fetch_all_advisories()
    
    stats = {
        'total': len(advisories),
        'new': 0,
        'updated': 0,
        'skipped': 0,
        'errors': []
    }
    
    for advisory in advisories:
        try:
            cve_id = advisory['cve_id']
            
            # Проверить, существует ли в БД
            existing = service.get_by_cve_id(cve_id)
            
            if existing:
                # Проверить, нужно ли обновить
                if should_update(existing, advisory):
                    update_vulnerability(existing, advisory)
                    stats['updated'] += 1
                    print(f"✏️  Updated: {cve_id}")
                else:
                    stats['skipped'] += 1
            else:
                # Создать новую запись
                create_vulnerability(advisory)
                stats['new'] += 1
                print(f"➕ Created: {cve_id}")
        
        except Exception as e:
            stats['errors'].append(f"{cve_id}: {str(e)}")
            print(f"❌ Error processing {cve_id}: {e}")
    
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
    
    # Проверить дату обновления
    if new_data.get('updated_date') and new_data['updated_date'] != '—':
        # Если есть новая дата обновления
        return True
    
    return False
```

---

## 📊 Этап 10: Полный workflow

### 10.1 Последовательность действий

```
1. Запуск парсера
   ↓
2. Получение списка всех advisory (с пагинацией)
   ↓
3. Для каждого advisory:
   ├─ Проверка в БД (существует?)
   ├─ Если НЕТ → переход к шагу 4
   └─ Если ДА → проверка на обновления
   ↓
4. Получение детальной страницы CVE
   ↓
5. Парсинг всех данных
   ↓
6. Маппинг на структуру БД
   ↓
7. Сохранение в БД
   ↓
8. Статистика и логирование
```

### 10.2 Псевдокод полного процесса

```python
def full_sync_workflow():
    """
    Полный цикл синхронизации Grafana advisories
    """
    print("🚀 Starting Grafana Security Advisories sync...")
    
    # Инициализация
    parser = GrafanaParser()
    service = VulnerabilityService()
    stats = {'new': 0, 'updated': 0, 'errors': []}
    
    # Шаг 1: Получить список advisory
    print("\n📋 Step 1: Fetching advisory list...")
    advisory_list = parser.fetch_all_advisories()
    print(f"   Found {len(advisory_list)} advisories")
    
    # Шаг 2: Обработать каждый advisory
    print("\n🔄 Step 2: Processing advisories...")
    for i, advisory_summary in enumerate(advisory_list, 1):
        cve_id = advisory_summary['cve_id']
        print(f"\n   [{i}/{len(advisory_list)}] Processing {cve_id}...")
        
        try:
            # Шаг 2.1: Проверить в БД
            existing = service.get_by_cve_id(cve_id)
            
            # Шаг 2.2: Получить детальные данные
            detail_url = advisory_summary['advisory_url']
            advisory_detail = parser.fetch_advisory_detail(detail_url)
            
            # Шаг 2.3: Объединить данные
            full_data = {**advisory_summary, **advisory_detail}
            
            # Шаг 2.4: Маппинг на БД структуру
            db_data = map_grafana_to_db(full_data)
            
            # Шаг 2.5: Сохранить/обновить
            if existing:
                if should_update(existing, db_data):
                    service.update_vulnerability(existing.id, db_data)
                    stats['updated'] += 1
                    print(f"      ✏️  Updated")
                else:
                    print(f"      ⏭️  Skipped (no changes)")
            else:
                service.create_vulnerability(db_data)
                stats['new'] += 1
                print(f"      ➕ Created")
        
        except Exception as e:
            stats['errors'].append(f"{cve_id}: {str(e)}")
            print(f"      ❌ Error: {e}")
    
    # Шаг 3: Итоговая статистика
    print("\n" + "="*60)
    print("📊 Sync completed!")
    print(f"   New:     {stats['new']}")
    print(f"   Updated: {stats['updated']}")
    print(f"   Errors:  {len(stats['errors'])}")
    
    if stats['errors']:
        print("\n❌ Errors:")
        for error in stats['errors']:
            print(f"   - {error}")
    
    return stats
```

---

## 🎯 Этап 11: Маппинг на БД (интеграция с БДУ структурой)

### 11.1 Маппинг полей

```python
def map_grafana_to_db(grafana_data):
    """
    Маппинг данных Grafana на структуру БД
    
    Учитывает существующую БДУ структуру
    """
    return {
        # Основные поля
        'cve_id': grafana_data['cve_id'],
        'title': grafana_data['advisory_title'],
        'description': grafana_data.get('summary', ''),
        
        # Vendor и Product (БДУ поля)
        'vendor': 'Grafana Labs',
        'product_name': grafana_data['product'],
        'affected_versions': format_affected_versions(grafana_data.get('fixed_versions', [])),
        'software_type': detect_software_type(grafana_data['product']),
        
        # CVSS
        'cvss_score': grafana_data.get('cvss_score'),
        'severity': map_severity(grafana_data.get('severity')),
        'metrics': {
            'cvss_v3': parse_cvss_metrics(grafana_data.get('cvss_vector'))
        },
        
        # Даты
        'published_date': parse_date(grafana_data.get('published_date')),
        'last_modified_date': parse_date(grafana_data.get('updated_date')),
        
        # Устранение (БДУ поля)
        'remediation_method': 'Обновление ПО',
        'remediation_info': format_remediation_info(grafana_data),
        'remediation_date': parse_date(grafana_data.get('published_date')),  # Дата публикации патча
        
        # Источник
        'source': 'grafana',
        'references': [
            {
                'url': f"https://grafana.com/security/security-advisories/{grafana_data['cve_id'].lower()}/",
                'type': 'vendor_advisory'
            }
        ],
        
        # Credits
        'vendor_comments': {
            'credits': grafana_data.get('credits', '')
        }
    }

def detect_software_type(product_name):
    """
    Определить тип ПО по названию продукта
    """
    product_lower = product_name.lower()
    
    if 'plugin' in product_lower:
        return 'Плагин'
    elif any(x in product_lower for x in ['grafana', 'loki', 'tempo', 'mimir', 'pyroscope']):
        return 'Прикладное ПО'
    else:
        return 'Прикладное ПО'

def format_affected_versions(fixed_versions):
    """
    Форматировать информацию о затронутых версиях
    
    Вход: [{"range": ">=1.15.2 <1.16.0"}, {"range": ">=1.16.1"}]
    Выход: "Уязвимы версии до 1.15.2 и 1.16.0. Исправлено в 1.15.2+, 1.16.1+"
    """
    if not fixed_versions:
        return "Информация о версиях отсутствует"
    
    fixed_list = []
    for v in fixed_versions:
        if isinstance(v, dict):
            fixed_list.append(v.get('range', str(v)))
        else:
            fixed_list.append(str(v))
    
    return f"Исправлено в версиях: {', '.join(fixed_list)}"

def format_remediation_info(grafana_data):
    """
    Форматировать информацию об устранении
    """
    info_parts = []
    
    # Описание уязвимости
    if grafana_data.get('summary'):
        info_parts.append(grafana_data['summary'])
    
    # Исправленные версии
    if grafana_data.get('fixed_versions'):
        versions_text = format_affected_versions(grafana_data['fixed_versions'])
        info_parts.append(f"\n\n{versions_text}")
    
    # Рекомендации
    info_parts.append("\n\nРекомендуется обновить до последней версии продукта.")
    
    # Ссылка на advisory
    cve_id = grafana_data.get('cve_id', '').lower()
    info_parts.append(f"\n\nПодробности: https://grafana.com/security/security-advisories/{cve_id}/")
    
    return ''.join(info_parts)

def map_severity(grafana_severity):
    """
    Маппинг severity Grafana на стандартные значения
    """
    severity_map = {
        'critical': 'CRITICAL',
        'high': 'HIGH',
        'medium': 'MEDIUM',
        'low': 'LOW'
    }
    
    if isinstance(grafana_severity, str):
        return severity_map.get(grafana_severity.lower(), 'UNKNOWN')
    
    return 'UNKNOWN'
```

---

## ✅ Чек-лист этапов

### Перед началом парсинга:
- [ ] Изучить структуру сайта Grafana
- [ ] Определить селекторы HTML
- [ ] Проверить наличие robots.txt
- [ ] Настроить rate limiting
- [ ] Подготовить кэширование

### Реализация парсера:
- [ ] Парсинг списка advisory
- [ ] Парсинг детальных страниц
- [ ] Обработка CVSS векторов
- [ ] Парсинг версий
- [ ] Обработка пагинации
- [ ] Маппинг на БД структуру

### Интеграция:
- [ ] Проверка дубликатов в БД
- [ ] Логика обновления существующих записей
- [ ] Обработка ошибок
- [ ] Логирование
- [ ] Статистика

### Тестирование:
- [ ] Тест на примерах
- [ ] Тест пагинации
- [ ] Тест обработки ошибок
- [ ] Тест инкрементального обновления
- [ ] Нагрузочное тестирование

---

## 📈 Ожидаемые результаты

### Метрики:
- **Скорость парсинга:** ~1-2 секунды на advisory (с rate limiting)
- **Точность:** >95% корректно распознанных полей
- **Покрытие:** 100% публичных advisory Grafana
- **Обновление:** Ежедневная синхронизация новых записей

### Интеграция с системой:
- Автоматическое заполнение vendor = "Grafana Labs"
- Использование существующих БДУ полей
- Дополнение NVD данных для Grafana CVE
- Единый интерфейс просмотра всех источников

---

**Следующий документ:** [DATA_MAPPING.md](DATA_MAPPING.md)

