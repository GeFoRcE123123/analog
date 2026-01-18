# Multi-Source Vulnerability Parser

Универсальный парсер уязвимостей для множественных источников без API.

## Описание

Этот парсер извлекает информацию об уязвимостях (CVE) с веб-сайтов различных вендоров, которые не предоставляют публичные API. Парсер использует веб-скрапинг для анализа HTML-страниц и извлечения данных об уязвимостях.

## Поддерживаемые источники

1. **Moxa** - Security Advisory
2. **FortiGuard** - PSIRT
3. **SUSE** - Security Updates
4. **Schneider Electric** - Security Notifications
5. **HP** - Security Bulletins
6. **Adobe** - Security Advisories
7. **Ubuntu** - Security Notices
8. **Debian** - Security Advisories
9. **Cisco** - Security Center
10. **MongoDB** - Security Alerts
11. **Dell** - Security Advisories
12. **Broadcom** - Security Advisory
13. **Huntr** - Bounty Platform
14. **Splunk** - Security Advisories
15. **Siemens** - Security Publications
16. **TeamViewer** - Security Bulletins
17. **Autodesk** - Security Advisories
18. **CVECrowd** - CVE Database
19. **Feedly** - CVE Feed
20. **SAP** - Security Notes
21. **Qualcomm** - Security Bulletins
22. **FediSec** - Security Feeds

## Установка

```bash
# Установка зависимостей
pip install -r requirements_parser.txt

# Или вручную:
pip install beautifulsoup4 lxml feedparser requests
```

## Использование

### Базовый пример

```python
from services.multi_source_vulnerability_parser import MultiSourceVulnerabilityParser

# Создание парсера
parser = MultiSourceVulnerabilityParser(timeout=30, delay=1.0)

# Список источников
sources = {
    'moxa': 'https://www.moxa.com/en/support/support/security-advisory',
    'fortiguard': 'https://www.fortiguard.com/psirt',
    'cisco': 'https://sec.cloudapps.cisco.com/security/center/publicationListing.x',
    # ... другие источники
}

# Парсинг всех источников
results = parser.parse_all_sources(sources, limit_per_source=50)

# Обработка результатов
for source_name, vulnerabilities in results.items():
    print(f"{source_name}: {len(vulnerabilities)} уязвимостей")
    for vuln in vulnerabilities:
        print(f"  - {vuln.cve_id}: {vuln.title}")
```

### Запуск тестового скрипта

```bash
python3 test_multi_source_parser.py
```

Скрипт:
- Парсит все указанные источники
- Выводит статистику по каждому источнику
- Сохраняет результаты в `parsed_vulnerabilities.json`

### Парсинг одного источника

```python
parser = MultiSourceVulnerabilityParser()

# Парсинг только Cisco
vulnerabilities = parser.parse_source(
    'cisco',
    'https://sec.cloudapps.cisco.com/security/center/publicationListing.x',
    limit=100
)

for vuln in vulnerabilities:
    print(f"CVE: {vuln.cve_id}")
    print(f"Title: {vuln.title}")
    print(f"Severity: {vuln.severity}")
    print(f"CVSS: {vuln.cvss_score}")
    print(f"URL: {vuln.source_url}")
    print("---")
```

## Структура данных

Каждая уязвимость представлена объектом `Vulnerability`:

```python
@dataclass
class Vulnerability:
    cve_id: str                    # CVE идентификатор (например, CVE-2024-1234)
    title: str                     # Заголовок уязвимости
    description: str               # Описание
    severity: str                  # Уровень серьезности (critical, high, medium, low)
    published_date: str            # Дата публикации
    source_url: str                # URL источника
    vendor: str                    # Вендор (Moxa, Cisco, etc.)
    cvss_score: Optional[float]    # CVSS score (если найден)
    affected_products: Optional[List[str]]  # Затронутые продукты
    references: Optional[List[str]]         # Дополнительные ссылки
```

## Особенности парсинга

### Извлечение CVE ID
Парсер использует регулярное выражение для поиска CVE ID в тексте:
- Паттерн: `CVE-\d{4}-\d{4,}`
- Примеры: `CVE-2024-1234`, `CVE-2023-12345`

### Извлечение CVSS Score
Парсер ищет CVSS score в различных форматах:
- `CVSS: 7.5`
- `CVSS v3: 8.1`
- `Score: 9.8`

### Определение Severity
Автоматическое определение уровня серьезности на основе ключевых слов:
- **Critical**: critical, критический
- **High**: high, высокий
- **Medium**: medium, средний, moderate
- **Low**: low, низкий

## Ограничения

1. **Структура сайтов**: Парсер использует общие паттерны для поиска данных. Если структура сайта изменится, парсер может не найти уязвимости.

2. **Динамический контент**: Некоторые сайты используют JavaScript для загрузки контента. Для таких случаев может потребоваться Selenium.

3. **Rate Limiting**: Парсер включает задержку между запросами (по умолчанию 1 секунда) для избежания блокировок.

4. **Аутентификация**: Некоторые сайты могут требовать авторизацию для доступа к данным.

## Расширение функциональности

### Добавление нового источника

1. Добавьте функцию парсера в класс:

```python
def _parse_new_vendor(self, base_url: str, limit: int) -> List[Vulnerability]:
    """Парсинг нового вендора"""
    vulnerabilities = []
    soup = self._fetch_page(base_url)
    if not soup:
        return vulnerabilities
    
    # Ваша логика парсинга
    items = soup.find_all('div', class_='vulnerability-item')
    
    for item in items[:limit]:
        text = item.get_text()
        cve_ids = self._extract_cve_ids(text)
        
        if cve_ids:
            vuln = Vulnerability(
                cve_id=cve_ids[0],
                title=item.find('h2').get_text(strip=True),
                description=text[:500],
                severity=self._extract_severity(text),
                published_date='',
                source_url=base_url,
                vendor='New Vendor',
                cvss_score=self._extract_cvss_score(text)
            )
            vulnerabilities.append(vuln)
    
    return vulnerabilities
```

2. Зарегистрируйте парсер:

```python
self.parsers = {
    # ... существующие парсеры
    'new_vendor': self._parse_new_vendor,
}
```

## Интеграция с основной системой

Парсер может быть интегрирован в `UnifiedParserService`:

```python
from services.multi_source_vulnerability_parser import MultiSourceVulnerabilityParser

# В UnifiedParserService
self.multi_source_parser = MultiSourceVulnerabilityParser()

# Использование
sources = {
    'moxa': 'https://www.moxa.com/en/support/support/security-advisory',
    'cisco': 'https://sec.cloudapps.cisco.com/security/center/publicationListing.x',
}

results = self.multi_source_parser.parse_all_sources(sources, limit_per_source=50)
```

## Пример вывода

```
🚀 Начало парсинга всех источников...
📋 Всего источников: 22

Парсинг источника: moxa (https://www.moxa.com/en/support/support/security-advisory)
Найдено 15 уязвимостей из moxa

Парсинг источника: cisco (https://sec.cloudapps.cisco.com/security/center/publicationListing.x)
Найдено 42 уязвимостей из cisco

================================================================================
РЕЗУЛЬТАТЫ ПАРСИНГА
================================================================================

📊 MOXA: 15 уязвимостей
  1. CVE-2024-1234 - Security Advisory for Industrial Router...
     Severity: high, Vendor: Moxa
     CVSS: 7.5

📊 CISCO: 42 уязвимостей
  1. CVE-2024-5678 - Cisco IOS XE Software Vulnerability...
     Severity: critical, Vendor: Cisco
     CVSS: 9.8

✅ Всего найдено уязвимостей: 157

📈 Статистика по вендорам:
  Cisco: 42
  Moxa: 15
  Fortinet: 12
  ...

💾 Результаты сохранены в parsed_vulnerabilities.json
```

## Примечания

- Парсер работает независимо от основной системы
- Результаты сохраняются в JSON формате
- Можно легко добавить сохранение в базу данных
- Поддерживается расширение для новых источников
