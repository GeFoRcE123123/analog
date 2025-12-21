# 🚀 Современная архитектура парсеров уязвимостей

Модульная система парсинга уязвимостей с поддержкой множества источников, AI/ML анализа, нормализации данных и дедупликации.

## 📋 Содержание

1. [Архитектура](#архитектура)
2. [Основные компоненты](#основные-компоненты)
3. [Использование](#использование)
4. [Расширение](#расширение)

## 🏗️ Архитектура

```
services/parsers/
├── __init__.py              # Экспорты модуля
├── base_parser.py           # Базовый класс BaseParser
├── normalizer.py            # Система нормализации данных
├── ai_analyzer.py           # AI/ML анализатор
├── deduplicator.py          # Система дедупликации
├── nvd_parser_adapter.py    # Пример адаптера (NVD)
└── README.md                # Эта документация
```

## 🔧 Основные компоненты

### 1. BaseParser

Базовый класс для всех парсеров, обеспечивающий:

- ✅ Единообразный интерфейс
- ✅ Обработку ошибок и retry логику
- ✅ Rate limiting
- ✅ Прогресс-трекинг
- ✅ Безопасность (SSL проверка, валидация URL)

**Пример использования:**

```python
from services.parsers import BaseParser

class MyCustomParser(BaseParser):
    def parse(self, **kwargs):
        # Ваша логика парсинга
        pass
    
    def get_source_info(self):
        return {
            'name': 'My Source',
            'type': 'api',
            'url': 'https://example.com',
            'description': 'Описание источника'
        }
```

### 2. DataNormalizer

Система нормализации данных для унификации форматов:

- ✅ CVSS (v2, v3, v4) → единый формат
- ✅ CPE → стандартный формат 2.3
- ✅ CWE → нормализованные коды
- ✅ Даты → datetime объекты
- ✅ Severity → critical/high/medium/low

**Пример:**

```python
from services.parsers import normalizer, NormalizedVulnerability

# Нормализация сырых данных
raw_data = {
    'cve_id': 'CVE-2023-1234',
    'cvss': {'baseScore': 9.8, 'version': '3.1'},
    'description': 'Some vulnerability...',
    # ...
}

normalized = normalizer.normalize_vulnerability(raw_data, source='nvd')
# Возвращает NormalizedVulnerability объект
```

### 3. AIAnalyzer

AI/ML модуль для анализа уязвимостей:

- ✅ Определение AI-связанных уязвимостей
- ✅ Классификация по OWASP Top 10
- ✅ Оценка zero-day потенциала
- ✅ Анализ рисков

**Пример:**

```python
from services.parsers import ai_analyzer

vulnerability_data = {
    'cve_id': 'CVE-2023-1234',
    'description': 'Vulnerability in TensorFlow...',
    'cvss_score': 9.8,
    # ...
}

# Полный анализ
analysis = ai_analyzer.analyze_all(vulnerability_data)
print(f"AI-related: {analysis['ai_classification']['is_ai_related']}")
print(f"Confidence: {analysis['ai_classification']['confidence']}")
print(f"OWASP: {analysis['owasp_classification']}")
print(f"Zero-day potential: {analysis['zero_day_assessment']['has_zero_day_potential']}")
```

### 4. Deduplicator

Система дедупликации для объединения дубликатов:

- ✅ По CVE ID (точное совпадение)
- ✅ По описанию (семантическое сходство)
- ✅ По affected products
- ✅ По CWE кодам

**Пример:**

```python
from services.parsers import deduplicator

new_vulnerability = {...}
existing_vulnerabilities = [...]

# Проверка дубликата
result = deduplicator.check_duplicate(new_vulnerability, existing_vulnerabilities)

if result.is_duplicate:
    print(f"Дубликат найден: {result.original_cve_id}")
    print(f"Confidence: {result.confidence}")
    
    # Объединение
    merged = deduplicator.merge_vulnerabilities(existing_vuln, new_vulnerability)
else:
    # Новая уязвимость
    save_new_vulnerability(new_vulnerability)
```

## 💡 Использование

### Создание нового парсера

```python
from services.parsers import BaseParser, normalizer, ai_analyzer
from typing import List, Dict, Any

class MySourceParser(BaseParser):
    def __init__(self, api_key: str = None):
        super().__init__('my_source', {
            'max_retries': 3,
            'rate_limit_delay': 1.0
        })
        self.api_key = api_key
    
    def get_source_info(self) -> Dict[str, Any]:
        return {
            'name': 'My Vulnerability Source',
            'type': 'api',
            'url': 'https://api.example.com',
            'description': 'Описание источника',
            'rate_limit': '10 requests/second'
        }
    
    def parse(self, limit: int = 100) -> List[Dict[str, Any]]:
        self.start()
        normalized_vulnerabilities = []
        
        try:
            # 1. Получение данных из источника
            raw_data = self._fetch_data(limit)
            
            # 2. Нормализация каждой уязвимости
            for raw_vuln in raw_data:
                normalized = normalizer.normalize_vulnerability(raw_vuln, source='my_source')
                
                # 3. AI анализ
                ai_result = ai_analyzer.analyze_all(raw_vuln)
                
                # 4. Формирование результата
                vuln_dict = {
                    'cve_id': normalized.cve_id,
                    'title': normalized.title,
                    'description': normalized.description,
                    'severity': normalized.severity,
                    'cvss_score': normalized.cvss_score,
                    'is_ai_related': ai_result['ai_classification']['is_ai_related'],
                    'ai_confidence': ai_result['ai_classification']['confidence'],
                    # ... другие поля
                }
                normalized_vulnerabilities.append(vuln_dict)
            
            self.status = ParserStatus.COMPLETED
            return normalized_vulnerabilities
        
        except Exception as e:
            self.logger.error(f"Ошибка парсинга: {e}")
            self.status = ParserStatus.ERROR
            return []
        
        finally:
            self.stop()
    
    def _fetch_data(self, limit: int):
        # Ваша логика получения данных
        url = f"{self.get_source_info()['url']}/vulnerabilities"
        response = self.make_request(url, params={'limit': limit})
        if response:
            return response.json()
        return []
```

### Использование адаптера NVD парсера

```python
from services.parsers import NVDParserAdapter

# Создание парсера
nvd_parser = NVDParserAdapter(api_key='your-api-key')

# Инкрементальная синхронизация (последние 7 дней)
vulnerabilities = nvd_parser.parse(days=7)

# Полная синхронизация
all_vulnerabilities = nvd_parser.full_sync()

# Статистика
stats = nvd_parser.get_stats()
print(f"Обработано: {stats['total_parsed']}")
print(f"Ошибок: {stats['errors']}")
```

### Полный цикл: парсинг → дедупликация → сохранение

```python
from services.parsers import NVDParserAdapter, deduplicator
from models.postgres_repositories import PostgresVulnerabilityRepository

# Инициализация
nvd_parser = NVDParserAdapter()
vuln_repo = PostgresVulnerabilityRepository(db_connection)

# Парсинг новых уязвимостей
new_vulnerabilities = nvd_parser.parse(days=1)

# Получение существующих из БД
existing_vulnerabilities = vuln_repo.get_all()

# Дедупликация и сохранение
for new_vuln in new_vulnerabilities:
    result = deduplicator.check_duplicate(new_vuln, existing_vulnerabilities)
    
    if result.is_duplicate:
        # Объединение с существующей
        merged = deduplicator.merge_vulnerabilities(
            existing_vuln,
            new_vuln
        )
        vuln_repo.update(merged['cve_id'], merged)
    else:
        # Сохранение новой
        vuln_repo.create(new_vuln)
```

## 🔌 Расширение

### Добавление нового источника

1. Создайте класс, наследующий `BaseParser`
2. Реализуйте методы `parse()` и `get_source_info()`
3. Используйте `normalizer` для нормализации данных
4. Используйте `ai_analyzer` для анализа
5. Интегрируйте с `deduplicator` для дедупликации

### Кастомизация AI анализа

Модуль `AIAnalyzer` можно расширить:

- Добавить новые ключевые слова в `AI_KEYWORDS`
- Настроить веса категорий в `CATEGORY_WEIGHTS`
- Добавить новые методы классификации

### Кастомизация нормализации

Модуль `DataNormalizer` поддерживает:

- Добавление новых форматов CVSS
- Расширение CPE парсинга
- Кастомные правила нормализации severity

## 📊 Метрики и мониторинг

Каждый парсер предоставляет статистику:

```python
stats = parser.get_stats()
print(f"Status: {stats['status']}")
print(f"Parsed: {stats['total_parsed']}")
print(f"Errors: {stats['errors']}")
print(f"Progress: {stats['progress']['percentage']}%")
print(f"Duration: {stats['duration_seconds']}s")
```

## 🔒 Безопасность

BaseParser включает:

- ✅ SSL проверку (можно отключить через `verify_ssl=False`)
- ✅ Валидацию URL (проверка схемы, подозрительных паттернов)
- ✅ Rate limiting для предотвращения DDoS
- ✅ Retry логику с exponential backoff

## 📝 TODO

- [ ] Система планирования (инкрементальные/полные синхронизации)
- [ ] Интеграция с Prometheus для метрик
- [ ] Система плагинов для динамической загрузки парсеров
- [ ] Расширенная система дедупликации с ML
- [ ] Поддержка WebSocket для real-time обновлений

## 🤝 Контрибуция

При добавлении новых парсеров:

1. Наследуйтесь от `BaseParser`
2. Используйте `normalizer` для нормализации
3. Используйте `ai_analyzer` для анализа
4. Добавьте тесты
5. Обновите документацию

