# Интеграция с NVD API - Текущее состояние

## ✅ Подключение к NVD API

**Статус**: **РАБОТАЕТ** (без API ключа, с ограничением 5 запросов/сек)

---

## 📋 Компоненты интеграции

### 1. Основной парсер
- **Файл**: `services/nvd_parser.py`
- **Класс**: `MultiThreadedNVDParser`
- **API Endpoint**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Версия API**: 2.0 (JSON)

### 2. Сервис интеграции
- **Файл**: `services/nvd_integration_service.py`
- **Класс**: `NVDIntegrationService`
- **Функции**:
  - `full_sync()` - полная синхронизация всех уязвимостей
  - `incremental_sync(days)` - синхронизация за последние N дней
  - `sync_ai_vulnerabilities()` - синхронизация только AI-уязвимостей
  - `validate_connection()` - проверка подключения

### 3. Адаптер парсера
- **Файл**: `services/parsers/nvd_parser_adapter.py`
- **Класс**: `NVDParserAdapter`
- Интеграция с новой архитектурой парсеров

---

## 🔑 API Ключ (опционально)

### Текущее состояние
- **API ключ**: НЕ используется (пустая строка `''`)
- **Лимит без ключа**: 5 запросов в секунду
- **Лимит с ключом**: 50 запросов в секунду

### Как получить API ключ NVD

1. **Регистрация**:
   - Перейдите на: https://nvd.nist.gov/developers/request-an-api-key
   - Заполните форму регистрации
   - Подтвердите email

2. **Получение ключа**:
   - После регистрации вы получите API ключ
   - Ключ будет выглядеть примерно так: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

3. **Настройка в проекте**:
   ```python
   # В config.py добавить:
   NVD_API_KEY = "ваш-api-ключ-здесь"
   
   # Или через переменную окружения:
   export NVD_API_KEY="ваш-api-ключ-здесь"
   ```

4. **Использование**:
   ```python
   from services.nvd_parser import MultiThreadedNVDParser
   
   parser = MultiThreadedNVDParser(api_key="ваш-api-ключ")
   ```

---

## 🚀 Как использовать

### Вариант 1: Через сервис интеграции
```python
from services.nvd_integration_service import NVDIntegrationService
from models.postgres_repositories import PostgresVulnerabilityRepository
from database.database_manager import DatabaseManager

# Инициализация
db_manager = DatabaseManager()
vuln_repo = PostgresVulnerabilityRepository(db_manager.connection)
nvd_service = NVDIntegrationService(vuln_repo, api_key="ваш-ключ-или-None")

# Полная синхронизация
stats = nvd_service.full_sync()

# Инкрементальная синхронизация (последние 7 дней)
stats = nvd_service.incremental_sync(days=7)

# Проверка подключения
status = nvd_service.validate_connection()
print(status)  # {'status': 'success', 'message': '...'}
```

### Вариант 2: Через парсер напрямую
```python
from services.nvd_parser import MultiThreadedNVDParser

parser = MultiThreadedNVDParser(
    api_key="ваш-ключ-или-None",
    max_workers=10,
    requests_per_second=5  # или 50 с ключом
)

# Получить все уязвимости
all_vulns, ai_vulns = parser.get_all_vulnerabilities()

# Получить за последние 30 дней
all_vulns, ai_vulns = parser.get_recent_vulnerabilities(days=30)
```

### Вариант 3: Через Unified Parser Service
```python
from services.unified_parser_service import UnifiedParserService

service = UnifiedParserService()
results = service.parse_all_sources(sources=['nvd'], limit_per_source=100)
```

---

## 📊 Возможности

### ✅ Что уже работает:
- ✅ Получение уязвимостей из NVD API 2.0
- ✅ Многопоточная загрузка (до 2000 записей за раз)
- ✅ Rate limiting (защита от блокировки)
- ✅ Обработка ошибок (403, 429, timeout)
- ✅ Парсинг CVSS метрик (v2, v3.1, v4)
- ✅ Парсинг CWE, ссылок, конфигураций
- ✅ Определение AI-уязвимостей по ключевым словам
- ✅ Сохранение в БД через репозиторий
- ✅ Инкрементальная и полная синхронизация

### 📝 Что сохраняется в БД:
- Основная информация (CVE ID, описание, статус)
- CVSS векторы и метрики (v2, v3, v4)
- EPSS (Exploit Prediction Scoring System)
- CWE коды
- Затронутые продукты (CPE)
- Ссылки (references)
- Конфигурации CPE
- Weaknesses (CWE)
- Даты публикации и изменения
- Флаги (KEV, CERT alerts)

---

## ⚙️ Конфигурация

### Параметры парсера:
```python
MultiThreadedNVDParser(
    api_key=None,              # API ключ (опционально)
    max_workers=10,            # Количество потоков
    requests_per_second=5      # Лимит запросов (5 без ключа, 50 с ключом)
)
```

### Параметры сервиса интеграции:
```python
NVDIntegrationService.config = {
    'max_retries': 3,              # Попытки при ошибках
    'retry_delay': 60,             # Задержка между попытками (сек)
    'batch_size': 100,             # Размер пачки для сохранения
    'sync_interval_hours': 24      # Интервал синхронизации
}
```

---

## 🔒 Rate Limiting

### Без API ключа:
- **Лимит**: 5 запросов в секунду
- **Блокировка**: При превышении лимита (HTTP 429) - автоматическая пауза 60 сек

### С API ключом:
- **Лимит**: 50 запросов в секунду
- **Блокировка**: Меньше вероятность блокировки

### Реализация:
- Автоматическое ограничение частоты запросов
- Обработка HTTP 429 (Too Many Requests)
- Автоматическая пауза при блокировке

---

## 📡 API Endpoints NVD

### Используемый endpoint:
```
GET https://services.nvd.nist.gov/rest/json/cves/2.0
```

### Параметры запроса:
- `startIndex` - начальный индекс (пагинация)
- `resultsPerPage` - количество результатов (до 2000)
- `pubStartDate` - дата начала публикации
- `pubEndDate` - дата окончания публикации
- `lastModStartDate` - дата начала последнего изменения
- `lastModEndDate` - дата окончания последнего изменения

### Headers:
- `User-Agent`: VulnerabilityManager/1.0
- `apiKey`: ваш API ключ (если есть)

---

## 🧪 Проверка подключения

### Тест через код:
```python
from services.nvd_integration_service import NVDIntegrationService
from models.postgres_repositories import PostgresVulnerabilityRepository
from database.database_manager import DatabaseManager

db_manager = DatabaseManager()
vuln_repo = PostgresVulnerabilityRepository(db_manager.connection)
nvd_service = NVDIntegrationService(vuln_repo)

status = nvd_service.validate_connection()
print(status)
```

### Тест через API endpoint (если есть):
```bash
curl -H "apiKey: ваш-ключ" \
     "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
```

---

## 🐛 Обработка ошибок

### HTTP 403 (Forbidden):
- Причина: Неверный API ключ или блокировка IP
- Решение: Проверить API ключ, подождать

### HTTP 429 (Too Many Requests):
- Причина: Превышен лимит запросов
- Решение: Автоматическая пауза 60 сек, затем повтор

### Timeout:
- Причина: Сеть или API недоступен
- Решение: Автоматический повтор с задержкой

### Connection Error:
- Причина: Проблемы с сетью
- Решение: Проверить подключение к интернету

---

## 📚 Дополнительные ресурсы

- **NVD API Документация**: https://nvd.nist.gov/developers/vulnerabilities
- **Регистрация API ключа**: https://nvd.nist.gov/developers/request-an-api-key
- **API 2.0 Спецификация**: https://nvd.nist.gov/developers/vulnerabilities#API-2.0
- **CVE JSON 5.0 Schema**: https://github.com/CVEProject/cve-schema

---

## ✅ Итог

**Интеграция с NVD API полностью реализована и работает!**

- ✅ Подключение установлено
- ✅ Парсинг данных работает
- ✅ Сохранение в БД настроено
- ✅ Rate limiting реализован
- ✅ Обработка ошибок есть

**Для увеличения производительности (50 req/sec вместо 5):**
1. Зарегистрируйтесь на https://nvd.nist.gov/developers/request-an-api-key
2. Получите API ключ
3. Добавьте его в конфигурацию проекта

