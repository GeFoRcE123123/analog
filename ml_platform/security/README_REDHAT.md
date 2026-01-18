# Red Hat CVE Collector

Интеграция парсера Red Hat CVE данных в платформу безопасности.

## Компоненты

### 1. RedHatCollector (`ml_platform/security/collectors/redhat_collector.py`)

Класс для работы с Red Hat Security Data API:

- **download_all_cves()** - скачивание всех CVE из API
- **load_json_files()** - загрузка скачанных JSON файлов
- **create_dataframe()** - создание pandas DataFrame
- **save_to_csv()** - сохранение в CSV формат
- **normalize_cve_data()** - нормализация данных для единого формата

### 2. Red Hat Full Downloader (`services/redhat_full_downloader.py`)

Скрипт для массового скачивания и обработки:

```bash
# Скачать все данные
python3 services/redhat_full_downloader.py --download --max-pages 10

# Обработать существующие файлы
python3 services/redhat_full_downloader.py --process

# Выполнить все (скачать и обработать)
python3 services/redhat_full_downloader.py --all
```

## Использование

### Через RedHatCollector

```python
from ml_platform.security.collectors.redhat_collector import RedHatCollector

# Создание коллектора
collector = RedHatCollector(data_dir="cve_data/redhat")

# Скачивание данных
pages = collector.download_all_cves(max_pages=5)

# Обработка файлов
records = collector.load_json_files()

# Создание DataFrame
df = collector.create_dataframe(records)

# Сохранение в CSV
csv_path = collector.save_to_csv(df)
```

### Интеграция с паспортами CVE

```python
from ml_platform.security.collectors.redhat_collector import RedHatCollector
from ml_platform.security.cve_passport import CVEPassportManager

collector = RedHatCollector()
manager = CVEPassportManager()

# Скачивание и обработка
records = collector.load_json_files()

# Создание паспортов
for record in records:
    normalized = collector.normalize_cve_data(record.get('raw_data', {}))
    passport = manager.create_passport(normalized["cve_id"], normalized)
```

## Структура данных

### JSON файлы (page_*.json)

Каждый файл содержит массив объектов CVE:

```json
[
  {
    "CVE": "CVE-2024-XXXXX",
    "bugzilla_description": "Description...",
    "threat_severity": "Important",
    "cvss3": {
      "cvss3_base_score": 7.5,
      "cvss3_scoring_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    "public_date": "2024-01-15T00:00:00Z",
    "affected_release": [...]
  }
]
```

### CSV файл (redhat_all_cve.csv)

Колонки:
- `cve_id` - идентификатор CVE
- `description` - описание уязвимости
- `severity` - уровень критичности
- `cvss3` - CVSS3 базовый score
- `public_date` - дата публикации

## Примеры

См. `ml_platform/examples/redhat_collector_demo.py` для полного примера использования.

## Интеграция с существующим кодом

Код интегрирован в:
- `ml_platform/security/collectors/redhat_collector.py` - новый коллектор
- `services/redhat_full_downloader.py` - скрипт для массового скачивания
- Существующий `services/redhat_cve_importer.py` остается без изменений

## Требования

- `requests` - для HTTP запросов
- `pandas` - для работы с данными
- `json` - стандартная библиотека Python

## API Red Hat

Документация: https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html/red_hat_security_data_api/

Особенности:
- Rate limiting: рекомендуется делать паузу 1 секунда между запросами
- Максимум 1000 записей на страницу
- Пагинация через параметр `page`
