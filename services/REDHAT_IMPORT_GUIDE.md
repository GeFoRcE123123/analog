# Руководство по импорту Red Hat CVE в БД

## Компоненты

### 1. RedHatDBImporter (`services/redhat_db_importer.py`)

Класс для импорта Red Hat CVE из JSON файлов в базу данных:

- `import_to_database()` - импорт из JSON файлов
- `import_from_csv()` - импорт из CSV файла
- `load_json_files()` - загрузка JSON файлов

### 2. Red Hat Full Downloader (`services/redhat_full_downloader.py`)

Скрипт для скачивания данных из Red Hat API.

### 3. API Endpoints

- `POST /api/redhat/import` - асинхронный импорт (для больших объемов)
- `POST /api/redhat/import-sync` - синхронный импорт (для небольших объемов)

### 4. Web Interface

Секция Red Hat парсера добавлена в `/parsers` страницу.

## Использование

### Через веб-интерфейс

1. Откройте страницу `/parsers`
2. В разделе "Red Hat Парсер" выберите режим:
   - **Скачать из API и импортировать** - скачивает данные и импортирует в БД
   - **Импортировать из существующих файлов** - импортирует из уже скачанных JSON
   - **Импортировать из CSV** - импортирует из CSV файла
3. Настройте параметры:
   - Максимальное количество страниц (для скачивания)
   - Лимит импорта (опционально)
   - Пропускать существующие CVE
4. Нажмите "Импортировать Red Hat CVE"

### Через командную строку

```bash
# Импорт из JSON файлов
python3 services/redhat_db_importer.py --data-dir cve_data/full --limit 1000

# Импорт из CSV
python3 services/redhat_db_importer.py --csv cve_data/full/redhat_all_cve.csv --limit 500

# Полный импорт (без ограничений)
python3 services/redhat_db_importer.py --data-dir cve_data/full
```

### Через Python API

```python
from services.redhat_db_importer import RedHatDBImporter

# Создание импортера
importer = RedHatDBImporter(data_dir="cve_data/full")

# Импорт из JSON файлов
result = importer.import_to_database(limit=1000, skip_existing=True)

print(f"Импортировано: {result['imported']}")
print(f"Пропущено: {result['skipped']}")
print(f"Ошибок: {result['errors']}")
```

## Процесс импорта

1. **Загрузка данных** - чтение JSON файлов из `cve_data/full/page_*.json`
2. **Трансформация** - преобразование формата Red Hat в NVD-совместимый формат
3. **Проверка существования** - проверка, есть ли CVE уже в БД (если `skip_existing=True`)
4. **Сохранение** - сохранение через репозиторий (legacy или modern схема)
5. **Статистика** - возврат статистики импорта

## Статистика импорта

```json
{
  "success": true,
  "message": "Импортировано 500 из 2000 записей",
  "total": 2000,
  "imported": 500,
  "skipped": 1500,
  "errors": 0
}
```

## Интеграция с существующей системой

- Использует существующий `RedHatCVEImporter` для трансформации
- Совместим с legacy и modern схемами БД
- Интегрирован в веб-интерфейс парсеров
- Поддерживает дедупликацию (пропуск существующих CVE)

## Требования

- `pandas` - для работы с CSV
- `requests` - для скачивания данных
- Подключение к БД (через `DatabaseManager`)

## Примеры использования

### Полный цикл: скачать и импортировать

```bash
# 1. Скачать данные
python3 services/redhat_full_downloader.py --download --max-pages 10

# 2. Импортировать в БД
python3 services/redhat_db_importer.py --data-dir cve_data/full
```

### Импорт из существующих файлов

```bash
python3 services/redhat_db_importer.py --data-dir cve_data/full --limit 1000
```

### Импорт из CSV

```bash
# Сначала создать CSV (если еще не создан)
python3 services/redhat_full_downloader.py --process

# Затем импортировать из CSV
python3 services/redhat_db_importer.py --csv cve_data/full/redhat_all_cve.csv
```
