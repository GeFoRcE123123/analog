# Интеграция официального формата CVE JSON 5.x

## 📚 Источники

1. **CVE Schema Repository**: https://github.com/CVEProject/cve-schema.git
   - Официальная JSON схема CVE Record Format 5.x
   - Версия 5.2.0 (текущая production версия)
   - Управляется CVE Quality Working Group

2. **CVE Downloads**: https://www.cve.org/Downloads
   - Официальные JSON файлы CVE
   - Актуальные данные всех уязвимостей
   - Регулярные обновления

## ✅ Что реализовано

### 1. Адаптер CVE JSON 5.x
- `services/cve_json5_adapter.py` - парсинг официального формата
- Поддержка всех основных полей:
  - cveMetadata (ID, статус, даты)
  - descriptions (описания на разных языках)
  - affected (затронутые продукты)
  - references (ссылки)
  - metrics (CVSS, EPSS)
  - workarounds/solutions (решения)

### 2. Загрузчик CVE JSON
- `services/cve_json_loader.py` - загрузка и обработка JSON файлов
- Поддержка gzip сжатия
- Фильтрация по датам
- Пакетная обработка

### 3. Интеграция с UnifiedParserService
- Добавлен метод `_parse_cve_json5()`
- Автоматическое преобразование в объекты Vulnerability
- Сохранение в БД

## 🔧 Использование

### Загрузка из файла

```python
from services.cve_json_loader import cve_json_loader

# Загрузить и распарсить файл
parsed_cves = cve_json_loader.load_and_parse_file('/path/to/cve-json-file.json')

# Использовать через UnifiedParserService
from services.unified_parser_service import unified_parser_service
result = unified_parser_service._parse_cve_json5(file_path='/path/to/cve-json-file.json')
```

### Парсинг одной записи

```python
from services.cve_json5_adapter import cve_json5_adapter

# Парсинг CVE записи
cve_data = cve_json5_adapter.parse_cve_record(cve_json_record)

# Преобразование в Vulnerability
vulnerability = cve_json5_adapter.to_vulnerability(cve_data)
```

### Интеграция в существующий парсер

Можно использовать в существующем NVD парсере:

```python
# В nvd_parser.py
from services.cve_json5_adapter import cve_json5_adapter

def parse_cve_json5(self, cve_json):
    parsed = cve_json5_adapter.parse_cve_record(cve_json)
    vulnerability = cve_json5_adapter.to_vulnerability(parsed)
    return vulnerability
```

## 📊 Структура данных

### Входной формат (CVE JSON 5.x):
```json
{
  "dataType": "CVE_RECORD",
  "dataVersion": "5.0",
  "cveMetadata": {
    "cveId": "CVE-2024-1234",
    "state": "PUBLISHED"
  },
  "containers": {
    "cna": {
      "descriptions": [...],
      "affected": [...],
      "references": [...],
      "metrics": [...]
    }
  }
}
```

### Выходной формат (нормализованный):
```python
{
  'cve_id': 'CVE-2024-1234',
  'title': '...',
  'description': '...',
  'severity': 'high',
  'cvss_score': 7.5,
  'cvss_version': '3.1',
  'affected_products': [...],
  'references': [...],
  'published_date': datetime(...),
  ...
}
```

## 🔄 Преимущества

1. **Официальный формат** - использование стандартизированного формата CVE
2. **Полнота данных** - все поля из официальной схемы
3. **Актуальность** - прямые данные от CVE.org
4. **Совместимость** - интеграция с существующей системой
5. **Расширяемость** - легко добавить поддержку новых полей

## 📋 Следующие шаги

1. **Загрузка с официального API**:
   - Реализовать загрузку JSON файлов с https://www.cve.org/Downloads
   - Поддержка инкрементальных обновлений
   - Автоматическая синхронизация

2. **Валидация по схеме**:
   - Загрузить JSON Schema из репозитория
   - Валидация данных перед парсингом
   - Обработка ошибок валидации

3. **Клонирование схемы**:
   ```bash
   git clone https://github.com/CVEProject/cve-schema.git data/cve-schema
   ```

4. **UI для загрузки**:
   - Страница для загрузки CVE JSON файлов
   - Просмотр загруженных данных
   - Статистика по загруженным CVE

## 🔗 Полезные ссылки

- [CVE Schema Repository](https://github.com/CVEProject/cve-schema)
- [CVE Downloads](https://www.cve.org/Downloads)
- [CVE Record Format Documentation](https://github.com/CVEProject/cve-schema/blob/main/README.md)

