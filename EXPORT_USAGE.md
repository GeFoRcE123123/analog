# Использование экспорта БДУ в JSON

## Быстрый старт

### 1. Создание демонстрационных данных

```bash
python3 create_demo_data.py
```

Создает файл `osint_redi/demo_data/vulnerabilities.json` с 3 примерами уязвимостей.

### 2. Экспорт из файлов (без БД)

```bash
python3 export_bdu_from_files.py
```

Экспортирует данные в JSON файлы:
- `bdu_export_YYYYMMDD_HHMMSS.json` - только БДУ уязвимости
- `bdu_export_all_YYYYMMDD_HHMMSS.json` - все уязвимости

## Структура экспорта

Каждый JSON файл содержит:

```json
{
  "exported_at": "2026-01-26T16:28:21.980377",
  "count": 2,
  "include_all": false,
  "vulnerabilities": [
    {
      "id": 1,
      "title": "...",
      "description": "...",
      "severity": "high",
      "cve_id": "CVE-2023-0437",
      "bdu": { ... },
      "bdu_excel_row": {
        "Статус": "True",
        "Идентификатор": "True",
        "Наименование уязвимости": "...",
        "Идентификаторы других систем описаний уязвимости": "CVE-2023-0437",
        ...
        // Всего 26 колонок
      }
    }
  ]
}
```

## Использование в коде

```python
from services.export_service import ExportService

# Загрузка данных из файла
import json
with open("osint_redi/demo_data/vulnerabilities.json", "r") as f:
    data = json.load(f)

# Преобразование в объекты (см. export_bdu_from_files.py для примера)
from export_bdu_from_files import FileVulnerability
vulnerabilities = [FileVulnerability(v) for v in data]

# Экспорт
export_service = ExportService()
filename = export_service.export_bdu_json(
    vulnerabilities,
    output_dir="osint_redi",
    filename_prefix="bdu_export",
    include_all=False  # True для всех, False только БДУ
)
```

## Результаты

✅ Создано 2 файла экспорта:
- `bdu_export_20260126_162821.json` - 2 записи (только БДУ)
- `bdu_export_all_20260126_162821.json` - 3 записи (все)

✅ Все 26 колонок БДУ присутствуют в `bdu_excel_row`
✅ Данные соответствуют структуре Excel файла
