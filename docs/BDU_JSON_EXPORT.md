# Экспорт БДУ в JSON

## Описание

Экспорт уязвимостей с БДУ метриками в JSON формат, строго соответствующий структуре Excel файла `docs/парсеры ии бду.xlsx`.

## Структура JSON

Экспортируемый JSON содержит **26 колонок** в точном соответствии с Excel:

1. Статус
2. Идентификатор
3. Наименование уязвимости
4. Идентификаторы других систем описаний уязвимости
5. Описание уязвимости
6. Вендор ПО
7. Название ПО
8. Версия ПО
9. Класс уязвимости
10. Наименование ОС и тип аппаратной платформы
11. Дата выявления
12. Уровень опасности уязвимости
13. CVSS 2.0
14. CVSS 3.1
15. CVSS 4.0
16. Возможные меры по устранению
17. Статус уязвимости
18. Информация об устранении
19. Дата устранения
20. Наличие эксплойта
21. Способ устранения
22. Способ эксплуатации
23. Ссылки на источники
24. cnt_arch
25. Описание ошибки CWE
26. Тип ошибки CWE

## Использование

### Через веб-интерфейс

1. Перейдите на страницу дашборда
2. Используйте форму экспорта (если доступна)

### Через API (с авторизацией)

```bash
# 1. Сначала авторизуйтесь и получите сессию
curl -c cookies.txt -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=your_password"

# 2. Экспорт только БДУ уязвимостей
curl -b cookies.txt -X POST http://localhost:5000/api/bdu/export-json \
  -H "Content-Type: application/json" \
  -d '{"include_all": false}'

# 3. Экспорт всех уязвимостей (включая без BDU ID)
curl -b cookies.txt -X POST http://localhost:5000/api/bdu/export-json \
  -H "Content-Type: application/json" \
  -d '{"include_all": true}'
```

### Прямой вызов из Python

```python
from services.export_service import ExportService
from services.vulnerability_service import VulnerabilityService

# Инициализация
vuln_service = VulnerabilityService()
export_service = ExportService()

# Получение уязвимостей
vulnerabilities = vuln_service.get_all_vulnerabilities_unlimited()

# Экспорт
filename = export_service.export_bdu_json(
    vulnerabilities,
    output_dir="osint_redi",
    filename_prefix="bdu_export",
    include_all=False  # True для всех, False только для БДУ
)

print(f"Файл сохранен: {filename}")
```

## Формат выходного файла

```json
{
  "exported_at": "2026-01-26T12:34:56.789012",
  "count": 150,
  "include_all": false,
  "vulnerabilities": [
    {
      "id": 123,
      "title": "Название уязвимости",
      "description": "Описание...",
      "severity": "high",
      "status": "open",
      "cve_id": "CVE-2023-0437",
      "bdu": { ... },
      "bdu_excel_row": {
        "Статус": "True",
        "Идентификатор": "True",
        "Наименование уязвимости": "...",
        "Идентификаторы других систем описаний уязвимости": "CVE-2023-0437",
        ...
      }
    }
  ]
}
```

## Расположение файлов

Экспортированные файлы сохраняются в:
```
vulnerability_manager/osint_redi/bdu_export_YYYYMMDD_HHMMSS.json
```

## Параметры

- `include_all` (bool):
  - `false` - экспортировать только уязвимости с `bdu_id`
  - `true` - экспортировать все уязвимости

## Особенности

- ✅ Строгое соответствие структуре Excel (26 колонок)
- ✅ Правильное форматирование дат (`YYYY-MM-DD HH:MM:SS`)
- ✅ Очистка данных от Excel-специфичных символов (`_x000D_`)
- ✅ UTF-8 кодировка с поддержкой кириллицы
- ✅ Пустые поля как `""` вместо `null` для совместимости
