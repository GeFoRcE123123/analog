# CVE JSON 5.x Schema Integration

Этот каталог содержит официальную схему CVE JSON 5.x из репозитория [CVEProject/cve-schema](https://github.com/CVEProject/cve-schema).

## Структура

```
schema/cve_json5/
├── schemas/              # JSON схемы CVE Record Format
│   ├── CVE_Record_Format.json
│   └── CVE_Record_Format_bundled.json
├── examples/             # Примеры CVE записей
│   ├── full-record-basic-example.json
│   ├── full-record-advanced-example.json
│   ├── cnaContainer-basic-example.json
│   └── cnaContainer-advanced-example.json
├── validators/           # Валидаторы
│   ├── D7Validator.py   # Оригинальный валидатор из репозитория
│   └── cve_json5_validator.py  # Обертка для использования в проекте
├── imports/              # Импортируемые схемы
│   └── cvss/            # CVSS схемы (v2.0, v3.0, v3.1, v4.0)
└── tags/                # Теги для ссылок и метаданных
    ├── reference-tags.json
    ├── cna-tags.json
    └── adp-tags.json
```

## Использование

### Валидация CVE записей

```python
from schema.cve_json5.validators.cve_json5_validator import cve_json5_validator

# Валидация одной записи
is_valid, errors = cve_json5_validator.validate(cve_record)

# Валидация файла
is_valid, errors = cve_json5_validator.validate_file('cve_record.json')

# Валидация списка записей
results = cve_json5_validator.validate_batch(cve_records)
```

### Парсинг Debian CVE в формат JSON 5.x

```python
from services.debian_cve_json5_parser import debian_cve_json5_parser

# Парсинг одного CVE
cve_json5 = debian_cve_json5_parser.parse_debian_cve_to_json5('CVE-2024-1234')

# Парсинг нескольких CVE
cve_list = debian_cve_json5_parser.parse_multiple_cves(['CVE-2024-1234', 'CVE-2024-5678'])
```

### Адаптация CVE JSON 5.x в внутренний формат

```python
from services.cve_json5_adapter import cve_json5_adapter

# Парсинг CVE JSON 5.x записи
parsed_data = cve_json5_adapter.parse_cve_record(cve_json5_record)

# Преобразование в объект Vulnerability
vulnerability = cve_json5_adapter.to_vulnerability(parsed_data)
```

## Источники

- **Официальный репозиторий**: https://github.com/CVEProject/cve-schema
- **Документация**: https://github.com/CVEProject/cve-schema/blob/main/README.md
- **Примеры**: https://github.com/CVEProject/cve-schema/tree/main/schema/docs

## Лицензия

CC0-1.0 (как в оригинальном репозитории)
