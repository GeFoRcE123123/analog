# Процесс сохранения уязвимостей в БД

## Обзор процесса

### 1. Подготовка данных
```python
# services/unified_parser_service.py
vulnerability = Vulnerability(
    id=0,
    cve_id="CVE-2024-TEST-001",
    title="Название уязвимости",
    description="Описание",
    severity="high",
    cvss_score=7.5,
    source_identifier="Debian"  # или Ubuntu, RedHat, OSV
)
```

### 2. Вызов save_vulnerability()
```python
# models/legacy_repositories.py
result = self.vuln_repo.save_vulnerability(vulnerability)
```

### 3. Внутренний процесс сохранения

#### Шаг 1: Сохранение в таблицу `turn`
```sql
-- Проверка существования
SELECT id FROM turn WHERE cve = 'CVE-2024-TEST-001';

-- Если не существует - INSERT
INSERT INTO turn (
    source, link, cve, joining_date, name, cvss,
    price_one, priority, start_date, end_date, etc, status
) VALUES (
    'Debian', 'https://...', 'CVE-2024-TEST-001', 
    '2024-01-01', 'Название', 7.5, 75.0, 7.5, 
    '2024-01-01', NULL, '{"category":"debian"}', true
) RETURNING id;

-- Если существует - UPDATE
UPDATE turn SET source=..., name=..., cvss=... WHERE cve=... RETURNING id;
```

#### Шаг 2: Сохранение в таблицу `cvelist`
```sql
-- Проверка существования
SELECT cve FROM cvelist WHERE cve = 'CVE-2024-TEST-001';

-- Если не существует - INSERT
INSERT INTO cvelist (cve, ff_eng, ff_rus) 
VALUES ('CVE-2024-TEST-001', 'English description', '');

-- Если существует - UPDATE
UPDATE cvelist SET ff_eng=..., ff_rus=... WHERE cve=...;
```

#### Шаг 3: Сохранение CWE данных (если есть)
```sql
-- Сохранение в cwelist
INSERT INTO cwelist (cwe, interpretation, wayexploitation)
VALUES ('CWE-79', 'Description', '');
```

#### Шаг 4: Сохранение в таблицу `map_table`
```sql
-- Проверка существования
SELECT cve FROM map_table WHERE cve = 'CVE-2024-TEST-001';

-- Если не существует - INSERT
INSERT INTO map_table (cve, cvss, cwe, exploit, patch, attack_compl)
VALUES ('CVE-2024-TEST-001', '7.5', 'CWE-79', false, false, 'debian');

-- Если существует - UPDATE
UPDATE map_table SET cvss=..., cwe=..., exploit=... WHERE cve=...;
```

#### Шаг 5: COMMIT транзакции
```python
self.db.commit()  # Сохраняем все изменения
```

## Текущие изменения

### ✅ Отключена проверка существования
- Все уязвимости сохраняются без проверки
- Режим тестирования для диагностики

### ✅ Закомментирована логика ИИ
- `is_ai_related` - закомментировано
- `ai_confidence` - закомментировано
- ИИ уязвимости обрабатываются как обычные

### ✅ Добавлено детальное логирование
- Каждый шаг сохранения логируется
- Показывается результат каждого SQL запроса
- Детальные ошибки с traceback

## Структура таблиц

### `turn` (основная таблица)
- `id` - автоинкремент
- `source` - источник (Debian, Ubuntu, RedHat, OSV, NVD)
- `cve` - CVE ID
- `name` - название
- `cvss` - CVSS score
- `etc` - JSON с метаданными

### `cvelist` (описания)
- `cve` - CVE ID
- `ff_eng` - английское описание
- `ff_rus` - русское описание

### `map_table` (маппинг)
- `cve` - CVE ID
- `cvss` - CVSS score
- `cwe` - CWE ID
- `exploit` - наличие эксплойта
- `patch` - наличие патча

