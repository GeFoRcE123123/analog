# БДУ ФСТЭК - Миграция базы данных

## 📋 Описание

Эта миграция добавляет **30+ полей** в таблицу `vulnerabilities` для полной поддержки данных БДУ ФСТЭК.

## 🎯 Что добавляется

### 1. Идентификация
- `bdu_id` - Уникальный ID БДУ (BDU:YYYY-XXXXX)
- `bdu_name` - Название из БДУ

### 2. Информация о ПО
- `vendor` - Вендор ПО
- `product_name` - Название продукта
- `affected_versions` - Уязвимые версии
- `platform` - Платформа (32/64-bit)
- `software_types` - JSONB типы ПО
- `registry_number` - Регистрационный номер
- `vulnerable_software` - JSONB полная структура

### 3. Окружение
- `environment` - JSONB информация об ОС

### 4. Технические детали
- `cwes` - JSONB массив CWE
- `vul_class` - Класс уязвимости
- `sl_oper_procs` - Служебные процессы

### 5. Даты
- `identify_date` - Дата обнаружения
- `publication_date` - Дата публикации в БДУ
- `last_upd_date` - Дата обновления

### 6. Оценка рисков
- `cvss2_vector`, `cvss2_score` - CVSS 2.0
- `cvss3_vector`, `cvss3_score` - CVSS 3.0
- `bdu_severity` - Уровень опасности (текст)

### 7. Статусы
- `vul_status` - Статус уязвимости
- `exploit_status` - Наличие эксплоита
- `fix_status` - Статус устранения
- `solution` - Способ устранения

### 8. Дополнительно
- `sources` - Источники
- `other_identifiers` - JSONB других ID
- `vul_incident` - Информация об инциденте
- `vul_state` - Состояние
- `vul_elimination` - Способ устранения

## 🚀 Применение миграции

### Вариант 1: Локальная БД

```bash
psql -U your_user -d vuln_db -f scripts/migration/add_bdu_fields_v2.sql
```

### Вариант 2: Удаленная БД (10.0.88.11)

```bash
psql -h 10.0.88.11 -U vuln_user -d vuln_db -f scripts/migration/add_bdu_fields_v2.sql
```

### Вариант 3: Через Docker контейнер

```bash
docker exec -i postgres-container psql -U vuln_user -d vuln_db < scripts/migration/add_bdu_fields_v2.sql
```

### Вариант 4: SSH + psql

```bash
ssh user@10.0.88.11 "psql -U vuln_user -d vuln_db" < scripts/migration/add_bdu_fields_v2.sql
```

## ✅ Проверка миграции

После применения миграции проверьте:

```sql
-- 1. Проверить добавленные колонки
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'vulnerabilities' 
  AND column_name LIKE '%bdu%' OR column_name IN ('vendor', 'product_name', 'exploit_status');

-- 2. Проверить индексы
SELECT indexname, indexdef 
FROM pg_indexes 
WHERE tablename = 'vulnerabilities' 
  AND indexname LIKE '%bdu%' OR indexname LIKE '%vendor%';

-- 3. Проверить constraints
SELECT conname, pg_get_constraintdef(oid) 
FROM pg_constraint 
WHERE conrelid = 'vulnerabilities'::regclass;

-- 4. Статистика
SELECT 
    COUNT(*) as total,
    COUNT(bdu_id) as with_bdu_id,
    COUNT(vendor) as with_vendor,
    COUNT(exploit_status) as with_exploit_status
FROM vulnerabilities;
```

## 📊 Индексы

Миграция создает **11 индексов**:
1. `idx_vulnerabilities_bdu_id` - BDU ID
2. `idx_vulnerabilities_vendor` - Вендор
3. `idx_vulnerabilities_product_name` - Продукт
4. `idx_vulnerabilities_exploit_status` - Эксплоит
5. `idx_vulnerabilities_publication_date` - Дата публикации
6. `idx_vulnerabilities_vul_class` - Класс уязвимости
7. `idx_vulnerabilities_cwes_gin` - GIN для CWE (JSONB)
8. `idx_vulnerabilities_vulnerable_software_gin` - GIN для ПО (JSONB)
9. `idx_vulnerabilities_environment_gin` - GIN для окружения (JSONB)
10. `idx_vulnerabilities_other_identifiers_gin` - GIN для ID (JSONB)
11. `idx_vulnerabilities_vendor_product` - Составной (вендор + продукт)

## ⚠️ Важно

- Миграция использует `IF NOT EXISTS` - безопасно запускать несколько раз
- Используется транзакция (`BEGIN/COMMIT`) - откат при ошибке
- Добавлены комментарии к полям для документации
- CVSS scores имеют CHECK constraints (0-10)

## 🔄 Откат миграции

Если нужно откатить миграцию (НЕ РЕКОМЕНДУЕТСЯ):

```sql
-- ВНИМАНИЕ: Удалит все данные БДУ!
BEGIN;

ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS bdu_id CASCADE;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS bdu_name CASCADE;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS vendor CASCADE;
ALTER TABLE vulnerabilities DROP COLUMN IF EXISTS product_name CASCADE;
-- ... и так далее для всех полей

COMMIT;
```

## 📝 Следующие шаги

После миграции:
1. ✅ Обновить модели данных (`models/entities.py`)
2. ✅ Создать парсер XML БДУ
3. ✅ Обновить API endpoints
4. ✅ Обновить Frontend
5. ✅ Запустить импорт данных БДУ
6. ✅ Backfill существующих записей

## 📞 Поддержка

При возникновении проблем:
- Проверьте логи PostgreSQL
- Убедитесь что у пользователя есть права на ALTER TABLE
- Проверьте версию PostgreSQL (требуется 12+)

