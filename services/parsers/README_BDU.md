# БДУ ФСТЭК Parsers & Importers

## 📋 Описание

Набор инструментов для работы с данными БДУ ФСТЭК (Банк Данных Угроз).

## 🚀 Компоненты

### 1. BDU XML Parser (`bdu_xml_parser.py`)

Парсер XML файла с данными БДУ ФСТЭК.

**Возможности:**
- Streaming парсинг больших файлов (500+ MB)
- Извлечение всех полей из БДУ паспорта
- Поддержка CVSS 2.0 и 3.0
- Статистика парсинга

**Использование:**
```bash
# Парсинг и вывод первых 10 записей
python services/parsers/bdu_xml_parser.py temp_bdu/export/vulxml.xml

# Или импорт в Python
from services.parsers.bdu_xml_parser import BDUXMLParser

parser = BDUXMLParser('path/to/vulxml.xml')
for vuln in parser.parse_stream():
    print(vuln)
```

**Извлекаемые поля:**
- Идентификация: `bdu_id`, `bdu_name`, `description`
- ПО: `vendor`, `product_name`, `affected_versions`, `platform`
- Техн. детали: `cwes`, `vul_class`
- Даты: `identify_date`, `publication_date`, `last_upd_date`
- CVSS: `cvss2_vector`, `cvss2_score`, `cvss3_vector`, `cvss3_score`
- Статусы: `vul_status`, `exploit_status`, `fix_status`

### 2. BDU Importer (`bdu_importer.py`)

Импортер данных БДУ в PostgreSQL.

**Возможности:**
- Пакетная загрузка (batch insert)
- Upsert (вставка или обновление)
- Dry-run режим
- Статистика импорта

**Использование:**
```bash
# Базовый импорт
python services/parsers/bdu_importer.py --xml-file temp_bdu/export/vulxml.xml

# С настройками
python services/parsers/bdu_importer.py \
    --xml-file temp_bdu/export/vulxml.xml \
    --batch-size 2000 \
    --db-host 10.0.88.11 \
    --db-name vuln_db \
    --db-user vuln_user \
    --db-password YOUR_PASSWORD

# Dry-run (тестирование без записи в БД)
python services/parsers/bdu_importer.py \
    --xml-file temp_bdu/export/vulxml.xml \
    --dry-run
```

**Параметры:**
- `--xml-file` - Путь к vulxml.xml (обязательный)
- `--batch-size` - Размер пакета (по умолчанию: 1000)
- `--dry-run` - Режим тестирования без записи
- `--db-host` - Хост БД (по умолчанию: 10.0.88.11)
- `--db-port` - Порт БД (по умолчанию: 5432)
- `--db-name` - Название БД (по умолчанию: vuln_db)
- `--db-user` - Пользователь БД
- `--db-password` - Пароль БД

**Переменные окружения:**
```bash
export DB_HOST=10.0.88.11
export DB_PORT=5432
export DB_NAME=vuln_db
export DB_USER=vuln_user
export DB_PASSWORD=your_password
```

## 📦 Установка зависимостей

```bash
pip install psycopg2-binary
```

## 🔄 Полный процесс импорта БДУ

### Шаг 1: Скачать данные БДУ

```bash
mkdir -p temp_bdu
cd temp_bdu
curl -L --insecure -o vulxml.zip "https://bdu.fstec.ru/files/documents/vulxml.zip"
unzip vulxml.zip
cd ..
```

### Шаг 2: Применить миграцию БД

```bash
psql -h 10.0.88.11 -U vuln_user -d vuln_db -f scripts/migration/add_bdu_fields_v2.sql
```

### Шаг 3: Импортировать данные

```bash
python services/parsers/bdu_importer.py \
    --xml-file temp_bdu/export/vulxml.xml \
    --batch-size 1000
```

### Шаг 4: Проверить результат

```sql
-- Подключиться к БД
psql -h 10.0.88.11 -U vuln_user -d vuln_db

-- Статистика
SELECT 
    COUNT(*) as total,
    COUNT(bdu_id) as with_bdu,
    COUNT(cve_id) as with_cve,
    COUNT(CASE WHEN exploit_status LIKE '%Существует%' THEN 1 END) as with_exploit
FROM vulnerabilities;

-- Примеры записей
SELECT bdu_id, title, vendor, product_name, cvss3_score, exploit_status
FROM vulnerabilities
WHERE bdu_id IS NOT NULL
LIMIT 10;
```

## 📊 Статистика БДУ (на 2026-01-22)

- **Всего записей:** ~82,000
- **С CVSS 3.0:** ~71,000
- **С CVSS 2.0:** ~82,000
- **С CVE ID:** ~60,000
- **С эксплоитами:** ~15,000

## 🔍 Примеры запросов

### Поиск уязвимостей с эксплоитами

```sql
SELECT bdu_id, title, vendor, product_name, cvss3_score
FROM vulnerabilities
WHERE exploit_status LIKE '%Существует%'
ORDER BY cvss3_score DESC
LIMIT 20;
```

### Топ вендоров по количеству уязвимостей

```sql
SELECT vendor, COUNT(*) as vuln_count
FROM vulnerabilities
WHERE vendor IS NOT NULL
GROUP BY vendor
ORDER BY vuln_count DESC
LIMIT 20;
```

### Уязвимости высокой критичности

```sql
SELECT bdu_id, cve_id, title, cvss3_score, exploit_status
FROM vulnerabilities
WHERE cvss3_score >= 9.0
  AND bdu_id IS NOT NULL
ORDER BY cvss3_score DESC;
```

## ⚠️ Важные замечания

1. **Размер файла:** vulxml.xml ~500 MB, требует достаточно памяти
2. **Время импорта:** ~20-30 минут для полного импорта 82k записей
3. **Дисковое пространство:** ~2-3 GB в PostgreSQL после импорта
4. **Индексы:** Автоматически создаются миграцией для оптимизации
5. **Конфликты:** Используется upsert по `bdu_id` - безопасно запускать повторно

## 🐛 Troubleshooting

### Ошибка подключения к БД

```bash
# Проверить доступность БД
pg_isready -h 10.0.88.11 -p 5432 -U vuln_user

# Проверить права пользователя
psql -h 10.0.88.11 -U vuln_user -d vuln_db -c "SELECT current_user;"
```

### Ошибка парсинга XML

```bash
# Проверить целостность файла
unzip -t temp_bdu/vulxml.zip

# Проверить кодировку
file temp_bdu/export/vulxml.xml
```

### Медленный импорт

```bash
# Увеличить batch_size
python services/parsers/bdu_importer.py \
    --xml-file temp_bdu/export/vulxml.xml \
    --batch-size 5000

# Временно отключить индексы (для первого импорта)
# В БД:
DROP INDEX IF EXISTS idx_vulnerabilities_bdu_id;
-- ... импорт ...
-- Восстановить индексы после импорта
CREATE INDEX idx_vulnerabilities_bdu_id ON vulnerabilities(bdu_id);
```

## 📝 Логи

Логи сохраняются в stdout. Для сохранения в файл:

```bash
python services/parsers/bdu_importer.py \
    --xml-file temp_bdu/export/vulxml.xml \
    2>&1 | tee import.log
```

## 🔄 Обновление данных БДУ

БДУ ФСТЭК обновляется ежедневно. Рекомендуется автоматизировать:

```bash
#!/bin/bash
# Пример скрипта автообновления

cd /path/to/vulnerability_manager
rm -rf temp_bdu
mkdir temp_bdu
cd temp_bdu

# Скачать свежие данные
curl -L --insecure -o vulxml.zip "https://bdu.fstec.ru/files/documents/vulxml.zip"
unzip -q vulxml.zip

# Импортировать
cd ..
python services/parsers/bdu_importer.py \
    --xml-file temp_bdu/export/vulxml.xml \
    --batch-size 2000 \
    2>&1 | tee "logs/bdu_import_$(date +%Y%m%d).log"
```

Добавить в cron:
```bash
# Обновление БДУ каждый день в 3:00
0 3 * * * /path/to/update_bdu.sh
```

## 📞 Поддержка

При возникновении проблем:
1. Проверьте логи импорта
2. Убедитесь что миграция БД применена
3. Проверьте права доступа к БД
4. Используйте `--dry-run` для тестирования

