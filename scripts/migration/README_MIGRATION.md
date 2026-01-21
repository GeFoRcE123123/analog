# Миграция БДУ ФСТЭК - Руководство

## 🎯 Цель миграции

Добавление структурированных полей для поддержки полного паспорта уязвимости БДУ ФСТЭК.

---

## 📋 Что будет добавлено

### Новые поля (17 шт):
- **BDU ID** - идентификатор БДУ
- **Vendor/Product** - информация о ПО
- **Exploit info** - данные об эксплойтах
- **Remediation** - информация об устранении
- **Dates** - даты выявления и устранения

### Индексы (10 шт):
- Для быстрого поиска по вендору, эксплойтам, датам

---

## 🚀 Быстрый старт

### Шаг 1: Резервная копия БД

```bash
# ОБЯЗАТЕЛЬНО! Создать бэкап перед миграцией
pg_dump -U your_user -d vulnerability_db > backup_before_bdu_migration_$(date +%Y%m%d).sql
```

### Шаг 2: Применить миграцию

```bash
# Вариант 1: Напрямую через psql
psql -U your_user -d vulnerability_db -f scripts/migration/add_bdu_fields.sql

# Вариант 2: Через Python скрипт (если есть)
python scripts/migration/apply_migration.py add_bdu_fields
```

### Шаг 3: Обратное заполнение данных

```bash
# Тестовый прогон (без сохранения)
python scripts/migration/backfill_bdu_data.py --dry-run --limit 50 --verbose

# Полное выполнение
python scripts/migration/backfill_bdu_data.py
```

### Шаг 4: Проверка

```bash
# Проверить что поля добавлены
psql -U your_user -d vulnerability_db -c "\d vulnerabilities"

# Статистика по заполненности
psql -U your_user -d vulnerability_db -f scripts/migration/check_bdu_stats.sql
```

---

## 📊 Проверка результатов

После миграции выполните:

```sql
-- Проверка структуры таблицы
\d vulnerabilities

-- Статистика по БДУ полям
SELECT 
    COUNT(*) as total_vulnerabilities,
    COUNT(bdu_id) as with_bdu_id,
    COUNT(vendor) as with_vendor,
    COUNT(CASE WHEN exploit_available = TRUE THEN 1 END) as with_exploit,
    COUNT(date_discovered) as with_discovery_date
FROM vulnerabilities;

-- Топ-10 вендоров
SELECT vendor, COUNT(*) as count
FROM vulnerabilities
WHERE vendor IS NOT NULL
GROUP BY vendor
ORDER BY count DESC
LIMIT 10;
```

---

## ⚠️ Откат миграции

Если что-то пошло не так:

```bash
# Восстановить из бэкапа
psql -U your_user -d vulnerability_db < backup_before_bdu_migration_YYYYMMDD.sql

# Или использовать секцию отката в SQL файле
# (раскомментировать секцию ROLLBACK в add_bdu_fields.sql)
```

---

## 📝 Детальные инструкции

### Для разработчиков

1. **Перед миграцией:**
   - Остановить все сервисы
   - Сделать бэкап БД
   - Проверить версию PostgreSQL (>= 12)

2. **После миграции:**
   - Обновить модели данных в `models/entities.py`
   - Обновить API эндпоинты в `app.py`
   - Обновить UI в `templates/vulnerabilities_list.html`

3. **Тестирование:**
   - Запустить unit-тесты
   - Проверить работу парсеров
   - Проверить UI

### Для администраторов БД

```sql
-- Проверка размера таблицы до миграции
SELECT pg_size_pretty(pg_total_relation_size('vulnerabilities'));

-- Проверка активных соединений
SELECT count(*) FROM pg_stat_activity WHERE datname = 'vulnerability_db';

-- Анализ производительности после миграции
ANALYZE vulnerabilities;

-- Проверка индексов
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
WHERE tablename = 'vulnerabilities'
ORDER BY idx_scan DESC;
```

---

## 🐛 Решение проблем

### Проблема: Миграция не применяется

```bash
# Проверить права доступа
psql -U your_user -d vulnerability_db -c "SELECT current_user, session_user;"

# Проверить наличие таблицы
psql -U your_user -d vulnerability_db -c "\dt vulnerabilities"
```

### Проблема: Ошибка при создании индекса

```bash
# Удалить существующий индекс
DROP INDEX IF EXISTS idx_vulnerabilities_bdu_id_unique;

# Создать заново
CREATE UNIQUE INDEX idx_vulnerabilities_bdu_id_unique 
ON vulnerabilities(bdu_id) WHERE bdu_id IS NOT NULL;
```

### Проблема: Backfill скрипт не находит данные

```bash
# Проверить формат данных в description
psql -U your_user -d vulnerability_db -c "
SELECT id, title, substring(description, 1, 200) 
FROM vulnerabilities 
WHERE description LIKE '%BDU%' 
LIMIT 5;"

# Запустить с verbose для отладки
python scripts/migration/backfill_bdu_data.py --dry-run --verbose --limit 10
```

---

## 📈 Мониторинг миграции

### Во время выполнения:

```sql
-- Прогресс миграции (в другой сессии)
SELECT 
    now() - pg_stat_activity.xact_start AS duration,
    query
FROM pg_stat_activity
WHERE state = 'active' AND query LIKE '%vulnerabilities%';
```

### После завершения:

```bash
# Логи PostgreSQL
tail -f /var/log/postgresql/postgresql-*.log

# Размер таблицы после миграции
psql -U your_user -d vulnerability_db -c "
SELECT pg_size_pretty(pg_total_relation_size('vulnerabilities'));"
```

---

## ✅ Чек-лист миграции

- [ ] 📦 Создан бэкап базы данных
- [ ] 🛑 Остановлены все сервисы приложения
- [ ] 🔍 Проверена версия PostgreSQL
- [ ] 📝 Ознакомлен с содержимым миграции
- [ ] ▶️  Запущена миграция `add_bdu_fields.sql`
- [ ] ✅ Миграция завершилась без ошибок
- [ ] 🔄 Запущен backfill скрипт (тестовый прогон)
- [ ] 💾 Запущен backfill скрипт (реальное выполнение)
- [ ] 📊 Проверены статистики заполнения
- [ ] 🔧 Обновлены модели данных в коде
- [ ] 🎨 Обновлен UI для отображения новых полей
- [ ] 🧪 Выполнены тесты
- [ ] ✅ Запущены сервисы приложения
- [ ] 👀 Проверена работа системы

---

## 📚 Связанные документы

- **Полный анализ:** `docs/BDU_STRUCTURE_ANALYSIS_2026.md`
- **Краткое резюме:** `docs/BDU_QUICK_SUMMARY.md`
- **SQL миграция:** `scripts/migration/add_bdu_fields.sql`
- **Backfill скрипт:** `scripts/migration/backfill_bdu_data.py`

---

## 🆘 Помощь

При возникновении проблем:
1. Проверьте логи PostgreSQL
2. Проверьте логи приложения
3. Откатите миграцию из бэкапа
4. Свяжитесь с командой разработки

---

**Дата:** 22 января 2026  
**Версия:** 1.0  
**Статус:** Готово к применению

