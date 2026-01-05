# Руководство по миграции таблицы turn для системного администратора

## Цель миграции
Добавить новые поля NVD в таблицу `turn` без изменения структуры БД и ссылок в проекте.

## Важно
- **Не удаляйте всю БД** - только таблицу `turn`
- Остальные таблицы остаются без изменений
- Все ссылки в проекте продолжают работать (название таблицы `turn` не меняется)
- После миграции таблица будет содержать 39 колонок (вместо 13)

---

## Шаг 1: Подключение к VM с базой данных

```bash
sshpass -p "123" ssh user@10.0.88.11
```

Если sshpass не установлен, используйте обычный ssh:
```bash
ssh user@10.0.88.11
# Пароль: 123
```

---

## Шаг 2: Проверка текущего состояния

Проверьте, сколько колонок сейчас в таблице `turn`:

```bash
docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT COUNT(*) as total_columns FROM information_schema.columns WHERE table_name='turn';"
```

Ожидаемый результат: **13 колонок**

---

## Шаг 3: Копирование SQL файла миграции

### Вариант A: Если файл уже на VM (в /tmp/recreate.sql)
Пропустите этот шаг и переходите к Шагу 4.

### Вариант B: Скопировать файл с вашего компьютера

На вашем компьютере (не на VM) выполните:
```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager
sshpass -p "123" scp recreate_database_simple.sql user@10.0.88.11:/tmp/recreate.sql
```

---

## Шаг 4: Копирование файла в Docker контейнер

На VM выполните:
```bash
docker cp /tmp/recreate.sql vulnerability_db:/tmp/recreate.sql
```

Проверьте, что файл скопирован:
```bash
docker exec vulnerability_db ls -la /tmp/recreate.sql
```

---

## Шаг 5: Выполнение миграции

### Способ 1: Через psql интерактивно (РЕКОМЕНДУЕТСЯ)

1. Войдите в psql:
```bash
docker exec -it vulnerability_db psql -U admin -d vuln_db
```

2. Выполните SQL файл:
```sql
\i /tmp/recreate.sql
```

3. Дождитесь завершения выполнения (должны увидеть сообщение "Таблица создана! Всего колонок: 39")

4. Выйдите из psql:
```sql
\q
```

### Способ 2: Напрямую через docker exec (альтернатива)

```bash
docker exec vulnerability_db psql -U admin -d vuln_db -f /tmp/recreate.sql
```

---

## Шаг 6: Проверка результата миграции

### Проверка 1: Количество колонок
```bash
docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT COUNT(*) as total_columns FROM information_schema.columns WHERE table_name='turn';"
```

**Ожидаемый результат: 39 колонок**

### Проверка 2: Наличие новых NVD полей
```bash
docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT column_name FROM information_schema.columns WHERE table_name='turn' AND column_name IN ('cvss_v2_vector', 'cvss_v3_vector', 'epss_score', 'cwe_ids', 'nvd_references', 'has_kev', 'source_identifier', 'nvd_published', 'nvd_metrics', 'cve_json5_data') ORDER BY column_name;"
```

**Ожидаемый результат: список из 10 новых полей**

### Проверка 3: Все колонки таблицы
```bash
docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT column_name, data_type FROM information_schema.columns WHERE table_name='turn' ORDER BY ordinal_position;"
```

---

## Шаг 7: Проверка работы приложения

После миграции проверьте, что приложение работает:

1. Проверьте подключение к БД из приложения
2. Убедитесь, что список уязвимостей отображается
3. Проверьте, что новые уязвимости сохраняются корректно

---

## Что делается в миграции

SQL файл `recreate_database_simple.sql` выполняет:

1. **DROP TABLE IF EXISTS turn CASCADE;** - удаляет старую таблицу (данные будут потеряны!)
2. **CREATE TABLE turn (...)** - создает новую таблицу с полями:
   - Все старые поля (id, source, link, cve, и т.д.)
   - Новые NVD поля: cvss_v2_vector, cvss_v3_vector, epss_score, cwe_ids, nvd_references, has_kev, и другие
3. **CREATE INDEX ...** - создает индексы для оптимизации запросов

---

## Если что-то пошло не так

### Проблема: Таблица не создалась
```bash
# Проверьте ошибки
docker logs vulnerability_db | tail -50

# Попробуйте выполнить команды вручную через psql
docker exec -it vulnerability_db psql -U admin -d vuln_db
```

### Проблема: Ошибка "relation already exists"
Таблица уже существует. Сначала удалите её:
```sql
DROP TABLE IF EXISTS turn CASCADE;
```

### Проблема: Ошибка прав доступа
Убедитесь, что используете правильного пользователя:
```bash
docker exec vulnerability_db psql -U admin -d vuln_db
```

---

## Важные замечания

1. **Данные будут потеряны!** - таблица `turn` будет удалена и пересоздана. Если нужно сохранить данные, сделайте бэкап:
   ```bash
   docker exec vulnerability_db pg_dump -U admin -d vuln_db -t turn > /tmp/turn_backup.sql
   ```

2. **Остальные таблицы не затрагиваются** - мигрируется только таблица `turn`

3. **Название таблицы не меняется** - все ссылки в коде проекта продолжают работать

4. **Индексы создаются автоматически** - для оптимизации запросов

---

## Быстрая справка по командам

```bash
# Подключение к VM
sshpass -p "123" ssh user@10.0.88.11

# Копирование файла на VM
sshpass -p "123" scp recreate_database_simple.sql user@10.0.88.11:/tmp/

# Копирование в контейнер
docker cp /tmp/recreate.sql vulnerability_db:/tmp/recreate.sql

# Выполнение миграции
docker exec -it vulnerability_db psql -U admin -d vuln_db
\i /tmp/recreate.sql
\q

# Проверка
docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='turn';"
```

---

## Контакты и поддержка

Если возникли проблемы:
1. Проверьте логи PostgreSQL: `docker logs vulnerability_db`
2. Проверьте, что контейнер запущен: `docker ps | grep vulnerability_db`
3. Убедитесь, что файл SQL существует: `docker exec vulnerability_db ls -la /tmp/recreate.sql`

