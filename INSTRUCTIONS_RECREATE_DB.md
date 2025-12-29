# Инструкция по пересозданию таблицы turn с NVD полями

## Способ 1: Выполнение SQL файла напрямую

1. Скопируйте файл на VM:
```bash
sshpass -p "123" scp recreate_database_simple.sql user@10.0.88.11:/tmp/
```

2. Подключитесь к контейнеру и выполните:
```bash
sshpass -p "123" ssh user@10.0.88.11
docker exec -it vulnerability_db psql -U admin -d vuln_db -f /tmp/recreate_database_simple.sql
```

## Способ 2: Выполнение команд вручную (пошагово)

1. Подключитесь к БД:
```bash
sshpass -p "123" ssh user@10.0.88.11
docker exec -it vulnerability_db psql -U admin -d vuln_db
```

2. Выполните команды из файла `recreate_database_simple.sql` по очереди:

```sql
-- Удалить таблицу
DROP TABLE IF EXISTS turn CASCADE;

-- Создать новую таблицу (скопируйте весь CREATE TABLE из файла)

-- Создать индексы (скопируйте все CREATE INDEX из файла)

-- Проверить результат
SELECT COUNT(*) FROM information_schema.columns WHERE table_name='turn';
SELECT column_name FROM information_schema.columns WHERE table_name='turn' AND column_name IN ('cvss_v2_vector', 'epss_score', 'cwe_ids', 'nvd_references', 'has_kev') ORDER BY column_name;
```

## Способ 3: Автоматическое выполнение (один скрипт)

```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager
sshpass -p "123" scp recreate_database_simple.sql user@10.0.88.11:/tmp/
sshpass -p "123" ssh user@10.0.88.11 "docker exec -i vulnerability_db psql -U admin -d vuln_db < /tmp/recreate_database_simple.sql"
```

## Проверка результата

После выполнения проверьте:
```bash
docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT COUNT(*) as total_columns FROM information_schema.columns WHERE table_name='turn';"
```

Должно быть **39 колонок** (13 старых + 26 новых NVD полей).

