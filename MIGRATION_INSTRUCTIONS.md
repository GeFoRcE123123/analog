# Инструкция по применению миграции NVD полей

## Проблема
Миграция не применяется через SSH из-за проблем с соединением. Нужно выполнить вручную на VM.

## Способ 1: Выполнение скрипта на VM (рекомендуется)

1. Скопируйте файл `run_migration_on_vm.sh` на VM:
```bash
sshpass -p "123" scp run_migration_on_vm.sh user@10.0.88.11:/tmp/
```

2. Подключитесь к VM:
```bash
sshpass -p "123" ssh user@10.0.88.11
```

3. Выполните скрипт:
```bash
chmod +x /tmp/run_migration_on_vm.sh
/tmp/run_migration_on_vm.sh
```

## Способ 2: Прямое выполнение SQL команд

Подключитесь к VM и выполните:
```bash
docker exec -it vulnerability_db psql -U admin -d vuln_db
```

Затем выполните SQL команды из файла `services/database/migrate_add_nvd_fields.sql`

## Способ 3: Выполнение через одну команду (из локальной машины)

```bash
sshpass -p "123" ssh user@10.0.88.11 "docker exec vulnerability_db psql -U admin -d vuln_db -f /tmp/migration.sql"
```

(Предварительно скопируйте migration.sql на VM)

## Проверка результата

После выполнения миграции проверьте:
```bash
docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT column_name FROM information_schema.columns WHERE table_name='turn' AND column_name IN ('cvss_v2_vector', 'cvss_v3_vector', 'epss_score', 'cwe_ids', 'nvd_references', 'has_kev') ORDER BY column_name;"
```

Должно вернуть список из 6+ колонок.

