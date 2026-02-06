# Unified Deployment Toolkit

Цель: единая система деплоя для всех микросервисов с безопасными,
повторяемыми и строгими правилами.

## Структура
- `deploy/env/strict.env` — общие строгие настройки (обязательно).
- `deploy/lib/common.sh` — общие функции (ssh/rsync/health).
- `deploy/bin/deploy_microservice.sh` — добавление/деплой нового микросервиса.
- `deploy/bin/redeploy_strict.sh` — строгий повторный деплой.
- `deploy/bin/deploy_all.sh` — последовательный деплой нескольких сервисов.
- `deploy/templates/systemd.service` — шаблон systemd unit.
- `deploy/services/*.env` — конфиг каждого микросервиса.

## Добавление нового микросервиса
1) Создайте файл `deploy/services/<service>.env` по примеру `osint-api.env`.
2) Запустите:
```
bash deploy/bin/deploy_microservice.sh <service>
```

## Legacy режим (связь со старыми скриптами)
Если микросервис уже покрыт legacy‑скриптами, укажите:
```
SERVICE_DEPLOY_MODE="legacy"
LEGACY_SCRIPT="scripts/deploy.sh"
LEGACY_ARGS="backend"
```

## Строгий повторный деплой
```
FORCE_REDEPLOY=YES bash deploy/bin/redeploy_strict.sh <service>
```

## One‑click деплой всех сервисов
```
bash deploy/bin/deploy_all.sh
```

## Backend ENV
Файл `.env` для backend создается через:
```
bash deploy/bin/set_backend_env.sh
```

## Требования
- `sshpass` установлен на локальной машине.
- Доступ по SSH к целевым хостам.
- `DEPLOY_GUARD=YES` в `deploy/env/strict.env`.

