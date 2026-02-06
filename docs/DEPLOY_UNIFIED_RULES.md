# Unified Deployment Rules (All Agents)

Эти правила обязательны для всех агентов и сценариев деплоя.

## Единственная точка входа
Используйте только:

```
deploy/bin/deploy_all.sh
deploy/bin/deploy_microservice.sh <service>
```

Все остальные `deploy*.sh` считаются legacy и вызываются только
через legacy‑режим из `deploy/services/*.env`.

## Строгие настройки деплоя
Настройки берутся из:

```
deploy/env/strict.env
```

Требования:
- `DEPLOY_GUARD=YES` обязателен.
- `SSH_OPTIONS` должен быть задан.
- IP/учетные данные берутся только из `deploy_strict.env`.

## Цели деплоя
```
deploy/bin/deploy_all.sh
deploy/bin/deploy_microservice.sh frontend|backend|database|parsers|osint-api
```

## Запрещено
- Прямой запуск legacy‑скриптов.
- Изменение IP/учетных данных в теле скриптов.
- Деплой без проверки доступности хостов.
