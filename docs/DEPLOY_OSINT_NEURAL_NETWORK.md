# 🚀 Деплой OSINT‑нейросети на ML VM

Цель: развернуть OSINT API сервис на ML VM (по аналогии с `docs/DEPLOY_ML_INTEGRATION.md`) и подключить его к backend.

## Вариант "под ключ" (рекомендуется)

Скрипт автоматически:
- установит Python/venv,
- поставит зависимости,
- создаст `/etc/osint-neural-network.env`,
- установит и запустит systemd сервис,
- проверит `/health`.

На ML VM выполните:

```bash
sudo bash /opt/vulnerability_manager/osint-neural-network/scripts/deploy_osint_service.sh
```

Параметры можно переопределить переменными окружения:

```bash
sudo OSINT_API_PORT=8010 OSINT_USE_LORA=false \
  OSINT_DB_HOST=10.0.88.11 OSINT_DB_USER=admin OSINT_DB_PASSWORD=123 \
  bash /opt/vulnerability_manager/osint-neural-network/scripts/deploy_osint_service.sh
```

## Ручной вариант (если нужен контроль)

## 1. Подготовка окружения (на ML VM)

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-venv python3-pip git
```

## 2. Копирование проекта

```bash
cd /opt
git clone <repo-url> vulnerability_manager
cd vulnerability_manager/osint-neural-network
```

## 3. Установка зависимостей

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 4. Переменные окружения

```bash
export OSINT_API_HOST=0.0.0.0
export OSINT_API_PORT=8010
export OSINT_MODEL_PATH=/opt/vulnerability_manager/osint-neural-network/models/final_model
export OSINT_BASE_MODEL=mistralai/Mistral-7B-v0.1
export OSINT_USE_LORA=false

# Если не используете config.py
export OSINT_DB_HOST=10.0.88.11
export OSINT_DB_PORT=5432
export OSINT_DB_NAME=vuln_db
export OSINT_DB_USER=admin
export OSINT_DB_PASSWORD=123
```

## 5. Запуск API вручную

```bash
source venv/bin/activate
python src/api_server.py
```

Проверка:
```bash
curl http://localhost:8010/health
```

## 6. Systemd сервис

Создайте файл `/etc/systemd/system/osint-neural-network.service`
или используйте шаблон из репозитория:

```bash
sudo cp /opt/vulnerability_manager/osint-neural-network/scripts/osint-neural-network.service \
  /etc/systemd/system/osint-neural-network.service
```

```ini
[Unit]
Description=OSINT Neural Network API
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/vulnerability_manager/osint-neural-network
Environment="OSINT_API_HOST=0.0.0.0"
Environment="OSINT_API_PORT=8010"
Environment="OSINT_MODEL_PATH=/opt/vulnerability_manager/osint-neural-network/models/final_model"
Environment="OSINT_BASE_MODEL=mistralai/Mistral-7B-v0.1"
Environment="OSINT_USE_LORA=false"
Environment="OSINT_DB_HOST=10.0.88.11"
Environment="OSINT_DB_PORT=5432"
Environment="OSINT_DB_NAME=vuln_db"
Environment="OSINT_DB_USER=admin"
Environment="OSINT_DB_PASSWORD=123"
ExecStart=/opt/vulnerability_manager/osint-neural-network/venv/bin/python /opt/vulnerability_manager/osint-neural-network/src/api_server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Запуск:
```bash
sudo systemctl daemon-reload
sudo systemctl enable osint-neural-network
sudo systemctl start osint-neural-network
sudo systemctl status osint-neural-network
```

## 7. Интеграция с backend

На Backend VM укажите адрес OSINT API:

```bash
export OSINT_API_URL=http://10.0.88.25:8010
```

Проверка:
```bash
curl http://10.0.88.20:5000/api/osint/health
```

## 8. Тестирование

```bash
curl -X POST http://10.0.88.20:5000/api/osint/query \
  -H "Content-Type: application/json" \
  -d '{"query":"Проведи OSINT разведку example.com","include_tools":true}'
```

```bash
curl -X POST http://10.0.88.20:5000/api/osint/query-bdu \
  -H "Content-Type: application/json" \
  -d '{"query":"Сформируй краткий отчет","vulnerability_id":1,"include_tools":true}'
```
