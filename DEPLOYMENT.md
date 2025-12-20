# 🚀 Инструкция по развертыванию на 4 VM

## 📋 Обзор архитектуры

| VM | IP | Назначение | Сервисы |
|----|----|------------|---------|
| **Frontend** | `10.0.88.10` | UI + Nginx | Nginx, статические файлы |
| **Backend** | `10.0.88.20` | Flask API | Flask, Gunicorn |
| **Database** | `10.0.88.11` | PostgreSQL | PostgreSQL 15 |
| **Parsers** | `10.0.88.23` | Парсеры | NVD, RedHat, OSV парсеры |

---

## 🔧 Подготовка VM

### На всех VM:

```bash
# Обновление системы
sudo apt update && sudo apt upgrade -y

# Установка Docker и Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
sudo apt install docker-compose -y

# Перезагрузка для применения изменений
sudo reboot
```

---

## 📦 Развертывание Database (10.0.88.11)

### 1. Копирование файлов

```bash
# На VM 10.0.88.11
cd ~
mkdir -p vulnerability_manager/database
# Скопировать:
# - services/database/init.sql
# - services/database/docker-compose.yml
# - services/database/pg_hba.conf
```

### 2. Настройка PostgreSQL

```bash
cd ~/vulnerability_manager/database

# Создать директорию для данных
sudo mkdir -p /var/lib/postgresql/data
sudo chown -R 999:999 /var/lib/postgresql/data

# Запуск контейнера
docker-compose up -d

# Проверка
docker-compose ps
docker-compose logs -f
```

### 3. Настройка доступа

```bash
# Войти в контейнер
docker exec -it vulnerability_db psql -U admin -d vuln_db

# В psql:
ALTER SYSTEM SET listen_addresses = '*';
ALTER SYSTEM SET max_connections = 200;

# Применить pg_hba.conf
# (файл уже скопирован в контейнер через docker-compose)
```

### 4. Проверка подключения

```bash
# С другой VM (например, Backend)
psql -h 10.0.88.11 -U admin -d vuln_db
# Пароль: 123
```

---

## 🔌 Развертывание Backend (10.0.88.20)

### 1. Копирование файлов

```bash
# На VM 10.0.88.20
cd ~
mkdir -p vulnerability_manager/backend
# Скопировать:
# - services/backend/app.py
# - services/backend/config.py
# - services/backend/Dockerfile
# - services/backend/requirements.txt
# - models/ (все файлы)
# - services/ (кроме parsing_manager.py, nvd_integration_service.py, redhat_cve_importer.py)
# - utils/ (если есть)
```

### 2. Создание requirements.txt

```bash
cd ~/vulnerability_manager/backend
cat > requirements.txt << EOF
Flask==2.3.3
flask-cors==4.0.0
psycopg[binary]>=3.2.1
openpyxl==3.1.2
python-dotenv==1.0.0
requests>=2.31.0
gunicorn>=21.2.0
EOF
```

### 3. Запуск через Docker

```bash
# Сборка образа
docker build -t vulnerability-backend -f Dockerfile .

# Запуск контейнера
docker run -d \
  --name vulnerability-backend \
  --network host \
  -p 5000:5000 \
  vulnerability-backend

# Проверка
curl http://localhost:5000/api/health
```

### 4. Проверка API

```bash
# С Frontend VM
curl http://10.0.88.20:5000/api/health
```

---

## 🎨 Развертывание Frontend (10.0.88.10)

### 1. Копирование файлов

```bash
# На VM 10.0.88.10
cd ~
mkdir -p vulnerability_manager/frontend
# Скопировать:
# - services/frontend/nginx.conf
# - services/frontend/Dockerfile
# - templates/ (все HTML файлы)
# - static/ (CSS, JS, изображения)
```

### 2. Обновление шаблонов

В каждом HTML шаблоне заменить:
- `{{ url_for('...') }}` → статические пути или `/api/...`
- `localhost:5000` → `10.0.88.20:5000`
- Все ссылки на API должны использовать `/api/...` (Nginx проксирует)

### 3. Запуск через Docker

```bash
cd ~/vulnerability_manager/frontend

# Сборка образа
docker build -t vulnerability-frontend -f Dockerfile .

# Запуск контейнера
docker run -d \
  --name vulnerability-frontend \
  --network host \
  -p 80:80 \
  vulnerability-frontend

# Проверка
curl http://localhost
```

### 4. Проверка доступа

```bash
# С браузера или другой VM
curl http://10.0.88.10
```

---

## 🤖 Развертывание Parsers (10.0.88.23)

### 1. Копирование файлов

```bash
# На VM 10.0.88.23
cd ~
mkdir -p vulnerability_manager/parsers
# Скопировать:
# - services/parsers/config.py
# - services/parsers/run_parsers.py
# - services/parsers/Dockerfile
# - services/parsing_manager.py
# - services/nvd_integration_service.py
# - services/nvd_parser.py
# - services/nvd_scheduler.py
# - services/redhat_cve_importer.py
# - services/osv_parser.py
# - models/ (все файлы)
```

### 2. Создание requirements.txt

```bash
cd ~/vulnerability_manager/parsers
cat > requirements.txt << EOF
psycopg[binary]>=3.2.1
requests>=2.31.0
selenium>=4.15.0
beautifulsoup4>=4.12.0
schedule>=1.2.0
EOF
```

### 3. Запуск через Docker

```bash
# Сборка образа
docker build -t vulnerability-parsers -f Dockerfile .

# Запуск контейнера
docker run -d \
  --name vulnerability-parsers \
  --network host \
  --restart unless-stopped \
  vulnerability-parsers

# Проверка логов
docker logs -f vulnerability-parsers
```

---

## ✅ Проверка работы системы

### 1. Проверка Database

```bash
# На 10.0.88.11
docker exec -it vulnerability_db psql -U admin -d vuln_db -c "SELECT COUNT(*) FROM turn;"
```

### 2. Проверка Backend

```bash
# На 10.0.88.20
curl http://localhost:5000/api/health
curl http://localhost:5000/api/dashboard-stats
```

### 3. Проверка Frontend

```bash
# На 10.0.88.10
curl http://localhost
curl http://localhost/api/health  # Должен проксировать на Backend
```

### 4. Проверка Parsers

```bash
# На 10.0.88.23
docker logs vulnerability-parsers | tail -20
```

---

## 🔄 Обновление конфигурации

### Изменение IP адресов

Если нужно изменить IP:

1. **Backend** (`services/backend/config.py`):
   - `DATABASE_CONFIG.host = "10.0.88.11"`
   - `FRONTEND_URL = "http://10.0.88.10"`

2. **Parsers** (`services/parsers/config.py`):
   - `DATABASE_CONFIG.host = "10.0.88.11"`
   - `BACKEND_URL = "http://10.0.88.20:5000"`

3. **Frontend** (`services/frontend/nginx.conf`):
   - `upstream backend { server 10.0.88.20:5000; }`

4. **Frontend** (`services/frontend/base.html`):
   - `window.API_BASE_URL = 'http://10.0.88.20:5000';`

---

## 🐛 Устранение неполадок

### Backend не подключается к БД

```bash
# Проверить сеть
ping 10.0.88.11

# Проверить порт
telnet 10.0.88.11 5432

# Проверить логи
docker logs vulnerability-backend
```

### Frontend не проксирует API

```bash
# Проверить nginx.conf
docker exec vulnerability-frontend cat /etc/nginx/nginx.conf

# Перезапустить nginx
docker exec vulnerability-frontend nginx -s reload
```

### Parsers не работают

```bash
# Проверить логи
docker logs vulnerability-parsers

# Проверить подключение к БД
docker exec vulnerability-parsers python -c "from config import Config; print(Config.DATABASE_CONFIG.host)"
```

---

## 📝 Примечания

- Все пароли и ключи должны быть изменены в production
- Используйте HTTPS в production (настроить SSL сертификаты)
- Настройте firewall на каждой VM
- Регулярно делайте бэкапы БД
- Мониторьте логи всех сервисов

