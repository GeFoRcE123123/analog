# 📚 Полное руководство для второго разработчика

Комплексное руководство по проекту Vulnerability Manager: стек технологий, архитектура, деплой на сервер.

---

## 📋 Содержание

1. [Обзор проекта](#обзор-проекта)
2. [Технологический стек](#технологический-стек)
3. [Архитектура системы](#архитектура-системы)
4. [Структура проекта](#структура-проекта)
5. [Настройка окружения](#настройка-окружения)
6. [Деплой на сервер](#деплой-на-сервер)
7. [Работа с Git](#работа-с-git)
8. [Конфигурация](#конфигурация)
9. [Полезные команды](#полезные-команды)

---

## 🎯 Обзор проекта

**Vulnerability Manager** - система управления уязвимостями с распределенной архитектурой.

### Основные возможности:
- 📊 Управление базой данных уязвимостей (CVE)
- 🔍 Парсинг уязвимостей из различных источников (NVD, RedHat, OSV)
- 🤖 ИИ-анализ уязвимостей
- 📈 Аналитика и отчеты
- 👥 Управление операторами и назначениями

---

## 🛠️ Технологический стек

### Backend
- **Python 3.8+** - основной язык
- **Flask 2.3.3** - веб-фреймворк
- **Flask-CORS** - обработка CORS
- **Gunicorn** - WSGI сервер
- **psycopg[binary]** - драйвер PostgreSQL
- **requests** - HTTP клиент
- **beautifulsoup4** - парсинг HTML
- **selenium** - автоматизация браузера
- **paramiko** - SSH клиент

### Frontend
- **Nginx** - веб-сервер и reverse proxy
- **HTML/CSS/JavaScript** - клиентская часть
- **Bootstrap** - UI фреймворк (если используется)

### База данных
- **PostgreSQL** - основная БД
- **Legacy схема** - таблицы: `turn`, `cvelist`, `tagcve`, `users`, `operators`
- **Modern схема** - таблицы: `vulnerabilities`, `operators` (опционально)

### Инфраструктура
- **Docker** - контейнеризация
- **Docker Compose** - оркестрация контейнеров
- **SSH** - удаленное управление
- **Linux** - операционная система на VM

### ML Platform
- **Flask API** - сервер ML платформы
- **Python ML библиотеки** - анализ уязвимостей
- **SSH туннелирование** - доступ к ML сервису

---

## 🏗️ Архитектура системы

### Распределенная архитектура на 4 VM

```
┌─────────────────────────────────────────────────────────────┐
│                    FRONTEND (10.0.88.10)                     │
│                    Nginx + Static Files                       │
│                    Порт: 80                                   │
└───────────────────────────┬──────────────────────────────────┘
                            │ HTTP/HTTPS
                            │ /api/* → проксирует на Backend
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    BACKEND (10.0.88.20)                      │
│                    Flask API Server                           │
│                    Порт: 5000                                │
│                                                               │
│  Endpoints:                                                   │
│    /api/dashboard-stats                                       │
│    /api/vulnerabilities                                       │
│    /api/parsers/run-all                                       │
│    /api/ai/* (ИИ интеграция)                                 │
└───────────────────────────┬──────────────────────────────────┘
                            │ PostgreSQL
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    DATABASE (10.0.88.11)                    │
│                    PostgreSQL                                │
│                    Порт: 5432                                │
│                                                               │
│  Tables: turn, cvelist, tagcve, users, operators           │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    PARSERS (10.0.88.23)                     │
│                    Асинхронные парсеры                        │
│                                                               │
│  Парсеры:                                                    │
│    - NVD (National Vulnerability Database)                  │
│    - RedHat CVE                                              │
│    - OSV (Open Source Vulnerabilities)                       │
└───────────────────────────┬──────────────────────────────────┘
                            │ PostgreSQL
                            ▼
                    [DATABASE (10.0.88.11)]

┌─────────────────────────────────────────────────────────────┐
│              ML PLATFORM (10.0.88.25)                       │
│              Flask API для ИИ-анализа                        │
│              Порт: 8000                                      │
│              SSH: k8s-worker@10.0.88.25                    │
└─────────────────────────────────────────────────────────────┘
```

### Сетевые подключения

| От | К | Протокол | Порт | Назначение |
|---|---|---------|------|------------|
| Frontend | Backend | HTTP | 5000 | API запросы |
| Backend | Database | PostgreSQL | 5432 | Запросы к БД |
| Parsers | Database | PostgreSQL | 5432 | Сохранение данных |
| Backend | ML Platform | HTTP | 8000 | ИИ-анализ |
| Backend | ML Platform | SSH | 22 | Проверка доступности |

---

## 📁 Структура проекта

```
vulnerability_manager/
├── services/              # Основные сервисы
│   ├── backend/          # Backend сервис
│   │   ├── app.py       # Flask приложение (только API)
│   │   ├── config.py    # Конфигурация
│   │   ├── Dockerfile   # Docker образ
│   │   └── docker-compose.yml
│   ├── frontend/        # Frontend сервис
│   │   ├── nginx.conf   # Конфигурация Nginx
│   │   ├── Dockerfile
│   │   └── docker-compose.yml
│   ├── database/        # Database сервис
│   │   ├── init.sql     # Инициализация БД
│   │   ├── pg_hba.conf  # Настройки доступа
│   │   └── docker-compose.yml
│   ├── parsers/         # Parsers сервис
│   │   ├── run_parsers.py
│   │   ├── Dockerfile
│   │   └── docker-compose.yml
│   └── [различные сервисы]
│       ├── vulnerability_service.py
│       ├── operator_service.py
│       ├── parsing_manager.py
│       ├── nvd_integration_service.py
│       └── ai_integration_service.py
├── models/               # Модели данных
│   ├── database.py      # DatabaseManager
│   ├── entities.py      # Сущности
│   └── repositories.py  # Репозитории
├── templates/            # HTML шаблоны
│   ├── base.html
│   ├── dashboard.html
│   └── ...
├── static/               # Статические файлы
│   ├── css/
│   └── js/
├── scripts/              # Скрипты развертывания
│   ├── deploy.sh        # Основной скрипт деплоя
│   └── ...
├── config.py            # Главная конфигурация
├── requirements.txt     # Python зависимости
└── docs/                # Документация
```

---

## ⚙️ Настройка окружения

### 1. Клонирование репозитория

```bash
git clone https://github.com/GeFoRcE123123/analog.git vulnerability_manager
cd vulnerability_manager
```

### 2. Настройка Python окружения

```bash
# Создать виртуальное окружение
python3 -m venv venv
source venv/bin/activate  # На Windows: venv\Scripts\activate

# Установить зависимости
pip install -r requirements.txt
```

### 3. Настройка SSH

```bash
# Запустить скрипт настройки SSH
chmod +x scripts/setup_ssh.sh
./scripts/setup_ssh.sh --with-keys
```

Подробнее: [SSH_SETUP.md](./SSH_SETUP.md)

### 4. Настройка Git

```bash
git config user.name "Ваше Имя"
git config user.email "your.email@example.com"
```

---

## 🚀 Деплой на сервер

### Важно: Деплой напрямую на сервер (без GitHub)

Вы можете деплоить изменения напрямую на серверы через SSH, минуя GitHub.

### Способ 1: Автоматический деплой (рекомендуется)

```bash
# Из корня проекта
./scripts/deploy.sh all

# Или деплой конкретного сервиса
./scripts/deploy.sh backend
./scripts/deploy.sh frontend
./scripts/deploy.sh database
./scripts/deploy.sh parsers
```

**Что делает скрипт:**
1. ✅ Копирует файлы на соответствующие VM через SSH
2. ✅ Останавливает старые контейнеры
3. ✅ Собирает новые Docker образы
4. ✅ Запускает контейнеры

### Способ 2: Ручной деплой через SSH

#### Деплой Backend (10.0.88.20)

```bash
# 1. Подключиться к VM
ssh backend-vm  # или ssh user@10.0.88.20

# 2. Перейти в директорию проекта
cd ~/vulnerability_manager/backend

# 3. Скопировать файлы с локальной машины (из другого терминала)
# На вашей локальной машине:
scp -r services/backend/* backend-vm:~/vulnerability_manager/backend/
scp -r models/* backend-vm:~/vulnerability_manager/backend/models/
scp config.py backend-vm:~/vulnerability_manager/backend/

# 4. На VM: Перезапустить контейнер
cd ~/vulnerability_manager/backend
docker compose down
docker compose up -d --build

# 5. Проверить логи
docker logs vulnerability-backend --tail 50 -f
```

#### Деплой Frontend (10.0.88.10)

```bash
# 1. Скопировать файлы
scp -r services/frontend/* frontend-vm:~/vulnerability_manager/frontend/
scp -r templates/* frontend-vm:~/vulnerability_manager/frontend/templates/
scp -r static/* frontend-vm:~/vulnerability_manager/frontend/static/

# 2. На VM: Перезапустить
ssh frontend-vm
cd ~/vulnerability_manager/frontend
docker compose down
docker compose up -d --build
```

#### Деплой Parsers (10.0.88.23)

```bash
# 1. Скопировать файлы
scp -r services/parsers/* parsers-vm:~/vulnerability_manager/parsers/
scp -r models/* parsers-vm:~/vulnerability_manager/parsers/models/
scp config.py parsers-vm:~/vulnerability_manager/parsers/

# 2. На VM: Перезапустить
ssh parsers-vm
cd ~/vulnerability_manager/parsers
docker compose down
docker compose up -d --build
```

### Способ 3: Деплой через rsync (синхронизация)

```bash
# Синхронизация Backend
rsync -avz --exclude 'venv' --exclude '__pycache__' \
  services/backend/ backend-vm:~/vulnerability_manager/backend/

# На VM перезапустить
ssh backend-vm "cd ~/vulnerability_manager/backend && docker compose restart"
```

---

## 🔄 Работа с Git

### Если работаете в одной ветке (main-new)

**Утром:**
```bash
git checkout main-new
git pull origin main-new
```

**Перед каждым коммитом:**
```bash
git pull origin main-new  # Получить изменения
git add .
git commit -m "Описание изменений"
git push origin main-new  # Отправить на GitHub
```

**После коммита - деплой на сервер:**
```bash
# Деплой изменений на сервер
./scripts/deploy.sh all
```

Подробнее: [WORK_IN_SAME_BRANCH.md](./WORK_IN_SAME_BRANCH.md)

### Если работаете в отдельных ветках

**Создание ветки:**
```bash
git checkout -b feature/your-feature-name
```

**Деплой из ветки на сервер:**
```bash
# Деплой работает независимо от ветки
# Просто выполните:
./scripts/deploy.sh all
```

---

## ⚙️ Конфигурация

### Основной файл конфигурации: `config.py`

```python
# Database
DATABASE_CONFIG.host = "10.0.88.11"
DATABASE_CONFIG.port = 5432
DATABASE_CONFIG.database = "vuln_db"
DATABASE_CONFIG.username = "admin"
DATABASE_CONFIG.password = "123"

# Backend
BACKEND_HOST = "0.0.0.0"
BACKEND_PORT = 5000
BACKEND_URL = "http://10.0.88.20:5000"

# Frontend
FRONTEND_URL = "http://10.0.88.10"

# ML Platform
ML_PLATFORM_VM_IP = "10.0.88.25"
ML_PLATFORM_API_PORT = 8000
ML_PLATFORM_SSH_USER = "k8s-worker"
ML_PLATFORM_SSH_PASSWORD = "k8s-worker"
```

### IP адреса VM

| Сервис | IP | Пользователь | Пароль |
|--------|----|--------------|--------|
| Database | 10.0.88.11 | user | 123 |
| Frontend | 10.0.88.10 | user | 123 |
| Backend | 10.0.88.20 | user | 123 |
| Parsers | 10.0.88.23 | user | 123 |
| ML Platform | 10.0.88.25 | k8s-worker | k8s-worker |

---

## 🛠️ Полезные команды

### Проверка статуса сервисов

```bash
# Database
ssh database-vm "docker ps | grep vulnerability-db"

# Backend
curl http://10.0.88.20:5000/api/health
ssh backend-vm "docker logs vulnerability-backend --tail 50"

# Frontend
curl http://10.0.88.10
ssh frontend-vm "docker ps | grep vulnerability-frontend"

# Parsers
ssh parsers-vm "docker logs vulnerability-parsers --tail 50"
```

### Перезапуск сервисов

```bash
# Backend
ssh backend-vm "cd ~/vulnerability_manager/backend && docker compose restart"

# Frontend
ssh frontend-vm "cd ~/vulnerability_manager/frontend && docker compose restart"

# Parsers
ssh parsers-vm "cd ~/vulnerability_manager/parsers && docker compose restart"
```

### Просмотр логов

```bash
# Backend логи
ssh backend-vm "docker logs vulnerability-backend -f"

# Parsers логи
ssh parsers-vm "docker logs vulnerability-parsers -f"

# Database логи
ssh database-vm "docker logs vulnerability-db -f"
```

### Работа с базой данных

```bash
# Подключение к БД
ssh database-vm "docker exec -it vulnerability-db psql -U admin -d vuln_db"

# Выполнение SQL
ssh database-vm "docker exec vulnerability-db psql -U admin -d vuln_db -c 'SELECT COUNT(*) FROM turn;'"
```

### Копирование файлов на сервер

```bash
# Копирование одного файла
scp config.py backend-vm:~/vulnerability_manager/backend/

# Копирование директории
scp -r services/backend/* backend-vm:~/vulnerability_manager/backend/

# С использованием rsync (синхронизация)
rsync -avz services/backend/ backend-vm:~/vulnerability_manager/backend/
```

---

## 🔍 Отладка

### Проблема: Backend не подключается к БД

```bash
# Проверить сеть
ping 10.0.88.11

# Проверить порт
telnet 10.0.88.11 5432

# Проверить логи
ssh backend-vm "docker logs vulnerability-backend"
```

### Проблема: Frontend не проксирует API

```bash
# Проверить конфигурацию Nginx
ssh frontend-vm "docker exec vulnerability-frontend cat /etc/nginx/nginx.conf"

# Перезапустить Nginx
ssh frontend-vm "docker exec vulnerability-frontend nginx -s reload"
```

### Проблема: Parsers не работают

```bash
# Проверить логи
ssh parsers-vm "docker logs vulnerability-parsers"

# Проверить подключение к БД
ssh parsers-vm "docker exec vulnerability-parsers python -c 'from config import Config; print(Config.DATABASE_CONFIG.host)'"
```

---

## 📚 Дополнительные ресурсы

### Документация по разработке
- [DEVELOPER_SETUP.md](./DEVELOPER_SETUP.md) - Настройка окружения
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Правила работы
- [GIT_WORKFLOW.md](./GIT_WORKFLOW.md) - Git workflow

### Документация по деплою
- [README_DEPLOYMENT.md](./README_DEPLOYMENT.md) - Развертывание
- [SERVICES_STRUCTURE.md](./SERVICES_STRUCTURE.md) - Структура сервисов
- [QUICK_DEPLOY.md](./QUICK_DEPLOY.md) - Быстрый деплой

### Документация по синхронизации
- [WORK_IN_SAME_BRANCH.md](./WORK_IN_SAME_BRANCH.md) - Работа в одной ветке
- [GITHUB_SYNC.md](./GITHUB_SYNC.md) - Синхронизация с GitHub
- [SSH_SETUP.md](./SSH_SETUP.md) - Настройка SSH

---

## ✅ Чеклист для начала работы

- [ ] Репозиторий склонирован
- [ ] Python окружение настроено
- [ ] Зависимости установлены
- [ ] SSH подключения настроены
- [ ] Git настроен
- [ ] Прочитана документация
- [ ] Понимание архитектуры системы
- [ ] Доступ к VM проверен

---

## 🎯 Типичный workflow

1. **Получить изменения** (если работаете в одной ветке):
   ```bash
   git pull origin main-new
   ```

2. **Разработать изменения**:
   - Редактировать код
   - Тестировать локально

3. **Закоммитить** (опционально, если используете Git):
   ```bash
   git add .
   git commit -m "Описание"
   git push origin main-new
   ```

4. **Деплой на сервер**:
   ```bash
   ./scripts/deploy.sh all
   # или конкретный сервис
   ./scripts/deploy.sh backend
   ```

5. **Проверить работу**:
   ```bash
   curl http://10.0.88.20:5000/api/health
   curl http://10.0.88.10
   ```

---

**Успешной разработки! 🚀**

