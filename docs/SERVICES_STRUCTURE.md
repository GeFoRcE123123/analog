# 📁 Структура файлов для развертывания на 4 VM

## 🎯 Распределение файлов по сервисам

### 📦 Frontend (10.0.88.10)

```
~/vulnerability_manager/frontend/
├── Dockerfile
├── docker-compose.yml
├── nginx.conf
├── templates/
│   ├── base.html (обновленный с API_BASE_URL)
│   ├── dashboard.html
│   ├── vulnerabilities_list.html
│   ├── operators.html
│   ├── performance_analytics.html
│   ├── parsers.html
│   └── ... (все остальные HTML)
└── static/
    ├── css/
    └── js/
```

**Важно**: В `base.html` все `url_for()` заменены на статические пути, API вызовы идут на `http://10.0.88.20:5000`

---

### 🔌 Backend (10.0.88.20)

```
~/vulnerability_manager/backend/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── app.py (только API маршруты, без render_template)
├── config.py (с IP 10.0.88.11 для БД)
├── models/
│   ├── __init__.py
│   ├── database.py
│   ├── entities.py
│   ├── postgres_repositories.py
│   ├── legacy_repositories.py
│   ├── repositories.py
│   └── repository_factory.py
├── services/
│   ├── __init__.py
│   ├── vulnerability_service.py
│   ├── operator_service.py
│   ├── export_service.py
│   ├── assignment_manager.py
│   ├── data_manager.py
│   ├── analytics_service.py
│   └── auth_service.py
└── utils/
    └── decorators.py (если есть)
```

**Исключено**: 
- ❌ `services/parsing_manager.py`
- ❌ `services/nvd_integration_service.py`
- ❌ `services/nvd_parser.py`
- ❌ `services/redhat_cve_importer.py`
- ❌ `templates/`
- ❌ `static/`

---

### 🗄️ Database (10.0.88.11)

```
~/vulnerability_manager/database/
├── docker-compose.yml
├── init.sql
└── pg_hba.conf
```

**Только**: PostgreSQL конфигурация и миграции

---

### 🤖 Parsers (10.0.88.23)

```
~/vulnerability_manager/parsers/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── config.py (с IP 10.0.88.11 для БД)
├── run_parsers.py
├── models/
│   ├── __init__.py
│   ├── database.py
│   ├── entities.py
│   ├── postgres_repositories.py
│   ├── legacy_repositories.py
│   └── ... (все модели)
└── services/
    ├── __init__.py
    ├── parsing_manager.py
    ├── nvd_integration_service.py
    ├── nvd_parser.py
    ├── nvd_scheduler.py
    ├── redhat_cve_importer.py
    ├── osv_parser.py
    └── fast_osv_parser.py
```

**Исключено**:
- ❌ `app.py`
- ❌ `templates/`
- ❌ `static/`
- ❌ `services/vulnerability_service.py` (используется только для чтения)
- ❌ `services/operator_service.py` (используется только для чтения)

---

## 🔄 Процесс копирования файлов

### Автоматический (через deploy.sh):

```bash
./deploy.sh all
```

### Ручной:

#### 1. Database
```bash
scp -r services/database/* user@10.0.88.11:~/vulnerability_manager/database/
```

#### 2. Backend
```bash
# Создать структуру
ssh user@10.0.88.20 "mkdir -p ~/vulnerability_manager/backend/{models,services,utils}"

# Копировать файлы
scp -r services/backend/* user@10.0.88.20:~/vulnerability_manager/backend/
scp -r models/* user@10.0.88.20:~/vulnerability_manager/backend/models/
scp -r services/vulnerability_service.py services/operator_service.py services/export_service.py services/assignment_manager.py services/data_manager.py services/analytics_service.py services/auth_service.py user@10.0.88.20:~/vulnerability_manager/backend/services/
```

#### 3. Frontend
```bash
scp -r services/frontend/* user@10.0.88.10:~/vulnerability_manager/frontend/
scp -r templates/* user@10.0.88.10:~/vulnerability_manager/frontend/templates/
scp -r static/* user@10.0.88.10:~/vulnerability_manager/frontend/static/
```

#### 4. Parsers
```bash
# Создать структуру
ssh user@10.0.88.23 "mkdir -p ~/vulnerability_manager/parsers/{models,services}"

# Копировать файлы
scp -r services/parsers/* user@10.0.88.23:~/vulnerability_manager/parsers/
scp -r models/* user@10.0.88.23:~/vulnerability_manager/parsers/models/
scp -r services/parsing_manager.py services/nvd_integration_service.py services/nvd_parser.py services/nvd_scheduler.py services/redhat_cve_importer.py services/osv_parser.py user@10.0.88.23:~/vulnerability_manager/parsers/services/
```

---

## ✅ Чеклист развертывания

- [ ] Database: `init.sql` создает все таблицы
- [ ] Database: `pg_hba.conf` разрешает подключения с 10.0.88.0/24
- [ ] Backend: `config.py` указывает на `10.0.88.11`
- [ ] Backend: `app.py` содержит только API маршруты
- [ ] Frontend: `nginx.conf` проксирует `/api/*` на `10.0.88.20:5000`
- [ ] Frontend: `base.html` использует `API_BASE_URL = 'http://10.0.88.20:5000'`
- [ ] Parsers: `config.py` указывает на `10.0.88.11`
- [ ] Parsers: `run_parsers.py` запускает все парсеры
- [ ] Все Dockerfile собраны и протестированы
- [ ] Все docker-compose.yml настроены

---

## 🔍 Проверка после развертывания

```bash
# Database
curl http://10.0.88.11:5432  # Должен быть закрыт (только внутренний доступ)

# Backend
curl http://10.0.88.20:5000/api/health

# Frontend
curl http://10.0.88.10
curl http://10.0.88.10/api/health  # Должен проксировать на Backend

# Parsers
ssh user@10.0.88.23 "docker logs vulnerability-parsers | tail -20"
```

