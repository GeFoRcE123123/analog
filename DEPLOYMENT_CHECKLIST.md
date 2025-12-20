# ✅ Чеклист готовности к развертыванию на 4 VM

## 🔍 Проверка структуры файлов

### 1. Backend (10.0.88.20)

#### ✅ Обязательные файлы в `services/backend/`:
- [x] `app.py` - Flask API приложение
- [x] `config.py` - Конфигурация с IP 10.0.88.11
- [x] `Dockerfile` - Образ для контейнера
- [x] `docker-compose.yml` - Оркестрация
- [x] `requirements.txt` - Зависимости Python

#### ✅ Файлы для копирования в `services/backend/`:
- [ ] `models/` - ВСЯ директория (database.py, entities.py, repositories.py, legacy_repositories.py и т.д.)
- [ ] `services/vulnerability_service.py`
- [ ] `services/operator_service.py`
- [ ] `services/export_service.py`
- [ ] `services/assignment_manager.py`
- [ ] `services/data_manager.py`
- [ ] `services/analytics_service.py`
- [ ] `services/auth_service.py`
- [ ] `utils/decorators.py` (если используется)

#### ⚠️ Проблемы:
1. **Исправлено**: `app.py` импортирует `from config import Config` - должен импортировать из локального `config.py`
2. **Нужно**: Скопировать все файлы из `models/` и `services/` (кроме парсеров) в директорию backend при развертывании

---

### 2. Frontend (10.0.88.10)

#### ✅ Обязательные файлы в `services/frontend/`:
- [x] `nginx.conf` - Конфигурация Nginx
- [x] `Dockerfile` - Образ для контейнера
- [x] `docker-compose.yml` - Оркестрация
- [x] `base.html` - Базовый шаблон с API_BASE_URL

#### ✅ Файлы для копирования в `services/frontend/`:
- [ ] `templates/` - ВСЯ директория (dashboard.html, vulnerabilities_list.html, и т.д.)
- [ ] `static/` - ВСЯ директория (CSS, JS, изображения)

#### ⚠️ Проблемы:
1. **Нужно проверить**: Все шаблоны должны использовать статические пути вместо `url_for()`
2. **Нужно**: Обновить все ссылки на API в шаблонах на `http://10.0.88.20:5000`

---

### 3. Database (10.0.88.11)

#### ✅ Обязательные файлы в `services/database/`:
- [x] `init.sql` - Схема БД (modern + legacy)
- [x] `docker-compose.yml` - Оркестрация PostgreSQL
- [x] `pg_hba.conf` - Настройки доступа

#### ✅ Готовность:
- [x] Все файлы на месте
- [x] `init.sql` содержит обе схемы (modern и legacy)
- [x] `pg_hba.conf` разрешает подключения с 10.0.88.0/24

---

### 4. Parsers (10.0.88.23)

#### ✅ Обязательные файлы в `services/parsers/`:
- [x] `run_parsers.py` - Скрипт запуска
- [x] `config.py` - Конфигурация с IP 10.0.88.11
- [x] `Dockerfile` - Образ для контейнера
- [x] `docker-compose.yml` - Оркестрация
- [x] `requirements.txt` - Зависимости Python

#### ✅ Файлы для копирования в `services/parsers/`:
- [ ] `models/` - ВСЯ директория
- [ ] `services/parsing_manager.py`
- [ ] `services/nvd_integration_service.py`
- [ ] `services/nvd_parser.py`
- [ ] `services/nvd_scheduler.py`
- [ ] `services/redhat_cve_importer.py`
- [ ] `services/osv_parser.py`
- [ ] `services/fast_osv_parser.py` (если используется)

#### ⚠️ Проблемы:
1. **Нужно**: Скопировать все файлы из `models/` и парсеры из `services/` при развертывании
2. **Проверить**: `run_parsers.py` правильно импортирует config из локальной директории

---

## 📋 Детальный чеклист файлов

### Backend должен содержать:

```
services/backend/
├── app.py                    ✅
├── config.py                 ✅
├── Dockerfile                ✅
├── docker-compose.yml        ✅
├── requirements.txt          ✅
├── models/                   ❌ НУЖНО СКОПИРОВАТЬ
│   ├── __init__.py
│   ├── database.py
│   ├── entities.py
│   ├── postgres_repositories.py
│   ├── legacy_repositories.py
│   ├── repository_factory.py
│   └── ...
├── services/                 ❌ НУЖНО СКОПИРОВАТЬ (частично)
│   ├── vulnerability_service.py
│   ├── operator_service.py
│   ├── export_service.py
│   ├── assignment_manager.py
│   ├── data_manager.py
│   ├── analytics_service.py
│   └── auth_service.py
└── utils/                    ❌ НУЖНО СКОПИРОВАТЬ (если используется)
    └── decorators.py
```

### Frontend должен содержать:

```
services/frontend/
├── nginx.conf                ✅
├── Dockerfile                ✅
├── docker-compose.yml        ✅
├── base.html                 ✅
├── templates/                ❌ НУЖНО СКОПИРОВАТЬ
│   ├── dashboard.html
│   ├── vulnerabilities_list.html
│   ├── operators.html
│   ├── performance_analytics.html
│   ├── parsers.html
│   └── ...
└── static/                   ❌ НУЖНО СКОПИРОВАТЬ
    ├── css/
    └── js/
```

### Parsers должен содержать:

```
services/parsers/
├── run_parsers.py            ✅
├── config.py                 ✅
├── Dockerfile                ✅
├── docker-compose.yml        ✅
├── requirements.txt          ✅
├── models/                   ❌ НУЖНО СКОПИРОВАТЬ
│   └── (все файлы)
└── services/                 ❌ НУЖНО СКОПИРОВАТЬ (только парсеры)
    ├── parsing_manager.py
    ├── nvd_integration_service.py
    ├── nvd_parser.py
    ├── nvd_scheduler.py
    ├── redhat_cve_importer.py
    └── osv_parser.py
```

---

## 🔧 Исправления перед развертыванием

### 1. Backend app.py

**Проблема**: Импорт config должен быть из локальной директории

**Исправлено**: ✅ Добавлен правильный импорт config из `services/backend/config.py`

### 2. Обновить deploy.sh

**Нужно проверить**: Скрипт `deploy.sh` правильно копирует все необходимые файлы:

```bash
# Backend
- services/backend/* → ~/vulnerability_manager/backend/
- models/* → ~/vulnerability_manager/backend/models/
- services/vulnerability_service.py и др. → ~/vulnerability_manager/backend/services/
- utils/* → ~/vulnerability_manager/backend/utils/

# Frontend
- services/frontend/* → ~/vulnerability_manager/frontend/
- templates/* → ~/vulnerability_manager/frontend/templates/
- static/* → ~/vulnerability_manager/frontend/static/

# Parsers
- services/parsers/* → ~/vulnerability_manager/parsers/
- models/* → ~/vulnerability_manager/parsers/models/
- services/parsing*.py и др. → ~/vulnerability_manager/parsers/services/
```

---

## ✅ Финальная проверка

### Перед развертыванием убедиться:

1. **Backend**:
   - [x] `app.py` импортирует config из локальной директории
   - [ ] Все зависимости в `requirements.txt`
   - [ ] Dockerfile правильно копирует файлы
   - [ ] docker-compose.yml настроен

2. **Frontend**:
   - [x] `nginx.conf` проксирует на 10.0.88.20:5000
   - [x] `base.html` использует API_BASE_URL
   - [ ] Все шаблоны обновлены (статичные пути)

3. **Database**:
   - [x] `init.sql` содержит обе схемы
   - [x] `pg_hba.conf` разрешает доступ

4. **Parsers**:
   - [x] `run_parsers.py` импортирует config из локальной директории
   - [ ] Все зависимости в `requirements.txt`
   - [ ] Dockerfile правильно копирует файлы

---

## 🚀 Готовность к развертыванию

### Статус: ⚠️ ТРЕБУЕТСЯ ДОПОЛНИТЕЛЬНАЯ ПОДГОТОВКА

**Что нужно сделать**:

1. **Обновить deploy.sh** - убедиться, что он копирует все необходимые файлы
2. **Проверить импорты** - все сервисы должны импортировать config из локальных директорий
3. **Создать структуру директорий** на каждой VM перед копированием
4. **Протестировать локально** - собрать Docker образы и проверить запуск

---

## 📝 Рекомендации

1. **Создать скрипт подготовки** для каждой VM:
   ```bash
   # Создать структуру директорий
   mkdir -p ~/vulnerability_manager/{backend,frontend,database,parsers}/{models,services,utils}
   ```

2. **Проверить зависимости**:
   - Backend: Flask, psycopg, gunicorn
   - Parsers: selenium, beautifulsoup4, schedule

3. **Протестировать сборку**:
   ```bash
   cd services/backend && docker build -t test-backend .
   cd ../parsers && docker build -t test-parsers .
   ```

