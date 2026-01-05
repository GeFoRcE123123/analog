# 🚀 Развертывание Vulnerability Manager на 4 VM

## 📋 Обзор

Проект разделен на 4 изолированных сервиса, каждый на отдельной VM:

| Сервис | IP | Назначение | Порт |
|--------|----|------------|------|
| **Frontend** | `10.0.88.10` | Nginx + UI | 80 |
| **Backend** | `10.0.88.20` | Flask API | 5000 |
| **Database** | `10.0.88.11` | PostgreSQL | 5432 |
| **Parsers** | `10.0.88.23` | Асинхронные парсеры | - |

---

## 📁 Структура проекта

```
vulnerability_manager/
├── services/
│   ├── frontend/          # Frontend сервис
│   │   ├── Dockerfile
│   │   ├── docker-compose.yml
│   │   ├── nginx.conf
│   │   └── base.html      # Обновленный с API_BASE_URL
│   ├── backend/           # Backend сервис
│   │   ├── Dockerfile
│   │   ├── docker-compose.yml
│   │   ├── app.py         # Только API маршруты
│   │   ├── config.py      # Конфигурация с IP 10.0.88.11
│   │   └── requirements.txt
│   ├── database/          # Database сервис
│   │   ├── docker-compose.yml
│   │   ├── init.sql       # Схема БД
│   │   └── pg_hba.conf    # Настройки доступа
│   └── parsers/           # Parsers сервис
│       ├── Dockerfile
│       ├── docker-compose.yml
│       ├── config.py      # Конфигурация с IP 10.0.88.11
│       ├── run_parsers.py # Скрипт запуска
│       └── requirements.txt
├── models/                # Общие модели (копируются в backend и parsers)
├── services/              # Общие сервисы (разделяются между backend и parsers)
├── templates/             # HTML шаблоны (копируются в frontend)
├── static/                # Статические файлы (копируются в frontend)
├── deploy.sh              # Автоматический скрипт развертывания
├── DEPLOYMENT.md          # Подробная инструкция
├── SERVICES_STRUCTURE.md  # Структура файлов
└── QUICK_START.md         # Быстрый старт
```

---

## 🔑 Ключевые изменения

### ✅ Backend (10.0.88.20)
- ❌ Удалены все `render_template()` маршруты
- ✅ Только API маршруты (`/api/*`)
- ✅ CORS настроен для `http://10.0.88.10`
- ✅ Подключение к БД: `10.0.88.11:5432`

### ✅ Frontend (10.0.88.10)
- ✅ Nginx проксирует `/api/*` → `http://10.0.88.20:5000`
- ✅ `base.html` использует `API_BASE_URL = 'http://10.0.88.20:5000'`
- ✅ Все `url_for()` заменены на статические пути

### ✅ Database (10.0.88.11)
- ✅ PostgreSQL слушает на всех интерфейсах (`listen_addresses = '*'`)
- ✅ `pg_hba.conf` разрешает подключения с `10.0.88.0/24`
- ✅ Автоматическая инициализация через `init.sql`

### ✅ Parsers (10.0.88.23)
- ✅ Изолированный сервис без Flask
- ✅ Подключение к БД: `10.0.88.11:5432`
- ✅ Автоматический запуск всех парсеров через `run_parsers.py`

---

## 🚀 Быстрое развертывание

### Вариант 1: Автоматический (рекомендуется)

```bash
# Установить sshpass
sudo apt install sshpass -y

# Запустить развертывание
./deploy.sh all
```

### Вариант 2: Ручной

См. подробные инструкции в `DEPLOYMENT.md`

---

## ✅ Проверка работы

```bash
# 1. Database
ssh user@10.0.88.11 "docker ps | grep vulnerability_db"

# 2. Backend
curl http://10.0.88.20:5000/api/health

# 3. Frontend
curl http://10.0.88.10
curl http://10.0.88.10/api/health  # Должен проксировать на Backend

# 4. Parsers
ssh user@10.0.88.23 "docker logs vulnerability-parsers | tail -20"
```

---

## 🔧 Конфигурация

### Изменение IP адресов

Если нужно изменить IP, обновите:

1. **Backend** (`services/backend/config.py`):
   ```python
   DATABASE_CONFIG.host = "10.0.88.11"
   FRONTEND_URL = "http://10.0.88.10"
   ```

2. **Parsers** (`services/parsers/config.py`):
   ```python
   DATABASE_CONFIG.host = "10.0.88.11"
   BACKEND_URL = "http://10.0.88.20:5000"
   ```

3. **Frontend** (`services/frontend/nginx.conf`):
   ```nginx
   upstream backend {
       server 10.0.88.20:5000;
   }
   ```

4. **Frontend** (`services/frontend/base.html`):
   ```javascript
   window.API_BASE_URL = 'http://10.0.88.20:5000';
   ```

---

## 📝 Документация

- `DEPLOYMENT.md` - Подробная инструкция по развертыванию
- `SERVICES_STRUCTURE.md` - Структура файлов по сервисам
- `QUICK_START.md` - Быстрый старт

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

## 📞 Поддержка

При возникновении проблем:
1. Проверьте логи всех сервисов
2. Убедитесь, что все IP адреса правильные
3. Проверьте сетевую связность между VM
4. Убедитесь, что все порты открыты

