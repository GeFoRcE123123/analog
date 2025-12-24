# 🖥️ Локальный запуск на вашем ноутбуке

## ✅ Да, вы можете запустить тестовый вариант локально!

Все основные функции сайта можно запустить на вашем ноутбуке без доступа к VM.

---

## 🚀 Быстрый способ: Docker Compose (рекомендуется)

### Шаг 1: Установите Docker и Docker Compose
- Скачайте Docker Desktop для macOS: https://www.docker.com/products/docker-desktop

### Шаг 2: Запустите базу данных
```bash
cd services/database
docker compose up -d
```

### Шаг 3: Измените настройки подключения к БД

Создайте файл `config_local.py` в корне проекта:
```python
class Config:
    # Локальная БД
    DATABASE_HOST = 'localhost'
    DATABASE_PORT = 5432
    DATABASE_NAME = 'vuln_db'
    DATABASE_USER = 'admin'
    DATABASE_PASSWORD = 'admin'
    
    # Backend на localhost
    BACKEND_HOST = '127.0.0.1'
    BACKEND_PORT = 5000
    
    # Frontend на localhost
    FRONTEND_HOST = '127.0.0.1'
    FRONTEND_PORT = 80
```

### Шаг 4: Установите зависимости Python
```bash
pip install -r requirements.txt
# или если файла нет, установите основные:
pip install flask flask-wtf psycopg2-binary beautifulsoup4 requests
```

### Шаг 5: Запустите Backend
```bash
cd services/backend
export FLASK_APP=app.py
export FLASK_ENV=development
python app.py
# или
flask run --host=127.0.0.1 --port=5000
```

### Шаг 6: Откройте в браузере
```
http://localhost:5000
```

---

## 📋 Что будет работать:

✅ **Веб-интерфейс** - все страницы
✅ **API** - все эндпоинты  
✅ **База данных** - сохранение и чтение данных
✅ **Авторизация** - вход/выход пользователей
✅ **Парсинг** - большинство парсеров (если сайты доступны)
✅ **Управление уязвимостями** - просмотр, редактирование, назначение операторам

---

## ❌ Что может не работать:

⚠️ **Некоторые парсеры** - те, что требуют Selenium (нужен ChromeDriver)
⚠️ **Парсеры с защитой** - сайты, которые блокируют ботов
⚠️ **Многопоточность** - может работать медленнее на слабом ноутбуке

---

## 🔧 Альтернатива: Простой запуск без Docker

### Шаг 1: Установите PostgreSQL локально
```bash
# macOS
brew install postgresql
brew services start postgresql

# Создайте БД
createdb vuln_db
psql vuln_db < services/database/init.sql
```

### Шаг 2: Запустите Flask
```bash
python services/backend/app.py
```

### Шаг 3: Откройте браузер
```
http://localhost:5000
```

---

## 💡 Преимущества локального запуска:

1. **Быстрая разработка** - изменения видны сразу
2. **Отладка** - легко ставить breakpoints и логи
3. **Тестирование** - можно экспериментировать без риска
4. **Независимость** - не нужен доступ к VM

---

## 🆘 Если что-то не работает:

1. **Проверьте PostgreSQL**: `psql -U admin -d vuln_db -c "SELECT 1"`
2. **Проверьте порты**: `lsof -i :5000` (порт должен быть свободен)
3. **Проверьте логи**: ошибки будут в консоли где запускали Flask
4. **Проверьте зависимости**: `pip list | grep flask`

---

## 📝 Минимальная конфигурация для теста:

Если нужно просто посмотреть интерфейс без БД:

1. Запустите только Frontend (без сохранения в БД)
2. Или используйте SQLite вместо PostgreSQL (нужно изменить config)

**Для полноценного тестирования лучше использовать PostgreSQL через Docker.**

