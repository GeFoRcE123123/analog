# 🛠️ Настройка окружения разработчика

Пошаговое руководство для нового разработчика по настройке рабочего окружения проекта Vulnerability Manager.

---

## 📋 Предварительные требования

### Необходимое ПО

- **Git** (версия 2.0+)
- **Python** (версия 3.8+)
- **pip** (менеджер пакетов Python)
- **SSH клиент** (для работы с VM)
- **Текстовый редактор** (VS Code, PyCharm, или другой)

### Проверка установки

```bash
# Проверьте версии
git --version
python3 --version
pip3 --version
ssh -V
```

---

## 🚀 Шаг 1: Клонирование репозитория

### Получение кода проекта

```bash
# Перейдите в директорию для проектов
cd ~/Projects  # или любая другая директория

# Клонируйте репозиторий
git clone https://github.com/GeFoRcE123123/analog.git vulnerability_manager
cd vulnerability_manager

# Проверьте текущую ветку
git branch -a
# Вы должны увидеть ветки, включая main-new
```

### Настройка Git (если еще не настроено)

```bash
# Установите ваше имя и email
git config --global user.name "Ваше Имя"
git config --global user.email "your.email@example.com"

# Настройте редактор (опционально)
git config --global core.editor "code --wait"  # VS Code
# или
git config --global core.editor "nano"  # Nano

# Проверьте настройки
git config --list
```

---

## 🐍 Шаг 2: Настройка Python окружения

### Создание виртуального окружения

```bash
# Создайте виртуальное окружение
python3 -m venv venv

# Активируйте виртуальное окружение
# На macOS/Linux:
source venv/bin/activate

# На Windows:
# venv\Scripts\activate

# Вы должны увидеть (venv) в начале строки терминала
```

### Установка зависимостей

```bash
# Убедитесь, что виртуальное окружение активировано
# (должно быть (venv) в начале строки)

# Обновите pip
pip install --upgrade pip

# Установите зависимости проекта
pip install -r requirements.txt

# Если есть дополнительные зависимости для парсеров
pip install -r requirements_parser.txt
```

### Проверка установки

```bash
# Проверьте, что основные пакеты установлены
python -c "import flask; print('Flask OK')"
python -c "import psycopg2; print('PostgreSQL OK')"
python -c "import requests; print('Requests OK')"
```

---

## 🔐 Шаг 3: Настройка SSH подключений

Для работы с виртуальными машинами проекта необходимо настроить SSH.

### Быстрая настройка

```bash
# Запустите скрипт автоматической настройки
chmod +x scripts/setup_ssh.sh
./scripts/setup_ssh.sh --with-keys
```

Скрипт автоматически:
- ✅ Создаст SSH ключ
- ✅ Скопирует ключ на все VM
- ✅ Настроит SSH config
- ✅ Протестирует подключения

### Ручная настройка

См. подробные инструкции в [SSH_SETUP.md](./SSH_SETUP.md)

### Проверка SSH подключений

```bash
# Проверьте подключение к каждой VM
ssh database-vm "echo 'Database VM OK'"
ssh frontend-vm "echo 'Frontend VM OK'"
ssh backend-vm "echo 'Backend VM OK'"
ssh parsers-vm "echo 'Parsers VM OK'"
ssh ml-platform-vm "echo 'ML Platform VM OK'"
```

---

## ⚙️ Шаг 4: Настройка конфигурации

### Создание локального конфига

```bash
# Скопируйте пример конфигурации (если есть)
cp config.py.example config.py.local

# Или отредактируйте config.py напрямую
# (но не коммитьте изменения с паролями!)
```

### Настройка переменных окружения

```bash
# Создайте файл .env (он в .gitignore, не будет закоммичен)
cat > .env << EOF
# Database
DATABASE_HOST=10.0.88.11
DATABASE_PORT=5432
DATABASE_NAME=vuln_db
DATABASE_USER=admin
DATABASE_PASSWORD=123

# Backend
BACKEND_HOST=0.0.0.0
BACKEND_PORT=5000

# ML Platform
ML_PLATFORM_VM_IP=10.0.88.25
ML_PLATFORM_SSH_USER=k8s-worker
ML_PLATFORM_SSH_PASSWORD=k8s-worker
EOF
```

---

## 🧪 Шаг 5: Проверка работоспособности

### Проверка структуры проекта

```bash
# Убедитесь, что все директории на месте
ls -la

# Должны быть:
# - services/
# - models/
# - scripts/
# - docs/
# - templates/
# - config.py
# - requirements.txt
```

### Запуск тестов (если есть)

```bash
# Активируйте виртуальное окружение
source venv/bin/activate

# Запустите тесты
pytest tests/ -v

# Или отдельные тесты
python -m pytest tests/test_models.py
```

### Проверка импортов

```bash
# Проверьте, что основные модули импортируются
python -c "from models.database import DatabaseManager; print('Models OK')"
python -c "from services.backend import app; print('Services OK')"
```

---

## 🔧 Шаг 6: Настройка IDE/редактора

### VS Code

1. Установите расширения:
   - Python
   - Python Docstring Generator
   - GitLens
   - Remote - SSH (для работы с VM)

2. Создайте `.vscode/settings.json`:
```json
{
    "python.defaultInterpreterPath": "${workspaceFolder}/venv/bin/python",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.formatting.provider": "black",
    "editor.formatOnSave": true,
    "files.exclude": {
        "**/__pycache__": true,
        "**/*.pyc": true
    }
}
```

### PyCharm

1. Откройте проект в PyCharm
2. Настройте интерпретатор: `File → Settings → Project → Python Interpreter`
3. Выберите виртуальное окружение: `venv/bin/python`
4. Включите проверку кода: `File → Settings → Editor → Inspections`

---

## 📦 Шаг 7: Установка дополнительных инструментов

### Для разработки

```bash
# Установите инструменты разработки
pip install black pylint pytest pytest-cov

# Форматирование кода
black --check .

# Проверка стиля
pylint services/
```

### Для работы с БД

```bash
# Установите клиент PostgreSQL (если нужен)
# На macOS:
brew install postgresql

# На Ubuntu/Debian:
sudo apt-get install postgresql-client

# Проверьте подключение к БД
psql -h 10.0.88.11 -U admin -d vuln_db
```

---

## 🎯 Шаг 8: Создание первой ветки

### Начало работы над задачей

```bash
# Убедитесь, что вы на актуальной версии main-new
git checkout main-new
git pull origin main-new

# Создайте ветку для вашей задачи
git checkout -b feature/your-feature-name

# Или для исправления бага
git checkout -b fix/bug-description

# Проверьте текущую ветку
git branch
# Должна быть выделена ваша новая ветка
```

---

## ✅ Чеклист готовности

Проверьте, что все настроено:

- [ ] Репозиторий склонирован
- [ ] Git настроен (имя, email)
- [ ] Виртуальное окружение создано и активировано
- [ ] Зависимости установлены (`pip install -r requirements.txt`)
- [ ] SSH подключения настроены и работают
- [ ] Конфигурация настроена (config.py или .env)
- [ ] Тесты проходят (если есть)
- [ ] IDE/редактор настроен
- [ ] Создана рабочая ветка для разработки

---

## 🚨 Решение проблем

### Проблема: "command not found: git"

**Решение:**
```bash
# Установите Git
# На macOS:
brew install git

# На Ubuntu/Debian:
sudo apt-get install git
```

### Проблема: "No module named 'flask'"

**Решение:**
```bash
# Убедитесь, что виртуальное окружение активировано
source venv/bin/activate

# Переустановите зависимости
pip install -r requirements.txt
```

### Проблема: "Permission denied (publickey)" при SSH

**Решение:**
См. [SSH_SETUP.md](./SSH_SETUP.md) раздел "Устранение проблем"

### Проблема: "Could not connect to database"

**Решение:**
1. Проверьте, что БД запущена на VM
2. Проверьте настройки в config.py
3. Проверьте сетевую доступность: `ping 10.0.88.11`

---

## 📚 Следующие шаги

После настройки окружения:

1. **Прочитайте [CONTRIBUTING.md](./CONTRIBUTING.md)** - правила работы с проектом
2. **Изучите структуру проекта** - посмотрите основные файлы
3. **Ознакомьтесь с документацией** - начните с `docs/INDEX.md`
4. **Выберите задачу** - начните с простой задачи для знакомства
5. **Создайте ветку** - начните разработку

---

## 🆘 Получение помощи

Если возникли проблемы:

1. Проверьте документацию в `docs/`
2. Посмотрите примеры в коде
3. Спросите команду
4. Проверьте Issues на GitHub (если используется)

---

**Готово! Теперь вы можете начать разработку! 🎉**

