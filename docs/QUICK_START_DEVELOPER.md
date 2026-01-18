# ⚡ Быстрый старт для нового разработчика

Краткая инструкция для быстрого начала работы над проектом.

---

## 🚀 За 5 минут

### 1. Клонирование репозитория

```bash
git clone https://github.com/GeFoRcE123123/analog.git vulnerability_manager
cd vulnerability_manager
```

### 2. Настройка окружения

```bash
# Создайте виртуальное окружение
python3 -m venv venv
source venv/bin/activate  # На Windows: venv\Scripts\activate

# Установите зависимости
pip install -r requirements.txt
```

### 3. Настройка Git

```bash
# Настройте ваше имя и email
git config user.name "Ваше Имя"
git config user.email "your.email@example.com"

# Переключитесь на рабочую ветку
git checkout main-new
git pull origin main-new
```

### 4. Создайте свою ветку

```bash
# Создайте ветку для вашей задачи
git checkout -b feature/your-feature-name
```

---

## ✅ Готово!

Теперь вы можете начать разработку. Для подробной информации см.:

- 📖 [DEVELOPER_SETUP.md](./DEVELOPER_SETUP.md) - Полная настройка окружения
- 👥 [CONTRIBUTING.md](./CONTRIBUTING.md) - Правила работы с проектом
- 🔀 [GIT_WORKFLOW.md](./GIT_WORKFLOW.md) - Рабочий процесс с Git
- 🔄 [GITHUB_SYNC.md](./GITHUB_SYNC.md) - Синхронизация с GitHub ⭐
- 🔐 [SSH_SETUP.md](./SSH_SETUP.md) - Настройка SSH для работы с VM

---

## 📝 Ежедневный workflow

```bash
# Утром - синхронизация с GitHub
git checkout main-new
git pull origin main-new
git checkout feature/your-feature-name
git rebase origin/main-new

# Во время работы
git add .
git commit -m "Описание изменений"
git push origin feature/your-feature-name  # Отправка на GitHub

# Вечером - финальная синхронизация
git push origin feature/your-feature-name
git fetch origin  # Проверка новых изменений
```

📖 Подробнее о синхронизации: [GITHUB_SYNC.md](./GITHUB_SYNC.md)

---

**Удачной разработки! 🎉**

