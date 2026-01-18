# 👋 Онбординг нового разработчика

Добро пожаловать в проект Vulnerability Manager! Этот документ поможет вам быстро начать работу.

---

## 📚 Что нужно прочитать (в порядке приоритета)

### 1. Начните здесь ⭐
- **[COMPLETE_GUIDE_FOR_SECOND_DEVELOPER.md](./COMPLETE_GUIDE_FOR_SECOND_DEVELOPER.md)** - 📚 **ПОЛНОЕ РУКОВОДСТВО** (стек, архитектура, деплой на сервер)
- **[QUICK_START_DEVELOPER.md](./QUICK_START_DEVELOPER.md)** - Быстрый старт за 5 минут

### 2. Настройка окружения
- **[DEVELOPER_SETUP.md](./DEVELOPER_SETUP.md)** - Полная настройка окружения разработчика
- **[SSH_SETUP.md](./SSH_SETUP.md)** - Настройка SSH для работы с VM

### 3. Рабочий процесс
- **[CONTRIBUTING.md](./CONTRIBUTING.md)** - Правила работы с проектом
- **[GIT_WORKFLOW.md](./GIT_WORKFLOW.md)** - Детальный Git workflow для параллельной разработки
- **[GITHUB_SYNC.md](./GITHUB_SYNC.md)** - 🔄 Синхронизация с GitHub (важно!)
- **[GET_UPDATES_FROM_GITHUB.md](./GET_UPDATES_FROM_GITHUB.md)** - 📥 Получение изменений с GitHub (когда первый разработчик залил изменения)
- **[WORK_IN_SAME_BRANCH.md](./WORK_IN_SAME_BRANCH.md)** - 👥 Работа в одной ветке (видеть изменения на сайте сразу)

### 4. Дополнительно
- **[INDEX.md](./INDEX.md)** - Индекс всей документации проекта
- **[GIT_VS_GITHUB.md](./GIT_VS_GITHUB.md)** - Понимание Git и GitHub

---

## 🎯 Чеклист первого дня

- [ ] Клонирован репозиторий
- [ ] Настроено виртуальное окружение Python
- [ ] Установлены зависимости (`pip install -r requirements.txt`)
- [ ] Настроен Git (имя, email)
- [ ] Настроены SSH подключения к VM (если нужно)
- [ ] Прочитаны основные документы
- [ ] Создана первая ветка для разработки
- [ ] Сделан первый тестовый коммит

---

## 🔄 Основной workflow

```
1. git checkout main-new
2. git pull origin main-new
3. git checkout -b feature/your-feature-name
4. [разработка]
5. git add .
6. git commit -m "Описание"
7. git push origin feature/your-feature-name
8. [повторять шаги 4-7]
```

---

## 📞 Получение помощи

Если у вас возникли вопросы:

1. Проверьте документацию в `docs/`
2. Посмотрите примеры в коде
3. Спросите команду
4. Изучите историю коммитов: `git log`

---

## 🎓 Полезные команды

```bash
# Статус репозитория
git status

# История коммитов
git log --oneline --graph

# Просмотр изменений
git diff

# Синхронизация с удаленным репозиторием
git fetch origin
git pull origin main-new
```

---

**Удачи в разработке! 🚀**

