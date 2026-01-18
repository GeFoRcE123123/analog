# 🔀 Git Workflow для параллельной разработки

Подробное руководство по работе с Git для эффективной параллельной разработки в команде.

---

## 📋 Содержание

1. [Основные принципы](#основные-принципы)
2. [Ежедневный workflow](#ежедневный-workflow)
3. [Сценарии работы](#сценарии-работы)
4. [Решение конфликтов](#решение-конфликтов)
5. [Best Practices](#best-practices)

---

## 🎯 Основные принципы

### Структура веток

```
main-new (основная ветка)
  ├── feature/user-auth (ваша ветка)
  ├── feature/parser-redhat (ветка другого разработчика)
  └── fix/database-timeout (ветка с исправлением)
```

**Правила:**
- ✅ **main-new** - стабильная ветка, только рабочий код
- ✅ **feature/** - новая функциональность
- ✅ **fix/** - исправления багов
- ✅ Каждый разработчик работает в своей ветке
- ❌ Никогда не коммитьте напрямую в `main-new`

---

## 📅 Ежедневный workflow

### Утро: Начало работы

```bash
# 1. Переключитесь на основную ветку
git checkout main-new

# 2. Получите последние изменения
git pull origin main-new

# 3. Переключитесь на вашу рабочую ветку
git checkout feature/your-feature-name

# 4. Обновите вашу ветку из main-new
git rebase origin/main-new
# или если предпочитаете merge:
git merge origin/main-new
```

### В течение дня: Разработка

```bash
# Делайте изменения в коде...

# 1. Проверьте статус
git status

# 2. Добавьте изменения
git add .
# или конкретные файлы:
git add services/backend/app.py

# 3. Сделайте коммит
git commit -m "Добавлена функция парсинга RedHat CVE"

# 4. Периодически отправляйте изменения (каждые 2-3 часа)
git push origin feature/your-feature-name
```

### Вечер: Завершение работы

```bash
# 1. Убедитесь, что все изменения закоммичены
git status

# 2. Отправьте все изменения
git push origin feature/your-feature-name

# 3. Проверьте, нет ли новых изменений в main-new
git fetch origin
git log HEAD..origin/main-new

# 4. Если есть изменения, обновите вашу ветку
git rebase origin/main-new
git push origin feature/your-feature-name
```

---

## 🎬 Сценарии работы

### Сценарий 1: Начало новой задачи

```bash
# 1. Убедитесь, что вы на актуальной версии
git checkout main-new
git pull origin main-new

# 2. Создайте новую ветку
git checkout -b feature/new-parser

# 3. Начните разработку
# ... делайте изменения ...

# 4. Первый коммит
git add .
git commit -m "Начало работы над новым парсером"

# 5. Отправьте ветку на сервер
git push -u origin feature/new-parser
```

### Сценарий 2: Продолжение работы над задачей

```bash
# 1. Переключитесь на вашу ветку
git checkout feature/new-parser

# 2. Получите последние изменения (если работали с другого компьютера)
git pull origin feature/new-parser

# 3. Обновите из main-new (если нужно)
git fetch origin
git rebase origin/main-new

# 4. Продолжайте разработку
# ... делайте изменения ...

# 5. Коммитьте и отправляйте
git add .
git commit -m "Добавлена обработка ошибок"
git push origin feature/new-parser
```

### Сценарий 3: Синхронизация с изменениями других разработчиков

```bash
# 1. Сохраните ваши текущие изменения (если есть незакоммиченные)
git stash
# или закоммитьте их:
git add .
git commit -m "WIP: работа в процессе"

# 2. Переключитесь на main-new
git checkout main-new

# 3. Получите последние изменения
git pull origin main-new

# 4. Вернитесь на вашу ветку
git checkout feature/your-feature-name

# 5. Обновите вашу ветку
git rebase origin/main-new
# или
git merge origin/main-new

# 6. Восстановите ваши изменения (если использовали stash)
git stash pop

# 7. Разрешите конфликты, если они есть (см. ниже)
```

### Сценарий 4: Завершение задачи и слияние

```bash
# 1. Убедитесь, что все изменения закоммичены
git status

# 2. Обновите вашу ветку из main-new
git fetch origin
git rebase origin/main-new

# 3. Разрешите все конфликты (если есть)

# 4. Отправьте обновленную ветку
git push origin feature/your-feature-name

# 5. Уведомите команду о готовности
# (или создайте Pull Request, если используется)

# 6. После одобрения, слияние в main-new делает ведущий разработчик
```

---

## 🔀 Решение конфликтов

### Что такое конфликт?

Конфликт возникает, когда:
- Вы изменили файл в вашей ветке
- Другой разработчик изменил тот же файл в main-new
- Git не может автоматически объединить изменения

### Процесс разрешения конфликта

#### Шаг 1: Обнаружение конфликта

```bash
git rebase origin/main-new
# Вы увидите:
# CONFLICT (content): Merge conflict in services/backend/app.py
```

#### Шаг 2: Просмотр конфликтующих файлов

```bash
# Список файлов с конфликтами
git status

# Просмотр конфликта
git diff
```

#### Шаг 3: Открытие файла с конфликтом

В файле вы увидите маркеры:

```python
<<<<<<< HEAD
# Ваш код
def your_function():
    return "your code"
=======
# Код из main-new
def their_function():
    return "their code"
>>>>>>> origin/main-new
```

#### Шаг 4: Разрешение конфликта

**Вариант 1: Оставить ваш код**
```python
def your_function():
    return "your code"
```

**Вариант 2: Оставить код из main-new**
```python
def their_function():
    return "their code"
```

**Вариант 3: Объединить оба (рекомендуется)**
```python
def your_function():
    return "your code"

def their_function():
    return "their code"
```

**Вариант 4: Создать новую версию**
```python
def combined_function():
    return "combined code"
```

#### Шаг 5: Завершение разрешения

```bash
# 1. Добавьте разрешенные файлы
git add services/backend/app.py

# 2. Продолжите rebase
git rebase --continue

# 3. Если нужно отменить rebase
git rebase --abort
```

### Стратегии предотвращения конфликтов

1. **Частая синхронизация** - делайте `git pull` несколько раз в день
2. **Общение с командой** - обсуждайте, кто над какими файлами работает
3. **Работа над разными файлами** - если возможно
4. **Небольшие коммиты** - легче разрешать конфликты

---

## 💡 Best Practices

### ✅ Делайте:

1. **Частые коммиты**
   ```bash
   # Хорошо: коммит каждые 1-2 часа
   git commit -m "Добавлена валидация данных"
   
   # Плохо: один большой коммит в конце дня
   ```

2. **Понятные сообщения коммитов**
   ```bash
   # Хорошо:
   git commit -m "Исправлена ошибка подключения к БД при таймауте"
   
   # Плохо:
   git commit -m "fix"
   ```

3. **Работа в ветках**
   ```bash
   # Хорошо: каждая задача в отдельной ветке
   git checkout -b feature/user-auth
   
   # Плохо: работа напрямую в main-new
   ```

4. **Регулярная синхронизация**
   ```bash
   # Хорошо: несколько раз в день
   git fetch origin
   git rebase origin/main-new
   
   # Плохо: только в конце недели
   ```

5. **Тестирование перед коммитом**
   ```bash
   # Проверьте, что код работает
   python -m pytest tests/
   python app.py  # проверка запуска
   ```

### ❌ Не делайте:

1. **Не коммитьте неработающий код**
   ```bash
   # Плохо: код не компилируется
   git commit -m "WIP"
   ```

2. **Не коммитьте пароли и секреты**
   ```bash
   # Плохо: пароли в коде
   password = "12345"
   
   # Хорошо: использование переменных окружения
   password = os.getenv("DB_PASSWORD")
   ```

3. **Не игнорируйте конфликты**
   ```bash
   # Плохо: оставить маркеры конфликта в коде
   <<<<<<< HEAD
   
   # Хорошо: разрешить конфликт сразу
   ```

4. **Не перезаписывайте историю в общей ветке**
   ```bash
   # Плохо: force push в main-new
   git push --force origin main-new
   
   # Хорошо: только в своих ветках
   git push --force origin feature/your-branch
   ```

---

## 🔧 Полезные команды

### Просмотр истории

```bash
# История коммитов
git log --oneline --graph --all

# История конкретного файла
git log -- services/backend/app.py

# Кто изменил строку
git blame services/backend/app.py
```

### Работа с изменениями

```bash
# Просмотр изменений
git diff

# Просмотр изменений конкретного файла
git diff services/backend/app.py

# Просмотр изменений перед коммитом
git diff --cached
```

### Отмена изменений

```bash
# Отменить изменения в файле (до git add)
git checkout -- services/backend/app.py

# Отменить добавление файла (после git add, до commit)
git reset HEAD services/backend/app.py

# Отменить последний коммит (сохранить изменения)
git reset --soft HEAD~1

# Отменить последний коммит (удалить изменения)
git reset --hard HEAD~1
```

### Работа с ветками

```bash
# Список всех веток
git branch -a

# Создать ветку из текущей
git checkout -b feature/new-feature

# Переключиться на ветку
git checkout feature/new-feature

# Удалить локальную ветку
git branch -d feature/old-feature

# Удалить удаленную ветку
git push origin --delete feature/old-feature
```

---

## 📊 Визуализация workflow

```
День 1: Начало работы
├── git checkout main-new
├── git pull origin main-new
├── git checkout -b feature/new-feature
└── git push -u origin feature/new-feature

День 2-5: Разработка
├── git add .
├── git commit -m "Описание"
├── git push origin feature/new-feature
└── (повторять несколько раз в день)

День 6: Синхронизация
├── git fetch origin
├── git rebase origin/main-new
├── (разрешить конфликты если есть)
└── git push origin feature/new-feature

День 7: Завершение
├── git rebase origin/main-new
├── git push origin feature/new-feature
└── Уведомить команду о готовности
```

---

## 🆘 Частые проблемы и решения

### Проблема: "Your branch is ahead of 'origin/main-new' by X commits"

**Решение:**
```bash
git push origin feature/your-branch-name
```

### Проблема: "Updates were rejected because the remote contains work"

**Решение:**
```bash
# Получите изменения
git pull origin feature/your-branch-name

# Или используйте rebase
git pull --rebase origin feature/your-branch-name
```

### Проблема: "Merge conflict" при rebase

**Решение:**
1. Разрешите конфликты в файлах
2. `git add <файлы>`
3. `git rebase --continue`

### Проблема: Случайно закоммитили в main-new

**Решение:**
```bash
# Создайте ветку из текущего состояния
git checkout -b feature/save-changes

# Вернитесь в main-new
git checkout main-new

# Откатите последний коммит
git reset --hard HEAD~1

# Продолжите работу в ветке
git checkout feature/save-changes
```

---

## 📚 Дополнительные ресурсы

- [CONTRIBUTING.md](./CONTRIBUTING.md) - общее руководство для разработчиков
- [DEVELOPER_SETUP.md](./DEVELOPER_SETUP.md) - настройка окружения
- [Официальная документация Git](https://git-scm.com/doc)
- [GitHub Guides](https://guides.github.com/)

---

**Удачной разработки! 🚀**

