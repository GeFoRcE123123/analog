# 🔄 Синхронизация с GitHub

Пошаговая инструкция по синхронизации локального репозитория с GitHub для параллельной разработки.

---

## 📋 Быстрая справка

### Основные команды синхронизации

```bash
# Получить изменения с GitHub
git pull origin main-new

# Отправить изменения на GitHub
git push origin your-branch-name

# Проверить статус
git status
```

---

## 🚀 Первоначальная настройка

### Шаг 1: Клонирование репозитория

Если вы только начинаете работу, клонируйте репозиторий:

```bash
git clone https://github.com/GeFoRcE123123/analog.git vulnerability_manager
cd vulnerability_manager
```

### Шаг 2: Проверка подключения к GitHub

```bash
# Проверьте удаленные репозитории
git remote -v

# Должно показать:
# origin  https://github.com/GeFoRcE123123/analog.git (fetch)
# origin  https://github.com/GeFoRcE123123/analog.git (push)
```

### Шаг 3: Настройка Git (если еще не настроено)

```bash
# Установите ваше имя и email
git config --global user.name "Ваше Имя"
git config --global user.email "your.email@example.com"

# Проверьте настройки
git config --list
```

---

## 📥 Получение изменений с GitHub

> 💡 **Для второго разработчика:** Когда первый разработчик залил изменения на GitHub, см. [GET_UPDATES_FROM_GITHUB.md](./GET_UPDATES_FROM_GITHUB.md) для подробной инструкции.

### Вариант 1: Простое получение (pull)

```bash
# Переключитесь на основную ветку
git checkout main-new

# Получите и слейте изменения
git pull origin main-new
```

**Что делает:**
- ✅ Получает изменения с GitHub
- ✅ Автоматически сливает их с вашей локальной веткой
- ✅ Создает merge commit (если есть изменения)

### Вариант 2: Получение без слияния (fetch + rebase)

```bash
# Получите изменения без слияния
git fetch origin

# Посмотрите, что изменилось
git log HEAD..origin/main-new

# Обновите вашу ветку через rebase (чистая история)
git checkout main-new
git rebase origin/main-new
```

**Что делает:**
- ✅ Получает изменения без автоматического слияния
- ✅ Позволяет просмотреть изменения перед применением
- ✅ Создает линейную историю (без merge commits)

### Рекомендация

**Используйте `git pull`** для простоты, если вы не уверены.  
**Используйте `git fetch + rebase`** для чистой истории коммитов.

---

## 📤 Отправка изменений на GitHub

### Базовая отправка

```bash
# 1. Проверьте статус
git status

# 2. Добавьте изменения
git add .

# 3. Сделайте коммит
git commit -m "Описание ваших изменений"

# 4. Отправьте на GitHub
git push origin your-branch-name
```

### Первая отправка новой ветки

Если вы создали новую ветку и отправляете её впервые:

```bash
# Создайте ветку
git checkout -b feature/your-feature-name

# Сделайте изменения и закоммитьте
git add .
git commit -m "Начало работы над функцией"

# Отправьте и установите отслеживание
git push -u origin feature/your-feature-name
```

Флаг `-u` (или `--set-upstream`) устанавливает связь между локальной и удаленной веткой.

---

## 🔄 Ежедневная синхронизация

### Утром (начало работы)

```bash
# 1. Переключитесь на основную ветку
git checkout main-new

# 2. Получите последние изменения с GitHub
git pull origin main-new

# 3. Переключитесь на вашу рабочую ветку
git checkout feature/your-feature-name

# 4. Обновите вашу ветку из main-new
git rebase origin/main-new
# или
git merge origin/main-new
```

### В течение дня

```bash
# После каждого коммита (каждые 2-3 часа)
git push origin feature/your-feature-name
```

### Вечером (завершение работы)

```bash
# 1. Убедитесь, что все закоммичено
git status

# 2. Отправьте все изменения
git push origin feature/your-feature-name

# 3. Проверьте, нет ли новых изменений
git fetch origin
git log HEAD..origin/main-new

# 4. Если есть изменения, обновите вашу ветку
git rebase origin/main-new
git push origin feature/your-feature-name
```

---

## 🔍 Проверка синхронизации

### Проверить, синхронизированы ли ветки

```bash
# Проверьте статус
git status

# Сравните локальную и удаленную ветки
git fetch origin
git log HEAD..origin/main-new  # Коммиты на GitHub, которых нет у вас
git log origin/main-new..HEAD  # Ваши коммиты, которых нет на GitHub
```

### Визуальное сравнение

```bash
# Графическое представление истории
git log --oneline --graph --all --decorate

# Сравнение веток
git diff main-new origin/main-new
```

---

## ⚠️ Решение проблем

### Проблема: "Your branch is ahead of 'origin/main-new' by X commits"

**Причина:** У вас есть локальные коммиты, которых нет на GitHub.

**Решение:**
```bash
# Отправьте ваши изменения
git push origin main-new
```

### Проблема: "Your branch is behind 'origin/main-new' by X commits"

**Причина:** На GitHub есть изменения, которых нет у вас локально.

**Решение:**
```bash
# Получите изменения
git pull origin main-new
```

### Проблема: "Updates were rejected because the remote contains work"

**Причина:** На GitHub есть изменения, которые конфликтуют с вашими.

**Решение:**
```bash
# Вариант 1: Получить изменения и слить
git pull origin your-branch-name

# Вариант 2: Получить и перебазировать (рекомендуется)
git pull --rebase origin your-branch-name

# После разрешения конфликтов (если есть)
git push origin your-branch-name
```

### Проблема: "Permission denied (publickey)"

**Причина:** Не настроена аутентификация SSH или HTTPS.

**Решение для HTTPS:**
```bash
# Git запросит логин и пароль
# Или используйте Personal Access Token вместо пароля
# Получить токен: GitHub → Settings → Developer settings → Personal access tokens
```

**Решение для SSH:**
```bash
# Настройте SSH ключ (см. SSH_SETUP.md)
# Или измените URL на SSH:
git remote set-url origin git@github.com:GeFoRcE123123/analog.git
```

---

## 🔐 Настройка аутентификации

### Вариант 1: HTTPS (проще для начала)

```bash
# При первом push/pull Git запросит логин и пароль
# Используйте ваш GitHub username и Personal Access Token
# (не обычный пароль!)

# Получить токен:
# GitHub → Settings → Developer settings → Personal access tokens → Generate new token
```

### Вариант 2: SSH (рекомендуется)

```bash
# 1. Проверьте, есть ли SSH ключ
ls -la ~/.ssh/id_*.pub

# 2. Если нет, создайте
ssh-keygen -t ed25519 -C "your.email@example.com"

# 3. Скопируйте публичный ключ
cat ~/.ssh/id_ed25519.pub

# 4. Добавьте ключ на GitHub:
# GitHub → Settings → SSH and GPG keys → New SSH key

# 5. Измените URL репозитория на SSH
git remote set-url origin git@github.com:GeFoRcE123123/analog.git

# 6. Проверьте подключение
ssh -T git@github.com
```

---

## 📊 Типичные сценарии

### Сценарий 1: Вы работали один день, другой разработчик тоже работал

```bash
# Утром получите его изменения
git checkout main-new
git pull origin main-new

# Обновите вашу ветку
git checkout feature/your-feature-name
git rebase origin/main-new

# Продолжайте работу
```

### Сценарий 2: Вы хотите отправить изменения, но на GitHub есть новые

```bash
# Получите изменения
git fetch origin

# Обновите вашу ветку
git rebase origin/main-new

# Разрешите конфликты, если есть (см. GIT_WORKFLOW.md)

# Отправьте изменения
git push origin feature/your-feature-name
```

### Сценарий 3: Вы работали с другого компьютера

```bash
# Получите последние изменения
git pull origin feature/your-feature-name

# Продолжайте работу
```

---

## 💡 Best Practices

### ✅ Делайте:

1. **Часто синхронизируйтесь** - делайте `git pull` несколько раз в день
2. **Отправляйте изменения регулярно** - каждые 2-3 часа
3. **Проверяйте статус перед push** - `git status` и `git fetch`
4. **Используйте понятные сообщения коммитов** - легче понять историю

### ❌ Не делайте:

1. **Не игнорируйте конфликты** - решайте их сразу
2. **Не делайте force push в общие ветки** - только в свои feature ветки
3. **Не коммитьте без синхронизации** - сначала `git pull`
4. **Не отправляйте неработающий код** - тестируйте перед push

---

## 🎯 Чеклист синхронизации

Перед началом работы:
- [ ] `git checkout main-new`
- [ ] `git pull origin main-new`
- [ ] `git checkout feature/your-feature-name`
- [ ] `git rebase origin/main-new`

Во время работы:
- [ ] `git add .`
- [ ] `git commit -m "Описание"`
- [ ] `git push origin feature/your-feature-name` (каждые 2-3 часа)

Перед завершением:
- [ ] `git push origin feature/your-feature-name`
- [ ] `git fetch origin`
- [ ] Проверить, нет ли конфликтов

---

## 📚 Дополнительные ресурсы

- [GIT_WORKFLOW.md](./GIT_WORKFLOW.md) - Детальный workflow
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Правила работы с проектом
- [DEVELOPER_SETUP.md](./DEVELOPER_SETUP.md) - Настройка окружения
- [GitHub Docs](https://docs.github.com/) - Официальная документация GitHub

---

**Успешной синхронизации! 🔄**

