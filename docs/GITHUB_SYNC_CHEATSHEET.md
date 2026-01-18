# 📋 Шпаргалка: Синхронизация с GitHub

Быстрая справка по основным командам синхронизации.

> 💡 **Для второго разработчика:** Когда первый разработчик залил изменения, см. [FOR_SECOND_DEVELOPER.md](./FOR_SECOND_DEVELOPER.md)

---

## 🔄 Основные команды

### Получить изменения с GitHub
```bash
git pull origin main-new
```

### Отправить изменения на GitHub
```bash
git push origin your-branch-name
```

### Проверить статус
```bash
git status
```

---

## 📅 Ежедневный workflow

### Утром
```bash
git checkout main-new
git pull origin main-new
git checkout feature/your-feature-name
git rebase origin/main-new
```

### Во время работы
```bash
git add .
git commit -m "Описание"
git push origin feature/your-feature-name
```

### Вечером
```bash
git push origin feature/your-feature-name
git fetch origin
```

---

## 🔍 Проверка синхронизации

```bash
# Что изменилось на GitHub
git fetch origin
git log HEAD..origin/main-new

# Ваши изменения, которых нет на GitHub
git log origin/main-new..HEAD
```

---

## ⚠️ Решение проблем

### "Your branch is ahead"
```bash
git push origin your-branch-name
```

### "Your branch is behind"
```bash
git pull origin main-new
```

### "Updates were rejected"
```bash
git pull --rebase origin your-branch-name
```

---

📖 **Подробная инструкция:** [GITHUB_SYNC.md](./GITHUB_SYNC.md)

