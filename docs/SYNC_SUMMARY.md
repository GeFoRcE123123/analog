# 📌 Краткая инструкция: Синхронизация с GitHub

## Для нового разработчика

### Первый раз

```bash
# 1. Клонировать репозиторий
git clone https://github.com/GeFoRcE123123/analog.git
cd analog

# 2. Создать свою ветку
git checkout -b feature/your-name

# 3. Настроить Git (если еще не настроено)
git config user.name "Ваше Имя"
git config user.email "your.email@example.com"
```

### Каждый день

**Утром:**
```bash
git checkout main-new
git pull origin main-new
git checkout feature/your-name
git rebase origin/main-new
```

**Во время работы:**
```bash
git add .
git commit -m "Описание изменений"
git push origin feature/your-name
```

**Вечером:**
```bash
git push origin feature/your-name
```

---

## Для второго разработчика (когда первый залил изменения)

**Быстрая команда:**
```bash
git checkout main-new
git pull origin main-new
git checkout feature/your-name
git rebase origin/main-new
git push origin feature/your-name
```

📖 **Подробнее:** [FOR_SECOND_DEVELOPER.md](./FOR_SECOND_DEVELOPER.md)

---

## Важно!

- ✅ **Всегда синхронизируйтесь утром** - получайте изменения других разработчиков
- ✅ **Отправляйте изменения регулярно** - каждые 2-3 часа
- ✅ **Работайте в своей ветке** - не коммитьте в main-new
- ❌ **Не игнорируйте конфликты** - решайте их сразу

---

📖 **Подробнее:** [GITHUB_SYNC.md](./GITHUB_SYNC.md)
