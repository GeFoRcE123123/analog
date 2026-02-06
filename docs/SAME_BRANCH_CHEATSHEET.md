# 📋 Шпаргалка: Работа в одной ветке

Быстрая справка для работы обоих разработчиков в main-new.

---

## ⚠️ Первый шаг: Добавить Collaborator

**Владелец репозитория должен:**
1. GitHub → Settings → Collaborators → Add people
2. Добавить второго разработчика с правами **Write**

---

## 🔄 Основные команды

### Утром (перед началом работы)
```bash
git checkout main-new
git pull origin main-new
```

### Перед каждым коммитом
```bash
git pull origin main-new  # ← ВАЖНО! Получить изменения
git add .
git commit -m "Описание"
git push origin main-new
```

### Вечером
```bash
git push origin main-new
```

---

## ⚠️ Правила

✅ **Всегда pull перед push**  
✅ **Работайте над разными файлами**  
✅ **Общайтесь с другим разработчиком**  
❌ **Никогда не делайте force push**  
❌ **Не игнорируйте конфликты**

---

## 🔀 Решение конфликтов

```bash
git pull origin main-new
# Разрешите конфликты в файлах
git add <файлы>
git commit -m "Разрешен конфликт"
git push origin main-new
```

---

📖 **Подробнее:** [WORK_IN_SAME_BRANCH.md](./WORK_IN_SAME_BRANCH.md)

