# 👥 Инструкция для второго разработчика

Краткая инструкция: что делать, когда первый разработчик залил изменения на GitHub.

> 💡 **Вариант работы в одной ветке:** Если вы работаете в одной ветке main-new, см. [WORK_IN_SAME_BRANCH.md](./WORK_IN_SAME_BRANCH.md)

---

## 🎯 Главное правило

**Всегда синхронизируйтесь перед началом работы!**

---

## 📥 Когда первый разработчик залил изменения

### Быстрая инструкция (копируйте и выполняйте):

```bash
# 1. Переключитесь на основную ветку
git checkout main-new

# 2. Получите изменения с GitHub
git pull origin main-new

# 3. Вернитесь на вашу рабочую ветку
git checkout feature/your-feature-name

# 4. Обновите вашу ветку из main-new
git rebase origin/main-new

# 5. Если есть конфликты - разрешите их
# (см. инструкцию ниже)

# 6. Отправьте обновленную ветку
git push origin feature/your-feature-name
```

---

## ⏰ Когда выполнять синхронизацию

### ✅ Обязательно:

1. **Утром, перед началом работы** - каждый день
2. **После того, как первый разработчик сказал "залил изменения"**
3. **Перед началом новой задачи**

### ✅ Рекомендуется:

1. **Каждые 2-3 часа** - проверяйте новые изменения
2. **Перед большими изменениями** - убедитесь, что у вас актуальная версия

---

## 🔍 Как проверить, есть ли новые изменения

```bash
# Получите информацию об изменениях (без применения)
git fetch origin

# Проверьте статус
git status

# Если видите "Your branch is behind" - есть новые изменения
# Если видите "Your branch is up to date" - все актуально
```

---

## 🔄 Полный процесс получения изменений

### Шаг 1: Сохраните вашу текущую работу

```bash
# Если есть незакоммиченные изменения
git add .
git commit -m "WIP: сохранение текущей работы"

# Или временно сохраните
git stash
```

### Шаг 2: Получите изменения

```bash
git checkout main-new
git pull origin main-new
```

### Шаг 3: Обновите вашу ветку

```bash
git checkout feature/your-feature-name
git rebase origin/main-new
```

### Шаг 4: Разрешите конфликты (если есть)

Если Git сообщит о конфликтах:

1. Откройте файлы с конфликтами
2. Найдите маркеры `<<<<<<<`, `=======`, `>>>>>>>`
3. Разрешите конфликт (оставьте нужный код или объедините)
4. Удалите маркеры конфликта
5. Выполните:
```bash
git add <файлы>
git rebase --continue
```

### Шаг 5: Отправьте обновления

```bash
git push origin feature/your-feature-name

# Если нужно (после rebase)
git push --force-with-lease origin feature/your-feature-name
```

---

## ⚠️ Что делать, если что-то пошло не так

### "Your branch is behind"

```bash
git checkout main-new
git pull origin main-new
git checkout feature/your-feature-name
git rebase origin/main-new
```

### "Cannot rebase: You have unstaged changes"

```bash
git stash
git rebase origin/main-new
git stash pop
```

### Конфликты при rebase

1. Разрешите конфликты в файлах
2. `git add <файлы>`
3. `git rebase --continue`

### "Updates were rejected"

```bash
git push --force-with-lease origin feature/your-feature-name
```

---

## 📋 Ежедневный чеклист

**Утром:**
- [ ] `git checkout main-new`
- [ ] `git pull origin main-new`
- [ ] `git checkout feature/your-feature-name`
- [ ] `git rebase origin/main-new`
- [ ] Разрешить конфликты (если есть)
- [ ] `git push origin feature/your-feature-name`

**Во время работы:**
- [ ] Периодически проверять: `git fetch origin`
- [ ] Если есть изменения - обновить ветку

**Вечером:**
- [ ] `git push origin feature/your-feature-name`

---

## 💡 Важные советы

1. ✅ **Всегда синхронизируйтесь утром** - перед началом работы
2. ✅ **Получайте изменения часто** - минимум раз в день
3. ✅ **Общайтесь с первым разработчиком** - узнавайте, когда заливаются изменения
4. ✅ **Разрешайте конфликты сразу** - не откладывайте
5. ✅ **Тестируйте после обновления** - убедитесь, что все работает

---

## 📚 Подробная документация

- [GET_UPDATES_FROM_GITHUB.md](./GET_UPDATES_FROM_GITHUB.md) - Подробная инструкция
- [GITHUB_SYNC.md](./GITHUB_SYNC.md) - Полная инструкция по синхронизации
- [GIT_WORKFLOW.md](./GIT_WORKFLOW.md) - Git workflow

---

**Успешной синхронизации! 🚀**

