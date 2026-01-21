# ✅ ПРАВИЛЬНЫЙ ДЕПЛОЙ - Docker контейнер

## 🔍 Проблема

**Первый деплой был неправильным!**

### ❌ Что было не так:
1. **Копировал в `/home/user/vulnerability_manager/backend/.tmp_backend_60360`** - временная директория
2. Flask приложение работает **в Docker контейнере** `vulnerability-backend`
3. Рабочая директория контейнера: `/app`
4. Файлы были скопированы НЕ туда, где работает приложение

### ✅ Правильное решение:
Копировать файлы **напрямую в Docker контейнер** через `docker cp`

---

## 📦 Архитектура

```
Хост (10.0.88.20)
├── Docker контейнер: vulnerability-backend
│   ├── Image: backend-backend
│   ├── Working Directory: /app
│   ├── Process: gunicorn --bind 0.0.0.0:5000 --workers 4
│   ├── /app/templates/
│   ├── /app/static/
│   └── /app/app.py
└── Volumes:
    ├── /home/user/vulnerability_manager/backend/logs → /app/logs
    └── /tmp/cve_data → /tmp/cve_data
```

**Важно**: Основные файлы (templates, static, app.py) находятся **внутри образа контейнера**, а не в volumes!

---

## 🚀 Правильный процесс деплоя

### Шаг 1: Копирование файлов на хост в /tmp

```bash
scp templates/dashboard.html user@10.0.88.20:/tmp/
scp templates/base.html user@10.0.88.20:/tmp/
scp templates/vulnerabilities_list.html user@10.0.88.20:/tmp/
scp templates/admin/users.html user@10.0.88.20:/tmp/
scp app.py user@10.0.88.20:/tmp/
scp static/css/animations-enhanced.css user@10.0.88.20:/tmp/
scp static/js/*.js user@10.0.88.20:/tmp/
```

✅ **Выполнено**: Все файлы скопированы в `/tmp` на хосте

---

### Шаг 2: Копирование из /tmp в Docker контейнер

```bash
# HTML Templates
sudo docker cp /tmp/dashboard.html vulnerability-backend:/app/templates/
sudo docker cp /tmp/base.html vulnerability-backend:/app/templates/
sudo docker cp /tmp/vulnerabilities_list.html vulnerability-backend:/app/templates/
sudo docker cp /tmp/users.html vulnerability-backend:/app/templates/admin/

# Python backend
sudo docker cp /tmp/app.py vulnerability-backend:/app/

# CSS
sudo docker cp /tmp/animations-enhanced.css vulnerability-backend:/app/static/css/

# JavaScript
sudo docker cp /tmp/react-bits-vanilla.js vulnerability-backend:/app/static/js/
sudo docker cp /tmp/gsap-animations.js vulnerability-backend:/app/static/js/
sudo docker cp /tmp/particles-config.js vulnerability-backend:/app/static/js/
```

✅ **Выполнено**: Все файлы скопированы в контейнер

---

### Шаг 3: Перезапуск контейнера

```bash
sudo docker restart vulnerability-backend
```

✅ **Выполнено**: Контейнер перезапущен (Up 7 seconds)

---

## 📝 Проверка изменений

### 1. ✅ dashboard.html - Секция "Быстрые действия" только для Admin

**Строка 186**:
```jinja2
{% if session.role == 'admin' %}
<div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
    <!-- Парсеры -->
    <a href="{{ url_for('parsers_page') }}">...</a>
    
    <!-- Управление командой -->
    <a href="{{ url_for('operators_page') }}">...</a>
</div>
{% endif %}
```

**Строка 224**: Закрывающий `{% endif %}`

---

### 2. ✅ vulnerabilities_list.html - Колонка "Оператор" скрыта для User

**Найдено 5 проверок** `{% if session.role == 'admin' %}`:
- Строка: проверка для колонки "Оператор"
- Строка: данные колонки "Оператор"
- Строка: кнопка "ИИ-Паспорт"
- Строка: кнопка "Редактировать"
- Строка: кнопка "Назначить"

---

### 3. ✅ admin/users.html - Форма создания пользователей

Добавлено:
- Кнопка "Добавить пользователя"
- Модальное окно с формой
- JavaScript для AJAX отправки

---

### 4. ✅ app.py - API endpoints

Добавлено:
```python
@app.route('/api/admin/users', methods=['POST'])
def create_user_api():
    # Создание пользователя через AuthService
    
@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def delete_user_api(user_id):
    # Удаление пользователя
```

---

### 5. ✅ Анимации и стили

**CSS**: `/app/static/css/animations-enhanced.css` (14,826 bytes)
**JS**: 
- `/app/static/js/react-bits-vanilla.js` (16,712 bytes)
- `/app/static/js/gsap-animations.js`
- `/app/static/js/particles-config.js`

---

## 🧪 Как проверить результат

### Для User:
1. Войдите как `test@example.com` (роль: user)
2. На Dashboard **НЕ должно быть**:
   - ❌ Плашка "Парсеры уязвимостей"
   - ❌ Плашка "Управление командой"
3. В разделе "Уязвимости" **НЕ должно быть**:
   - ❌ Колонка "Оператор"
   - ❌ Кнопка "Редактировать"
   - ❌ Кнопка "ИИ-Паспорт"
   - ❌ Кнопка "Назначить"
4. **Должны быть доступны**:
   - ✅ Кнопка "Просмотр" (👁️)
   - ✅ Кнопка "Теги" (🏷️)

### Для Admin:
1. Войдите как `admin@example.com` (роль: admin)
2. **Должно быть всё**:
   - ✅ Все плашки на Dashboard
   - ✅ Колонка "Оператор"
   - ✅ Все кнопки действий
   - ✅ Форма создания пользователей в "Управление пользователями"

---

## 🔧 Скрипт для будущих деплоев

Создан: `/scripts/deploy_to_docker.sh`

```bash
#!/bin/bash
# Деплой в Docker контейнер vulnerability-backend

SERVER="10.0.88.20"
PASSWORD="123"
USER="user"
CONTAINER="vulnerability-backend"

export SSHPASS="$PASSWORD"

echo "📦 Копирование файлов на сервер..."
sshpass -e scp -o StrictHostKeyChecking=no templates/*.html $USER@$SERVER:/tmp/
sshpass -e scp -o StrictHostKeyChecking=no app.py $USER@$SERVER:/tmp/
sshpass -e scp -o StrictHostKeyChecking=no static/css/*.css $USER@$SERVER:/tmp/
sshpass -e scp -o StrictHostKeyChecking=no static/js/*.js $USER@$SERVER:/tmp/

echo "🐳 Копирование в Docker контейнер..."
sshpass -e ssh -o StrictHostKeyChecking=no $USER@$SERVER << 'ENDSSH'
echo '123' | sudo -S docker cp /tmp/dashboard.html vulnerability-backend:/app/templates/
echo '123' | sudo -S docker cp /tmp/base.html vulnerability-backend:/app/templates/
echo '123' | sudo -S docker cp /tmp/vulnerabilities_list.html vulnerability-backend:/app/templates/
echo '123' | sudo -S docker cp /tmp/users.html vulnerability-backend:/app/templates/admin/
echo '123' | sudo -S docker cp /tmp/app.py vulnerability-backend:/app/
echo '123' | sudo -S docker cp /tmp/animations-enhanced.css vulnerability-backend:/app/static/css/
echo '123' | sudo -S docker cp /tmp/*.js vulnerability-backend:/app/static/js/
ENDSSH

echo "🔄 Перезапуск контейнера..."
sshpass -e ssh -o StrictHostKeyChecking=no $USER@$SERVER "echo '123' | sudo -S docker restart $CONTAINER"

echo "✅ Деплой завершен!"
unset SSHPASS
```

---

## 📊 Статус деплоя

| Файл | Размер | Дата обновления | Статус |
|------|--------|-----------------|--------|
| `/app/templates/dashboard.html` | 35,794 bytes | Jan 21 23:07 | ✅ Обновлен |
| `/app/templates/base.html` | - | Jan 21 23:07 | ✅ Обновлен |
| `/app/templates/vulnerabilities_list.html` | - | Jan 21 23:07 | ✅ Обновлен |
| `/app/templates/admin/users.html` | - | Jan 21 23:07 | ✅ Обновлен |
| `/app/app.py` | - | Jan 21 23:07 | ✅ Обновлен |
| `/app/static/css/animations-enhanced.css` | 14,826 bytes | Jan 21 23:07 | ✅ Создан |
| `/app/static/js/react-bits-vanilla.js` | 16,712 bytes | Jan 21 23:07 | ✅ Создан |
| `/app/static/js/gsap-animations.js` | - | Jan 21 23:07 | ✅ Создан |
| `/app/static/js/particles-config.js` | - | Jan 21 23:07 | ✅ Создан |

---

## 🎯 Итог

### ✅ Что исправлено:
1. **Нашел правильную директорию**: `/app` внутри Docker контейнера
2. **Скопировал файлы правильно**: через `docker cp`
3. **Перезапустил контейнер**: `docker restart vulnerability-backend`
4. **Проверил изменения**: файлы обновлены, проверки роли на месте

### 🌐 Проверка:
**URL**: http://10.0.88.20:5000

**Ожидаемый результат**:
- User видит только "Просмотр" и "Теги"
- Admin видит все элементы и может создавать пользователей
- Редизайн с анимациями должен работать

---

**Дата**: 2026-01-22  
**Время**: 00:10 UTC  
**Статус**: ✅ ПРАВИЛЬНО ЗАДЕПЛОЕНО В DOCKER  
**Контейнер**: vulnerability-backend (Up 7 seconds)

🎉 **Теперь все изменения применены в правильном месте!**

