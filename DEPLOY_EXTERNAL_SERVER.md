# Инструкция по деплою исправлений дашборда на внешний сервер

## Сервер: 217.25.230.15:8080

## Файлы для деплоя:

1. `services/backend/app.py` → `/path/to/vulnerability_manager/app.py`
2. `templates/dashboard.html` → `/path/to/vulnerability_manager/templates/dashboard.html`
3. `static/css/main.css` → `/path/to/vulnerability_manager/static/css/main.css`

## Команды для деплоя:

```bash
# 1. Подключитесь к серверу
ssh user@217.25.230.15

# 2. Найдите директорию проекта
find /home -name "app.py" -path "*/vulnerability_manager/*" 2>/dev/null | head -1 | xargs dirname
# или
ls -d ~/vulnerability_manager 2>/dev/null || ls -d /opt/vulnerability_manager 2>/dev/null

# 3. Скопируйте файлы (с вашего локального компьютера)
scp services/backend/app.py user@217.25.230.15:/path/to/vulnerability_manager/app.py
scp templates/dashboard.html user@217.25.230.15:/path/to/vulnerability_manager/templates/dashboard.html
scp static/css/main.css user@217.25.230.15:/path/to/vulnerability_manager/static/css/main.css

# 4. Перезапустите сервис
# На сервере:
sudo systemctl restart vulnerability-manager-backend
# или
sudo kill -HUP $(ps aux | grep '[g]unicorn' | awk '{print $2}' | head -1)
```

## Альтернатива: Используйте скрипт с правильными учетными данными

Отредактируйте `scripts/deploy_dashboard_fix_external.sh` и укажите правильные:
- USER (имя пользователя)
- PASSWORD (пароль)

Затем запустите:
```bash
./scripts/deploy_dashboard_fix_external.sh
```

## Что было исправлено:

1. ✅ Добавлен фильтр форматирования чисел (113589 → 113 589)
2. ✅ Улучшены стили карточек статистики (тени, градиенты)
3. ✅ Исправлено отображение прогресс-бара
4. ✅ Улучшена типографика и читаемость

