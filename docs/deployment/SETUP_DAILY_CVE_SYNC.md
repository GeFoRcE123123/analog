# Настройка ежедневного автоматического скачивания CVE с cve.org

## 📋 Описание

Настройка автоматического ежедневного скачивания всех ~380,000 CVE записей с официального источника [cve.org](https://www.cve.org/Downloads).

## 🚀 Быстрая настройка

### 1. Настройка cron для ежедневной синхронизации

```bash
# Подключаемся к Backend VM или Parsers VM
ssh user@10.0.88.20  # или 10.0.88.23 для Parsers

# Редактируем crontab
crontab -e

# Добавляем задачу на ежедневный запуск в 3:00 ночи
0 3 * * * cd /home/user/vulnerability_manager && /usr/bin/python3 services/daily_cve_sync.py >> /var/log/cve_sync.log 2>&1
```

### 2. Первичная полная синхронизация (опционально)

Для первоначальной загрузки всех ~380,000 CVE:

```bash
# На Backend VM или Parsers VM
cd /home/user/vulnerability_manager
python3 services/full_cve_sync.py
```

**Время выполнения:** Несколько часов (зависит от скорости интернета и БД)

## 📊 Проверка работы

### Проверка логов

```bash
# Логи ежедневной синхронизации
tail -f /app/logs/daily_cve_sync.log

# Или если используется cron
tail -f /var/log/cve_sync.log
```

### Проверка количества CVE в БД

```bash
# На Database VM
ssh user@10.0.88.11
echo '123' | sudo -S docker exec vulnerability_db psql -U admin -d vuln_db -c "SELECT COUNT(*) FROM turn;"
```

## ⚙️ Альтернативный вариант: systemd timer

Если предпочитаете systemd:

### 1. Создаем service файл

```bash
sudo nano /etc/systemd/system/daily-cve-sync.service
```

Содержимое:

```ini
[Unit]
Description=Daily CVE synchronization from cve.org
After=network.target

[Service]
Type=oneshot
User=user
WorkingDirectory=/home/user/vulnerability_manager
ExecStart=/usr/bin/python3 services/daily_cve_sync.py
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 2. Создаем timer файл

```bash
sudo nano /etc/systemd/system/daily-cve-sync.timer
```

Содержимое:

```ini
[Unit]
Description=Daily CVE synchronization timer
Requires=daily-cve-sync.service

[Timer]
OnCalendar=daily
OnCalendar=*-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

### 3. Активируем timer

```bash
sudo systemctl daemon-reload
sudo systemctl enable daily-cve-sync.timer
sudo systemctl start daily-cve-sync.timer
sudo systemctl status daily-cve-sync.timer
```

### 4. Проверка статуса

```bash
# Статус timer
sudo systemctl status daily-cve-sync.timer

# Список всех timers
systemctl list-timers

# Запуск вручную для тестирования
sudo systemctl start daily-cve-sync.service
```

## 🔧 Настройки

### Изменение времени запуска (cron)

```bash
crontab -e

# Примеры:
# Каждый день в 2:00 ночи
0 2 * * * ...

# Каждый день в 4:00 утра
0 4 * * * ...

# Каждые 6 часов
0 */6 * * * ...
```

### Изменение времени запуска (systemd timer)

Отредактируйте `/etc/systemd/system/daily-cve-sync.timer`:

```ini
[Timer]
OnCalendar=daily
OnCalendar=*-*-* 02:00:00  # Изменить время на 2:00
Persistent=true
```

Затем:

```bash
sudo systemctl daemon-reload
sudo systemctl restart daily-cve-sync.timer
```

## 📁 Структура файлов

```
services/
├── cve_org_downloader.py          # Загрузчик репозитория CVE
├── cve_org_integration_service.py # Интеграционный сервис
├── daily_cve_sync.py              # Скрипт для ежедневной синхронизации
└── full_cve_sync.py               # Скрипт для полной синхронизации
```

## ✅ Результат

После настройки:

1. ✅ Ежедневное автоматическое обновление CVE данных
2. ✅ ~380,000 CVE записей в базе данных
3. ✅ Все данные в формате JSON 5.x
4. ✅ Логирование всех операций

## ⚠️ Требования

- `git` установлен в системе
- Достаточно места на диске (~1-2 GB)
- Стабильное интернет-соединение
- Доступ к GitHub (github.com)

## 🔍 Мониторинг

### Проверка последнего запуска (cron)

```bash
grep "CVE" /var/log/cron
# или
journalctl -u cron | grep "cve_sync"
```

### Проверка последнего запуска (systemd)

```bash
sudo journalctl -u daily-cve-sync.service -n 100
sudo journalctl -u daily-cve-sync.timer -n 50
```

