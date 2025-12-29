# Интеграция автоматического скачивания CVE с cve.org

## 📋 Описание

Реализован сервис для автоматического ежедневного скачивания всех ~380,000 CVE записей с официального источника [cve.org](https://www.cve.org/Downloads).

## 🔧 Компоненты

### 1. `CVEOrgDownloader` (`services/cve_org_downloader.py`)
- Клонирование GitHub репозитория `CVEProject/cvelistV5`
- Обновление репозитория (git pull)
- Итерация по всем CVE JSON файлам
- Загрузка и обработка CVE записей

### 2. `CVEOrgIntegrationService` (`services/cve_org_integration_service.py`)
- Полная синхронизация всех CVE
- Инкрементальная синхронизация (обновление)
- Пакетная обработка и сохранение в БД
- Интеграция с существующей системой

### 3. Скрипты автоматизации
- `daily_cve_sync.py` - ежедневная инкрементальная синхронизация
- `full_cve_sync.py` - полная синхронизация всех CVE (первичная загрузка)

## 🚀 Использование

### Первичная загрузка всех CVE (~380,000)

```bash
# На Backend VM или Parsers VM
cd /path/to/vulnerability_manager
python3 services/full_cve_sync.py
```

**Время выполнения:** Несколько часов (зависит от скорости интернета и БД)

### Ежедневное автоматическое обновление

#### Вариант 1: Через cron (рекомендуется)

```bash
# Редактируем crontab
crontab -e

# Добавляем задачу на ежедневный запуск в 3:00 ночи
0 3 * * * cd /path/to/vulnerability_manager && /usr/bin/python3 services/daily_cve_sync.py >> /var/log/cve_sync.log 2>&1
```

#### Вариант 2: Через systemd timer

Создаем файл `/etc/systemd/system/daily-cve-sync.service`:

```ini
[Unit]
Description=Daily CVE synchronization from cve.org
After=network.target

[Service]
Type=oneshot
User=user
WorkingDirectory=/path/to/vulnerability_manager
ExecStart=/usr/bin/python3 services/daily_cve_sync.py
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Создаем файл `/etc/systemd/system/daily-cve-sync.timer`:

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

Активируем:

```bash
sudo systemctl enable daily-cve-sync.timer
sudo systemctl start daily-cve-sync.timer
sudo systemctl status daily-cve-sync.timer
```

## 📊 Структура данных

CVE данные хранятся в формате JSON 5.x согласно официальной схеме:
- Репозиторий: `https://github.com/CVEProject/cvelistV5`
- Формат: CVE JSON 5.x
- Структура: `cves/YYYY/XXXXNNNN.json`

## 🔄 Процесс синхронизации

1. **Обновление репозитория:** `git pull` для получения последних изменений
2. **Итерация по файлам:** Рекурсивный обход всех JSON файлов
3. **Парсинг:** Использование `CVEJSON5Adapter` для преобразования в внутренний формат
4. **Сохранение:** Пакетная вставка в БД через `LegacyVulnerabilityRepository`

## ⚙️ Конфигурация

В `CVEOrgIntegrationService`:

```python
self.config = {
    'batch_size': 1000,      # Размер пакета для сохранения
    'max_workers': 10,       # Количество потоков (пока не используется)
    'update_on_start': True  # Обновлять репозиторий при старте
}
```

## 📁 Хранение данных

Репозиторий CVE клонируется в:
- Путь по умолчанию: `/tmp/cve_data/cvelistV5`
- Размер: ~500MB - 1GB (в зависимости от истории)

## 🔍 Мониторинг

Логи сохраняются в:
- `daily_cve_sync.py`: `/app/logs/daily_cve_sync.log`
- `full_cve_sync.py`: `/app/logs/full_cve_sync.log`

## ✅ Интеграция с UnifiedParserService

CVE.org сервис интегрирован в `UnifiedParserService` и доступен через параметр `enable_cve_org` (будет добавлен в следующем обновлении).

## 🎯 Результат

После синхронизации в базе данных будет доступно:
- ~380,000 CVE записей
- Все данные в формате JSON 5.x
- Ежедневное автоматическое обновление

## ⚠️ Требования

- `git` должен быть установлен в системе
- Достаточно места на диске (~1-2 GB для репозитория)
- Стабильное интернет-соединение
- Доступ к GitHub (github.com)

