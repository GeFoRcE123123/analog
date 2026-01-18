# 🔗 Интеграция ML платформы с k8s-worker

## 📋 Обзор

Интеграция ML платформы, работающей на VM `k8s-worker` (10.0.88.25), с фронтендом проекта для управления ИИ-анализом уязвимостей в реальном времени.

## 🏗️ Архитектура

```
┌─────────────────┐         ┌──────────────────┐         ┌──────────────┐
│   Frontend      │ ──────> │  Flask Backend   │ ──────> │ ML Platform  │
│  (10.0.88.10)   │         │  (10.0.88.20)    │         │ (k8s-worker) │
│                 │         │                  │         │ (10.0.88.25) │
└─────────────────┘         └──────────────────┘         └──────────────┘
                                      │                           │
                                      └──────────> БД (10.0.88.11)
```

## 🔌 Компоненты

### 1. ML Platform Client (`services/ml_platform_client.py`)

Клиент для взаимодействия с ML платформой на k8s-worker:

- **SSH подключение**: Выполнение команд на VM
- **HTTP API**: Взаимодействие с FastAPI сервером (порт 8000)
- **БД интеграция**: Сохранение результатов в БД проекта

**Настройки подключения:**
- VM: `10.0.88.25`
- User: `k8s-worker`
- Password: `k8s-worker`
- ML API: `http://10.0.88.25:8000`

### 2. Flask API Endpoints

#### Проверка подключения
```
GET /api/ml-platform/connection
```

#### ИИ-анализ
```
POST /api/ai/batch-analyze
Body: { "vulnerability_ids": [...] }
```

#### Статистика
```
GET /api/ai/statistics
```

#### Обучение модели
```
POST /api/ml-platform/training/start
GET  /api/ml-platform/training/status/<task_id>
GET  /api/ml-platform/training/history
```

#### Мониторинг сайтов
```
POST /api/ai/monitor-start
POST /api/ai/monitor-stop
GET  /api/ai/monitor-status
```

#### Паспорта CVE
```
GET /api/ml-platform/passports/<cve_id>
GET /api/ml-platform/passports?limit=100
```

### 3. Frontend страницы

#### `/ai/dashboard` - Главная страница ИИ-анализа
- Статус подключения к ML платформе
- Кнопки управления:
  - 🚀 Запустить ИИ-анализ
  - 📊 Статистика по ключевым словам
  - 🎓 Управление обучением (admin)
  - 🔍 Мониторинг сайтов (admin)
  - 📄 Паспорта уязвимостей

#### `/ai/statistics` - Статистика
- Общая статистика по анализу
- Распределение по категориям
- Данные из ML платформы

#### `/ai/training` - Управление обучением
- Запуск обучения модели
- Параметры обучения (эпохи, batch size, learning rate)
- История обучения
- Статус задач

#### `/ai/monitoring` - Мониторинг сайтов
- Запуск/остановка мониторинга
- Список мониторируемых сайтов
- Статус мониторинга в реальном времени

#### `/ai/passports` - Паспорта уязвимостей
- Поиск паспорта по CVE ID
- Список всех паспортов
- Детальная информация о паспорте

## 🔧 Установка

### 1. Установка зависимостей

```bash
pip install -r requirements.txt
```

Добавлено:
- `paramiko>=3.0.0` - для SSH подключения

### 2. Настройка ML платформы на k8s-worker

Убедитесь, что на k8s-worker запущен FastAPI сервер:

```bash
# На k8s-worker
cd /path/to/ml_platform
uvicorn ml_platform.api.server:app --host 0.0.0.0 --port 8000
```

### 3. Проверка подключения

```bash
# Проверка SSH
ssh k8s-worker@10.0.88.25

# Проверка HTTP API
curl http://10.0.88.25:8000/health
```

## 📊 Использование

### Запуск ИИ-анализа

1. Откройте `/ai/dashboard`
2. Проверьте статус подключения к ML платформе
3. Нажмите "🚀 Запустить ИИ-анализ"
4. Анализ запустится на k8s-worker
5. Результаты сохранятся в БД проекта

### Управление обучением

1. Откройте `/ai/training` (требуется admin)
2. Настройте параметры обучения
3. Нажмите "🚀 Запустить обучение"
4. Следите за статусом через историю обучения

### Мониторинг сайтов

1. Откройте `/ai/monitoring` (требуется admin)
2. Введите список сайтов для мониторинга
3. Нажмите "▶️ Запустить мониторинг"
4. Статус обновляется автоматически

### Просмотр паспортов

1. Откройте `/ai/passports`
2. Введите CVE ID для поиска
3. Или загрузите список всех паспортов

## 🔄 Поток данных

### ИИ-анализ уязвимостей

```
1. Frontend → POST /api/ai/batch-analyze
2. Flask → ml_platform_client.start_ai_analysis()
3. Client → Получение данных из БД проекта
4. Client → POST /security/ai/batch-analyze (ML Platform)
5. ML Platform → Анализ уязвимостей
6. ML Platform → Возврат результатов
7. Client → Сохранение результатов в БД проекта
8. Flask → Возврат результата во Frontend
```

### Обучение модели

```
1. Frontend → POST /api/ml-platform/training/start
2. Flask → ml_platform_client.start_training()
3. Client → POST /training/start (ML Platform)
4. ML Platform → Запуск обучения
5. ML Platform → Возврат task_id
6. Frontend → Мониторинг через GET /api/ml-platform/training/status/<task_id>
```

## 🗄️ Интеграция с БД

ML платформа подключается к БД проекта (10.0.88.11) через:

1. **Чтение данных**: Получение уязвимостей из `turn` таблицы
2. **Сохранение результатов**: Обновление `turn.etc` с результатами анализа

```python
# Пример сохранения результатов
UPDATE turn 
SET etc = jsonb_set(
    COALESCE(etc, '{}'::jsonb),
    '{ai_analysis}',
    '{"is_ai_related": true, "confidence": 0.85, ...}'::jsonb
)
WHERE id = %s
```

## 🔍 Мониторинг

### Проверка статуса ML платформы

```bash
# Через API
curl http://10.0.88.20:5000/api/ml-platform/connection

# Через SSH
ssh k8s-worker@10.0.88.25 "systemctl status ml-platform"
```

### Логи

- Flask: `/var/log/vulnerability_manager/backend.log`
- ML Platform: `/var/log/ml_platform/training.log` (на k8s-worker)

## ⚠️ Устранение неполадок

### ML платформа недоступна

1. Проверьте SSH подключение:
   ```bash
   ssh k8s-worker@10.0.88.25
   ```

2. Проверьте HTTP API:
   ```bash
   curl http://10.0.88.25:8000/health
   ```

3. Проверьте, что FastAPI сервер запущен на k8s-worker

### Ошибки подключения к БД

1. Проверьте настройки в `config.py`
2. Убедитесь, что БД доступна с k8s-worker (если нужно)

### Ошибки анализа

1. Проверьте логи ML платформы
2. Убедитесь, что данные уязвимостей корректны
3. Проверьте формат запросов к API

## 📖 Дополнительная документация

- `ml_platform/README.md` - Документация ML платформы
- `ml_platform/SECURITY_PLATFORM.md` - Документация модуля безопасности
- `ml_backup/README.md` - Информация о резервных копиях

## ✅ Готово к использованию

Интеграция полностью реализована и готова к использованию. Все функции доступны через фронтенд с кнопками управления.

