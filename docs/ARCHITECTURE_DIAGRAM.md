# Архитектура системы управления уязвимостями с ИИ интеграцией

## Общая схема взаимодействия

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         FRONTEND (10.0.88.10)                           │
│                          Nginx + HTML/JS                                 │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐  │
│  │ Dashboard   │  │Vulnerabilities│  │  Parsers    │  │ AI Dashboard │  │
│  │             │  │   List       │  │   Page      │  │              │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬───────┘  │
│         │                │                 │                 │          │
└─────────┼────────────────┼─────────────────┼─────────────────┼──────────┘
          │                │                 │                 │
          │                │                 │                 │
          │ HTTP/HTTPS     │                 │                 │
          │                │                 │                 │
          ▼                ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         BACKEND (10.0.88.20)                            │
│                          Flask API Server                               │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      app.py (Flask Routes)                        │  │
│  │                                                                   │  │
│  │  /api/dashboard-stats                                            │  │
│  │  /api/vulnerabilities                                            │  │
│  │  /api/parsers/run-all                                            │  │
│  │  /api/ai/analyze          ────────┐                              │  │
│  │  /api/ai/batch-analyze    ────────┤                              │  │
│  │  /api/ai/classify/<id>    ────────┼────────┐                     │  │
│  │  /api/ai/statistics       ────────┘        │                     │  │
│  │  /api/ai/keywords                          │                     │  │
│  │  /api/ai/train                              │                     │  │
│  │  /api/ai/generate-passport/<id>             │                     │  │
│  └─────────────────────────────────────────────┼─────────────────────┘  │
│                                                 │                        │
│  ┌──────────────────────────────────────────────▼────────────────────┐  │
│  │         ai_integration_service.py                                  │  │
│  │                                                                     │  │
│  │  class AIIntegrationService:                                       │  │
│  │    - ai_api_url = "http://10.0.88.25:8000"                        │  │
│  │    - ai_api_available: bool                                        │  │
│  │                                                                     │  │
│  │    def analyze_vulnerability(data):                                │  │
│  │      1. Проверка доступности внешнего AI API                       │  │
│  │      2. POST http://10.0.88.25:8000/api/analyze                   │  │
│  │      3. Fallback на локальные анализаторы (если доступны)          │  │
│  │                                                                     │  │
│  │    def batch_analyze(vulnerability_ids):                           │  │
│  │      - Для каждого ID: classify_vulnerability()                    │  │
│  │      - Получение данных из БД                                      │  │
│  │      - Анализ через AI API                                         │  │
│  │      - Сохранение результатов                                      │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                 │                        │
│  ┌──────────────────────────────────────────────▼────────────────────┐  │
│  │              Database Layer (models/)                              │  │
│  │  - DatabaseManager                                                 │  │
│  │  - LegacyVulnerabilityRepository                                   │  │
│  │  - PostgresVulnerabilityRepository                                 │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────┬─────────────────────────────────────┘
                                      │
                                      │ PostgreSQL Protocol
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      DATABASE (10.0.88.11)                              │
│                         PostgreSQL                                      │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐  │
│  │   turn      │  │   tagcve    │  │   users     │  │  operators   │  │
│  │ (уязвимости)│  │   (теги)    │  │  (пользоват.)│  │ (операторы)  │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └──────────────┘  │
│                                                                          │
│  ┌─────────────┐  ┌─────────────┐                                      │
│  │ai_keywords  │  │ai_training_ │  (если используются)                 │
│  │             │  │data         │                                      │
│  └─────────────┘  └─────────────┘                                      │
└─────────────────────────────────────────────────────────────────────────┘

                                      │
                                      │ HTTP REST API
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    AI SERVICE SERVER (10.0.88.25)                       │
│                      Flask API (Port 8000)                              │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    ai_service_server.py                           │  │
│  │                                                                   │  │
│  │  Endpoints:                                                       │  │
│  │    GET  /health              → Проверка здоровья                 │  │
│  │    POST /api/analyze         → Анализ одной уязвимости           │  │
│  │    POST /api/batch-analyze   → Пакетный анализ                   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                      │                                  │
│  ┌──────────────────────────────────▼──────────────────────────────┐  │
│  │                    AI Models (scikit-learn)                      │  │
│  │                                                                   │  │
│  │  ┌─────────────────┐         ┌──────────────────┐               │  │
│  │  │ ai_cve_detector │         │tfidf_vectorizer  │               │  │
│  │  │   .pkl          │         │     .pkl         │               │  │
│  │  │                 │         │                  │               │  │
│  │  │ LogisticRegression │      │ TfidfVectorizer  │               │  │
│  │  └─────────────────┘         └──────────────────┘               │  │
│  │         │                              │                         │  │
│  │         └──────────────┬───────────────┘                         │  │
│  │                        │                                         │  │
│  │                        ▼                                         │  │
│  │              [Text → Vector → Prediction]                        │  │
│  │              Возврат: is_ai_related, confidence                  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  Models Location: ~/mnist_visualization/                                 │
│  Service: systemd (ai_service.service)                                  │
└─────────────────────────────────────────────────────────────────────────┘

                                      │
                                      │ HTTP REST API
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       PARSERS (10.0.88.23)                              │
│                    Асинхронные парсеры                                  │
│                                                                          │
│  - parsing_manager.py                                                   │
│  - unified_parser_service.py                                            │
│  - html_vulnerability_parser.py                                         │
│  - vendor_parsers.py                                                    │
│  - nvd_integration_service.py                                           │
│                                                                          │
│  Парсинг → Сохранение в БД (10.0.88.11)                                │
└─────────────────────────────────────────────────────────────────────────┘
```

## Поток данных при анализе уязвимости

### 1. Анализ одной уязвимости

```
Frontend (JS)
    │
    │ POST /api/ai/analyze
    │ { vulnerability_data: {...} }
    ▼
Backend: app.py
    │
    │ ai_integration_service.analyze_vulnerability(data)
    ▼
AIIntegrationService
    │
    │ Проверка: ai_api_available?
    │
    ├─→ ДА: POST http://10.0.88.25:8000/api/analyze
    │       │
    │       ▼
    │   AI Service Server
    │       │
    │       ├─→ Загрузка моделей (joblib)
    │       ├─→ Векторизация текста (TF-IDF)
    │       ├─→ Предсказание (LogisticRegression)
    │       │
    │       ▼
    │   { is_ai_related: bool, confidence: float }
    │
    └─→ НЕТ: Fallback на локальные анализаторы
            (если доступны) или базовый результат
```

### 2. Пакетный анализ (batch-analyze)

```
Frontend (JS)
    │
    │ POST /api/ai/batch-analyze
    │ { vulnerability_ids: [1, 2, 3, ...] }  ← ВОТ ГДЕ ОШИБКА!
    ▼
Backend: app.py
    │
    │ Проверка: vulnerability_ids есть и не пустой?
    │   ├─→ НЕТ: Возврат ошибки "vulnerability_ids required"
    │   └─→ ДА: Продолжение
    │
    │ ai_integration_service.batch_analyze(vulnerability_ids)
    ▼
AIIntegrationService.batch_analyze()
    │
    │ Для каждого vulnerability_id:
    │   │
    │   ├─→ classify_vulnerability(id)
    │   │     │
    │   │     ├─→ Получение данных из БД
    │   │     ├─→ analyze_vulnerability(data)
    │   │     │     │
    │   │     │     └─→ AI API или fallback
    │   │     │
    │   │     └─→ Сохранение результата в БД
    │   │
    │   └─→ Сбор статистики
    │
    ▼
{ total: N, ai_related: M, percentage: X%, results: [...] }
```

## Зависимости между компонентами

### Backend (10.0.88.20)
```
services/backend/app.py
    ├─→ services/ai_integration_service.py
    │       ├─→ requests (HTTP клиент)
    │       ├─→ models/database.py (DatabaseManager)
    │       ├─→ config.py (Config)
    │       │
    │       └─→ Опционально:
    │           ├─→ services/parsers/ai_analyzer.py (если доступен)
    │           └─→ services/ai_tagger_service.py (если доступен)
    │
    ├─→ models/*.py
    └─→ utils/*.py
```

### AI Service Server (10.0.88.25)
```
services/ai_service_server.py
    ├─→ flask (веб-сервер)
    ├─→ flask_cors (CORS поддержка)
    ├─→ joblib (загрузка моделей)
    ├─→ sklearn (scikit-learn для моделей)
    │
    └─→ Модели:
        ├─→ ~/mnist_visualization/ai_cve_detector.pkl
        └─→ ~/mnist_visualization/tfidf_vectorizer.pkl
```

## Основные проблемы и решения

### Проблема: "vulnerability_ids required"

**Причина:**
- Frontend вызывает `/api/ai/batch-analyze` без параметра `vulnerability_ids`
- Или передает пустой массив `[]`
- Или передает `null`/`undefined`

**Решение:**
1. ✅ Улучшена валидация в Backend (добавлены проверки типа)
2. ❓ Нужно проверить Frontend код, который вызывает этот endpoint

**Где может вызываться:**
- AI Dashboard страница (`/ai/dashboard`)
- Страница статистики (`/ai/statistics`)
- Кнопка "Анализировать все" или "Batch Analyze"

### Взаимодействие с ИИ системой

1. **Инициализация (при старте Backend):**
   ```
   AIIntegrationService.__init__()
   ├─→ Проверка доступности AI API
   │     GET http://10.0.88.25:8000/health
   │     ├─→ 200 OK: ai_api_available = True
   │     └─→ Error: ai_api_available = False
   │
   └─→ Установка ai_api_url = "http://10.0.88.25:8000"
   ```

2. **Анализ уязвимости:**
   ```
   analyze_vulnerability(vulnerability_data)
   ├─→ Если ai_api_available:
   │     POST http://10.0.88.25:8000/api/analyze
   │     Body: { title, description, cve_id }
   │     Response: { is_ai_related, confidence, ... }
   │
   └─→ Иначе (fallback):
         └─→ Локальные анализаторы или базовый результат
   ```

3. **AI Service Server обработка:**
   ```
   POST /api/analyze
   ├─→ Загрузка TF-IDF векторизатора (если еще не загружен)
   ├─→ Векторизация текста: vectorizer.transform([text])
   ├─→ Предсказание: model.predict(vector)
   ├─→ Вероятность: model.predict_proba(vector)
   │
   └─→ Response: { is_ai_related: bool, confidence: float }
   ```

## Конфигурация и сетевые соединения

```
Frontend (10.0.88.10)
    │
    └─→ Backend (10.0.88.20:5000) ───┐
                                      │
Backend (10.0.88.20)                  │
    │                                 │
    ├─→ Database (10.0.88.11:5432)   │
    │                                 │
    └─→ AI Service (10.0.88.25:8000) ─┘

AI Service (10.0.88.25)
    │
    └─→ Модели: ~/mnist_visualization/*.pkl
```

## Статус компонентов

- ✅ **Frontend**: Работает (Nginx на 10.0.88.10)
- ✅ **Backend**: Работает (Flask на 10.0.88.20:5000)
- ✅ **Database**: Работает (PostgreSQL на 10.0.88.11:5432)
- ✅ **AI Service**: Работает (Flask на 10.0.88.25:8000)
- ✅ **Parsers**: Работают (на 10.0.88.23)

