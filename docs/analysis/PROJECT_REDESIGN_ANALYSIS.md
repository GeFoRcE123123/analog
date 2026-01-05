# 🏗️ ПОЛНЫЙ АНАЛИЗ ПРОЕКТА ДЛЯ РЕДИЗАЙНА

## 📋 СОДЕРЖАНИЕ

1. [Анализ HTML-файлов](#анализ-html-файлов)
2. [Архитектура связей](#архитектура-связей)
3. [Функциональность компонентов](#функциональность-компонентов)
4. [Зависимости и связи](#зависимости-и-связи)
5. [Рекомендации по улучшению](#рекомендации-по-улучшению)

---

## 📄 АНАЛИЗ HTML-ФАЙЛОВ

### 1. `base.html` — Базовый шаблон

**Описание:**
- Базовый шаблон для всех страниц приложения
- Содержит навигационную панель, общие стили (Tailwind CSS, Font Awesome), и структуру страницы
- Определяет общий layout: header с навигацией, основной контент (`{% block content %}`), и скрипты

**Информативность:**
- **Навигация**: Главное меню с ссылками на все разделы (Дашборд, Уязвимости, Операторы, Парсеры, ИИ-Анализ, Проверка, Аналитика)
- **Пользовательское меню**: Выпадающее меню с профилем, назначениями, статистикой, управлением пользователями (для админов)
- **Аутентификация**: Проверка `session.user_id` и `session.role` для отображения элементов
- **Flash-сообщения**: Отображение уведомлений (success, error, info)

**Важность:** ⭐⭐⭐⭐⭐ **КРИТИЧЕСКАЯ** — все страницы наследуются от этого шаблона

**Связи с API:**
- Не использует прямые API-вызовы
- Использует Jinja2 `url_for()` для генерации ссылок
- Содержит JavaScript для мобильного меню (Alpine.js)

**Используемые функции:**
- `url_for()` — генерация URL для маршрутов Flask
- `session` — доступ к данным сессии
- `get_flashed_messages()` — получение flash-сообщений
- Alpine.js для выпадающих меню

**Взаимодействие с backend:**
- Рендерится на backend через Flask `render_template()`
- Все маршруты определяются в `services/backend/app.py`

---

### 2. `dashboard.html` — Главная панель управления

**Описание:**
- Главная страница системы — точка входа для пользователей
- Отображает статистику по уязвимостям, операторам, и быстрые действия
- Показывает последние уязвимости и статус операторов

**Информативность:**
- **Статистика**: 4 карточки (Всего уязвимостей, Высокий риск, Новые, Завершено) — данные из `stats` (передается из backend)
- **Последние уязвимости**: Список из 5 последних уязвимостей (передается из backend как `vulnerabilities`)
- **Статус операторов**: Карточки операторов с метриками (только для админов)
- **Мои уязвимости**: Для обычных пользователей показываются только назначенные им уязвимости

**Важность:** ⭐⭐⭐⭐⭐ **КЛЮЧЕВАЯ** — основная точка входа в систему

**Связи с API:**
- `fetch('/api/start-parsing')` — запуск парсинга уязвимостей
- `EventSource('/api/parsing-progress')` — Server-Sent Events для отслеживания прогресса парсинга
- `EventSource('/api/live-vulnerabilities')` — обновление уязвимостей в реальном времени
- `fetch('/api/parsing-status')` — проверка статуса парсинга
- `fetch('/assign-vulnerabilities')` — массовое назначение уязвимостей

**Связи с backend:**
- Маршрут: `@app.route('/dashboard')` в `services/backend/app.py`
- Данные передаются через `render_template('dashboard.html', stats=stats, vulnerabilities=vulnerabilities, operators=operators, my_vulnerabilities=my_vulnerabilities)`
- Статистика формируется через `get_dashboard_stats()` на backend

**Используемые функции:**
- JavaScript функции: `startParsing()`, `trackParsingProgress()`, `updateVulnerabilitiesList()`, `showNotification()`
- SSE (Server-Sent Events) для real-time обновлений

---

### 3. `vulnerabilities_list.html` — Список уязвимостей

**Описание:**
- Основная страница для просмотра, фильтрации, и управления уязвимостями
- Таблица с пагинацией, фильтрами по статусу/уровню риска, поиском
- Модальные окна для просмотра деталей, редактирования, назначения операторов

**Информативность:**
- **Статистика**: 6 карточек (Всего, Высокий риск, Новые, В работе, Завершено, Всего страниц)
- **Таблица уязвимостей**: Колонки: Название (CVE ID + title), Описание, Уровень риска, Статус, CVSS, Оператор, Действия
- **Фильтры**: Поиск по названию, фильтры по статусу, уровню риска, встроенные фильтры в заголовках таблицы
- **Детали уязвимости**: Модальное окно с полной информацией, включая NVD-поля (CVSS vectors, EPSS, CWE, affected products, references, weaknesses, configurations)

**Важность:** ⭐⭐⭐⭐⭐ **КЛЮЧЕВАЯ** — основная функциональность системы

**Связи с API:**
- `fetch('/api/vulnerabilities?page=1&per_page=50&status=...&severity=...&search=...')` — получение списка уязвимостей с пагинацией
- `fetch('/get-vulnerability/<id>')` — получение деталей уязвимости (включая NVD-поля)
- `fetch('/api/operators')` — получение списка операторов
- `fetch('/api/assign-operator')` — назначение оператора уязвимости
- `fetch('/api/unassign-vulnerability')` — снятие назначения
- `fetch('/update-vulnerability')` — обновление данных уязвимости
- `fetch('/api/operator-workload/<id>')` — получение нагрузки оператора

**Связи с backend:**
- Маршрут: `@app.route('/vulnerabilities')` в `services/backend/app.py`
- Данные: `vulnerabilities, operators, total_count, page, per_page, total_pages` через `get_vulnerabilities_with_operators()`
- Фильтрация и пагинация выполняются на backend через `VulnerabilityService`

**Используемые функции:**
- JavaScript: `showVulnerabilityDetails()`, `editVulnerability()`, `assignOperator()`, `unassignOperator()`, `updateVulnerability()`, `sortTable()`, `applyFilters()`
- Модальные окна для просмотра/редактирования
- Real-time обновление через SSE (если включено)

---

### 4. `operators.html` — Управление операторами

**Описание:**
- Страница управления операторами (только для админов)
- Отображает карточки операторов с метриками, назначенными уязвимостями, и действиями
- Возможность создания операторов, назначения уязвимостей, экспорта данных

**Информативность:**
- **Карточки операторов**: Имя, email, уровень опыта, текущая метрика, нагрузка, список назначенных уязвимостей
- **Статистика по оператору**: Количество назначенных уязвимостей, уровень завершенности
- **Действия**: Назначить уязвимости, экспорт уязвимостей оператора

**Важность:** ⭐⭐⭐⭐ **ВЫСОКАЯ** — ключевая страница для админов

**Связи с API:**
- `fetch('/assign-vulnerabilities')` — массовое назначение уязвимостей оператору
- Данные передаются через `render_template()` из backend (список операторов с назначенными уязвимостями)

**Связи с backend:**
- Маршрут: `@app.route('/operators')` в `services/backend/app.py`
- Данные: `operators` через `OperatorService.get_all_operators()` с загруженными `assigned_vulnerabilities`
- Создание оператора: `@app.route('/create-operator', methods=['POST'])`
- Экспорт: `@app.route('/export/operator-vulnerabilities')`, `@app.route('/export/operator/<id>')`

**Используемые функции:**
- JavaScript: `openCreateOperatorModal()`, `assignVulnerabilities()`
- Модальное окно для создания оператора

---

### 5. `parsers.html` — Управление парсерами

**Описание:**
- Страница для управления парсерами уязвимостей (только для админов)
- Запуск всех парсеров одной кнопкой, расширенные настройки (NVD, Legacy парсеры)
- Отображение статистики парсинга, истории, прогресса в реальном времени

**Информативность:**
- **Статистика**: 4 карточки (Всего в БД, Спарсено, Сохранено, Ошибок)
- **Настройки парсеров**: Toggle для NVD парсера (с настройкой дней), Legacy парсеры (17 источников с чекбоксами)
- **Прогресс**: Progress bar, детали выполнения, список ошибок

**Важность:** ⭐⭐⭐⭐ **ВЫСОКАЯ** — ключевая страница для админов (источник данных)

**Связи с API:**
- `fetch('/api/parsers/stats')` — получение статистики парсинга
- `fetch('/api/parsers/run-all', { method: 'POST', body: JSON.stringify({ enable_nvd: ..., enable_legacy_parsers: ..., legacy_parser_sources: [...] }) })` — запуск всех парсеров
- `fetch('/api/parsers/history?limit=1')` — получение истории парсинга
- Данные передаются через `render_template()` (статистика из БД)

**Связи с backend:**
- Маршрут: `@app.route('/parsers')` в `services/backend/app.py`
- API маршрут: `@app.route('/api/parsers/run-all', methods=['POST'])` вызывает `UnifiedParserService.parse_all()`
- Парсеры сохраняют данные напрямую в БД через `LegacyVulnerabilityRepository` или `PostgresVulnerabilityRepository`

**Используемые функции:**
- JavaScript: `startAllParsers()`, `toggleAdvancedSettings()`, `getParserSettings()`, `updateStats()`
- Real-time обновление статистики через polling

---

### 6. `profile.html` — Профиль пользователя

**Описание:**
- Страница профиля пользователя
- Отображает информацию о пользователе, статистику по назначенным уязвимостям, список уязвимостей

**Информативность:**
- **Профиль**: Имя, email, роль (из `session`)
- **Статистика**: 3 карточки (Назначено, В процессе, Завершено)
- **Список уязвимостей**: Все назначенные пользователю уязвимости

**Важность:** ⭐⭐⭐ **СРЕДНЯЯ** — вспомогательная страница

**Связи с API:**
- Нет прямых API-вызовов
- Данные передаются через `render_template()` из backend

**Связи с backend:**
- Маршрут: `@app.route('/profile')` в `services/backend/app.py`
- Данные: `vulnerabilities` — уязвимости, назначенные текущему пользователю через `VulnerabilityService`

---

### 7. `my_assignments.html` — Мои назначения

**Описание:**
- Страница для просмотра назначенных пользователю уязвимостей
- Фильтры по статусу, уровню риска, поиск
- Упрощенная версия `vulnerabilities_list.html` для обычных пользователей

**Информативность:**
- **Список уязвимостей**: Назначенные пользователю уязвимости с фильтрами

**Важность:** ⭐⭐⭐ **СРЕДНЯЯ** — вспомогательная страница

**Связи с API:**
- Нет прямых API-вызовов
- Данные передаются через `render_template()`

**Связи с backend:**
- Маршрут: `@app.route('/my-assignments')` в `services/backend/app.py`
- Данные: `vulnerabilities` через `VulnerabilityService` для текущего пользователя

---

### 8. `review.html` — Проверка уязвимостей

**Описание:**
- Страница для проверки и одобрения уязвимостей (только для админов)
- Отображает уязвимости, сгруппированные по операторам
- Действия: Одобрить, Запросить правки, Завершить, Редактировать

**Информативность:**
- **Уязвимости по операторам**: Группировка по операторам, список уязвимостей с деталями
- **Действия**: Кнопки для одобрения, запроса правок, завершения, редактирования

**Важность:** ⭐⭐⭐⭐ **ВЫСОКАЯ** — ключевая страница для админов (workflow)

**Связи с API:**
- `fetch('/review-vulnerability', { method: 'POST', body: JSON.stringify({ vulnerability_id, action, operator_id }) })` — выполнение действия проверки
- `fetch('/get-vulnerability/<id>')` — получение деталей уязвимости для редактирования
- `fetch('/update-vulnerability')` — обновление уязвимости

**Связи с backend:**
- Маршрут: `@app.route('/review')` в `services/backend/app.py`
- Данные: `operators` с `assigned_vulnerabilities` через `OperatorService`
- Действие: `@app.route('/review-vulnerability', methods=['POST'])` вызывает `VulnerabilityService` методы (`mark_approved()`, `request_modification()`, `mark_completed()`)

---

### 9. `performance_analytics.html` — Аналитика производительности

**Описание:**
- Страница с визуальной аналитикой и графиками (Chart.js)
- Метрики производительности операторов, распределение уязвимостей, статистика

**Информативность:**
- **Метрики**: 4 карточки (Всего уязвимостей, Активных операторов, Завершено, Средняя производительность)
- **Графики**: Производительность операторов (bar chart), Уровни риска (pie chart), Статусы (pie chart), Распределение по CVSS (bar chart), Тренды (line chart)

**Важность:** ⭐⭐⭐ **СРЕДНЯЯ** — аналитическая страница

**Связи с API:**
- `fetch('/api/analytics/current')` — получение текущей аналитики (данные для графиков)

**Связи с backend:**
- Маршрут: `@app.route('/performance')` в `services/backend/app.py`
- Данные: `total_vulnerabilities, active_operators, completed_vulnerabilities, avg_performance` через `get_analytics_data()`
- API: `@app.route('/api/analytics/current')` вызывает `AnalyticsService`

**Используемые функции:**
- Chart.js для графиков
- JavaScript: `loadAnalytics()`, `updateCharts()`

---

### 10. `import_excel.html` — Импорт из Excel

**Описание:**
- Страница для импорта уязвимостей из Excel файлов
- Предварительный просмотр данных перед импортом

**Информативность:**
- **Загрузка файла**: Drag-and-drop область для загрузки Excel файла
- **Предварительный просмотр**: Таблица с данными, список колонок
- **Результат импорта**: Количество импортированных уязвимостей, ошибки

**Важность:** ⭐⭐⭐ **СРЕДНЯЯ** — вспомогательная функциональность

**Связи с API:**
- `fetch('/api/excel/import/preview', { method: 'POST', body: formData })` — предварительный просмотр данных
- `fetch('/api/excel/import', { method: 'POST', body: formData })` — импорт данных

**Связи с backend:**
- Маршрут: `@app.route('/import-excel')` в `services/backend/app.py`
- API: `@app.route('/api/excel/import/preview')`, `@app.route('/api/excel/import')` — используют `ExportService` для обработки Excel

---

### 11. `parsing_status.html` — Статус парсинга

**Описание:**
- Страница для мониторинга статуса парсинга в реальном времени
- Отображает прогресс, уязвимости в реальном времени, статистику

**Информативность:**
- **Статус системы**: Статус парсера (ready, error, running)
- **Прогресс**: Progress bar, детали (найдено, сохранено, текущий шаг), лог выполнения
- **Уязвимости в реальном времени**: Список уязвимостей, добавленных во время парсинга

**Важность:** ⭐⭐⭐ **СРЕДНЯЯ** — вспомогательная страница для мониторинга

**Связи с API:**
- `fetch('/api/start-parsing', { method: 'POST' })` — запуск парсинга
- `EventSource('/api/parsing-progress')` — SSE для прогресса
- `EventSource('/api/live-parsing-vulnerabilities')` — SSE для уязвимостей в реальном времени
- `fetch('/api/parsing-status')` — проверка статуса парсинга

**Связи с backend:**
- Маршрут: `@app.route('/parsing-status')` в `services/backend/app.py`
- API: SSE endpoints для real-time обновлений
- Парсеры работают на отдельной VM (Parsers VM) и сохраняют данные в БД

---

### 12. `auth/login.html` — Страница входа

**Описание:**
- Страница аутентификации пользователей
- Форма входа с email и паролем, валидация, обработка ошибок

**Информативность:**
- **Форма входа**: Email, пароль, кнопка входа
- **Flash-сообщения**: Ошибки авторизации, успешные сообщения

**Важность:** ⭐⭐⭐⭐⭐ **КРИТИЧЕСКАЯ** — точка входа в систему

**Связи с API:**
- Нет прямых API-вызовов (форма отправляется через POST)
- Можно использовать `fetch('/api/auth/login')` для AJAX-авторизации (но текущая реализация использует POST форму)

**Связи с backend:**
- Маршрут: `@app.route('/auth/login', methods=['GET', 'POST'])` в `services/backend/app.py`
- Обработка: `AuthService.authenticate()` проверяет credentials, создает сессию
- API альтернатива: `@app.route('/api/auth/login', methods=['POST'])` — JSON-авторизация

---

### 13. `admin/users.html` — Управление пользователями

**Описание:**
- Страница управления пользователями (только для админов)
- Таблица пользователей с возможностью удаления

**Информативность:**
- **Таблица пользователей**: Имя, email, роль, статус активности, дата создания
- **Действия**: Удаление пользователя

**Важность:** ⭐⭐ **НИЗКАЯ** — служебная страница

**Связи с API:**
- `fetch('/api/admin/users/<id>', { method: 'DELETE' })` — удаление пользователя

**Связи с backend:**
- Маршрут: `@app.route('/admin/users')` в `services/backend/app.py`
- Данные: `users` через `AuthService.get_all_users()`
- API: `@app.route('/api/admin/users/<id>', methods=['DELETE'])` — удаление пользователя

---

### 14. `ai/dashboard.html` — ИИ-Анализ (дашборд)

**Описание:**
- Главная страница ИИ-анализа уязвимостей
- Статистика по анализу, запуск анализа, ссылки на другие страницы ИИ

**Информативность:**
- **Статистика**: 4 карточки (Всего проанализировано, ИИ-уязвимости, Средняя уверенность, Ключевых слов)
- **Действия**: Кнопки для запуска анализа, перехода к статистике, обучению, мониторингу, паспортам

**Важность:** ⭐⭐⭐ **СРЕДНЯЯ** — функциональность ИИ-анализа

**Связи с API:**
- `fetch('/api/ai/statistics')` — получение статистики ИИ-анализа
- `fetch('/api/vulnerabilities?page=1&per_page=1000')` — получение списка уязвимостей для анализа
- `fetch('/api/ai/batch-analyze', { method: 'POST', body: JSON.stringify({ vulnerability_ids: [...] }) })` — запуск пакетного анализа

**Связи с backend:**
- Маршрут: `@app.route('/ai/dashboard')` в `services/backend/app.py`
- API: `@app.route('/api/ai/statistics')`, `@app.route('/api/ai/batch-analyze')` — используют `AITaggerService` или `AIIntegrationService`

---

### 15. `ai/statistics.html` — Статистика ИИ

**Описание:**
- Статистика по ключевым словам и ИИ-анализу

**Информативность:**
- Статистика по ключевым словам (данные из API)

**Важность:** ⭐⭐ **НИЗКАЯ** — вспомогательная страница

**Связи с API:**
- `fetch('/api/ai/keywords')` — получение статистики по ключевым словам

**Связи с backend:**
- Маршрут: `@app.route('/ai/statistics')` в `services/backend/app.py`
- API: `@app.route('/api/ai/keywords')` (если реализовано)

---

### 16. `ai/training.html` — Обучение ИИ

**Описание:**
- Страница управления обучением ИИ-модели (только для админов)

**Информативность:**
- Настройки обучения ИИ-модели

**Важность:** ⭐⭐ **НИЗКАЯ** — служебная страница

**Связи с API:**
- `fetch('/api/ai/train', { method: 'POST' })` — запуск обучения модели

**Связи с backend:**
- Маршрут: `@app.route('/ai/training')` в `services/backend/app.py`
- API: `@app.route('/api/ai/train')` (если реализовано)

---

### 17. `ai/monitoring.html` — Мониторинг сайтов

**Описание:**
- Страница мониторинга сайтов для ИИ-анализа (только для админов)

**Информативность:**
- Настройки мониторинга сайтов

**Важность:** ⭐⭐ **НИЗКАЯ** — служебная страница

**Связи с API:**
- Нет прямых API-вызовов (или специфичные для мониторинга)

**Связи с backend:**
- Маршрут: `@app.route('/ai/monitoring')` в `services/backend/app.py`

---

### 18. `ai/passports.html` — Паспорта уязвимостей

**Описание:**
- Страница для просмотра паспортов уязвимостей (результаты ИИ-анализа)

**Информативность:**
- Список паспортов уязвимостей

**Важность:** ⭐⭐ **НИЗКАЯ** — вспомогательная страница

**Связи с API:**
- Нет прямых API-вызовов (или специфичные для паспортов)

**Связи с backend:**
- Маршрут: `@app.route('/ai/passports')` в `services/backend/app.py`

---

## 🔗 АРХИТЕКТУРА СВЯЗЕЙ

### Схема взаимодействия компонентов

```
┌─────────────────────────────────────────────────────────────────┐
│                         FRONTEND (VM 231)                        │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Nginx (порт 80)                                         │  │
│  │  - Статические файлы (HTML, CSS, JS)                     │  │
│  │  - Проксирование /api/* → Backend (10.0.88.20:5000)     │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Flask App (APP_ROLE=frontend)                           │  │
│  │  - Только UI-маршруты (render_template)                  │  │
│  │  - БЕЗ подключения к БД                                  │  │
│  │  - БЕЗ API-маршрутов                                     │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTP Requests (/api/*)
                              │ (API_BASE_URL = http://10.0.88.20:5000)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         BACKEND (VM 232)                         │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Flask App (APP_ROLE=backend)                            │  │
│  │  - Только API-маршруты (/api/*)                          │  │
│  │  - БЕЗ render_template (кроме error handlers)            │  │
│  │  - С подключением к БД                                   │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Services Layer                                          │  │
│  │  - VulnerabilityService                                  │  │
│  │  - OperatorService                                       │  │
│  │  - AnalyticsService                                      │  │
│  │  - ExportService                                         │  │
│  │  - AuthService                                           │  │
│  │  - AssignmentManager                                     │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Repositories Layer                                      │  │
│  │  - LegacyVulnerabilityRepository                         │  │
│  │  - PostgresVulnerabilityRepository                       │  │
│  │  - OperatorRepository                                    │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ SQL Queries
                              │ (psycopg)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      DATABASE (VM 230)                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  PostgreSQL (порт 5432)                                  │  │
│  │  - Таблицы: turn, vulnerabilities, operators, users, ... │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ SQL INSERT/UPDATE
                              │ (psycopg)
                              │
┌─────────────────────────────────────────────────────────────────┐
│                        PARSERS (VM 233)                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Python Scripts (APP_ROLE=parsers)                       │  │
│  │  - БЕЗ Flask сервера                                     │  │
│  │  - БЕЗ HTTP endpoints                                    │  │
│  │  - С подключением к БД                                   │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Parser Services                                         │  │
│  │  - UnifiedParserService                                  │  │
│  │  - NVDIntegrationService                                 │  │
│  │  - Legacy Parsers (17 источников)                        │  │
│  │  - CVE.org Integration                                   │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Repositories                                            │  │
│  │  - LegacyVulnerabilityRepository                         │  │
│  │  - PostgresVulnerabilityRepository                       │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

### Детальное описание взаимодействий

#### 1. Frontend → Backend

**Механизм:**
- Frontend (VM 231) отдает статические HTML-файлы через Nginx
- JavaScript в HTML делает AJAX-запросы к `http://10.0.88.20:5000/api/...`
- Nginx на Frontend VM проксирует `/api/*` запросы на Backend VM

**Примеры запросов:**
```javascript
// В templates/dashboard.html
fetch('/api/dashboard-stats')  // → Nginx → http://10.0.88.20:5000/api/dashboard-stats

// В templates/vulnerabilities_list.html
fetch('/api/vulnerabilities?page=1&per_page=50')  // → Nginx → Backend API
```

**Протокол:**
- HTTP/HTTPS (REST API)
- JSON для данных
- Cookies/Session для аутентификации (CORS с credentials)

**CORS:**
- Backend настроен с `CORS(app, origins=[Config.FRONTEND_URL], supports_credentials=True)`
- `FRONTEND_URL = "http://10.0.88.10"` (или `10.0.88.231` в зависимости от конфигурации)

---

#### 2. Backend → Database

**Механизм:**
- Backend использует `psycopg` для подключения к PostgreSQL
- `DatabaseManager` (singleton) управляет соединением
- Репозитории (`LegacyVulnerabilityRepository`, `PostgresVulnerabilityRepository`) выполняют SQL-запросы

**Примеры запросов:**
```python
# В services/backend/app.py
db_manager = DatabaseManager()
vulnerability_repo = LegacyVulnerabilityRepository(db_manager.connection)

# В VulnerabilityService
vulnerabilities = vulnerability_repo.get_paginated(page=1, per_page=50)
```

**Протокол:**
- PostgreSQL protocol (TCP, порт 5432)
- SQL-запросы через `psycopg`

**Схема БД:**
- **Legacy**: `turn`, `cvelist`, `cwelist`, `operators_legacy`, `actids`
- **Modern**: `vulnerabilities`, `operators`, `users`, `user_vulnerability_assignments`
- Выбор схемы: `Config.USE_LEGACY_SCHEMA = True/False`

---

#### 3. Parsers → Database

**Механизм:**
- Parsers (VM 233) запускаются как фоновые скрипты (без Flask)
- Используют те же репозитории, что и Backend
- Сохраняют данные напрямую в БД

**Примеры:**
```python
# В services/unified_parser_service.py
db_manager = DatabaseManager()
vulnerability_repo = LegacyVulnerabilityRepository(db_manager.connection)

# Парсинг и сохранение
vulnerabilities = parser.parse(limit=100)
for vuln in vulnerabilities:
    vulnerability_repo.save_vulnerability(vuln)
```

**Протокол:**
- PostgreSQL protocol (TCP, порт 5432)
- SQL INSERT/UPDATE через `psycopg`

---

#### 4. Frontend → Backend → Database (полный цикл)

**Пример: Получение списка уязвимостей**

1. **Frontend (templates/vulnerabilities_list.html):**
   ```javascript
   fetch('/api/vulnerabilities?page=1&per_page=50&status=new')
   ```

2. **Nginx (Frontend VM):**
   - Проксирует запрос на `http://10.0.88.20:5000/api/vulnerabilities?page=1&per_page=50&status=new`

3. **Backend (services/backend/app.py):**
   ```python
   @app.route('/api/vulnerabilities', methods=['GET'])
   def api_vulnerabilities():
       page = int(request.args.get('page', 1))
       status = request.args.get('status')
       vulnerabilities, operators, total_count = get_vulnerabilities_with_operators(page=page, status=status)
       return jsonify({'success': True, 'vulnerabilities': [serialize_vulnerability(v) for v in vulnerabilities]})
   ```

4. **Service Layer (services/vulnerability_service.py):**
   ```python
   def get_paginated_vulnerabilities(self, page=1, per_page=50, status=None):
       return self.vulnerability_repo.get_paginated(page=page, per_page=per_page, status=status)
   ```

5. **Repository Layer (models/legacy_repositories.py):**
   ```python
   def get_paginated(self, page=1, per_page=50, status=None):
       query = "SELECT * FROM turn WHERE status = %s LIMIT %s OFFSET %s"
       cursor.execute(query, (status, per_page, (page-1)*per_page))
       return cursor.fetchall()
   ```

6. **Database (PostgreSQL):**
   - Выполняет SQL-запрос, возвращает данные

7. **Обратный путь:**
   - Database → Repository → Service → Backend API → JSON Response → Frontend JavaScript → Обновление DOM

---

## 🧩 ФУНКЦИОНАЛЬНОСТЬ КОМПОНЕНТОВ

### Frontend (VM 231)

**Роль:** Отображение UI и взаимодействие с пользователем

**Функции:**
- Рендеринг HTML-страниц (через Flask `render_template()`)
- Отдача статических файлов (CSS, JS, images) через Nginx
- Проксирование API-запросов на Backend VM
- Обработка форм и AJAX-запросов (JavaScript)

**Маршруты:**
- Все маршруты, которые возвращают HTML (не `/api/*`)
- Примеры: `/`, `/dashboard`, `/vulnerabilities`, `/operators`, `/parsers`, `/auth/login`, и т.д.

**Ограничения:**
- **НЕ подключается к БД** (APP_ROLE=frontend)
- **НЕ содержит API-маршрутов** (только UI)
- **НЕ содержит бизнес-логики** (только представление)

**Зависимости:**
- Flask (для `render_template()` и `url_for()`)
- Jinja2 (для шаблонов)
- Nginx (для статики и проксирования)

---

### Backend (VM 232)

**Роль:** API-сервер и бизнес-логика

**Функции:**
- Обработка API-запросов (`/api/*`)
- Бизнес-логика (Services Layer)
- Взаимодействие с БД (Repositories Layer)
- Аутентификация и авторизация
- Валидация данных

**API-маршруты:**
- `/api/auth/*` — аутентификация
- `/api/vulnerabilities/*` — управление уязвимостями
- `/api/operators/*` — управление операторами
- `/api/parsers/*` — управление парсерами
- `/api/analytics/*` — аналитика
- `/api/ai/*` — ИИ-анализ
- `/api/excel/*` — импорт из Excel

**Ограничения:**
- **НЕ рендерит HTML** (кроме error handlers)
- **НЕ содержит парсеров** (парсеры на отдельной VM)
- **НЕ содержит статических файлов** (на Frontend VM)

**Зависимости:**
- Flask (для API)
- psycopg (для БД)
- Services (VulnerabilityService, OperatorService, и т.д.)
- Repositories (LegacyVulnerabilityRepository, PostgresVulnerabilityRepository)

---

### Parsers (VM 233)

**Роль:** Фоновые задачи парсинга уязвимостей

**Функции:**
- Парсинг уязвимостей из различных источников (NVD, OSV, Legacy парсеры, CVE.org)
- Сохранение данных в БД
- Логирование результатов

**Парсеры:**
- **NVD Parser**: Парсинг из NVD API (с API ключом)
- **OSV Parser**: Парсинг из OSV.dev API
- **Legacy Parsers**: 17 источников (RedHat, Debian, Cisco, Cert, и т.д.)
- **CVE.org Integration**: Парсинг из CVEProject/cvelistV5 репозитория
- **Kaspersky Selenium Parser**: Парсинг через Selenium

**Ограничения:**
- **НЕ содержит Flask сервера** (APP_ROLE=parsers)
- **НЕ содержит HTTP endpoints**
- **НЕ содержит UI** (только фоновые задачи)

**Зависимости:**
- requests, BeautifulSoup (для HTML-парсинга)
- selenium, undetected-chromedriver (для Kaspersky)
- psycopg (для БД)
- Repositories (для сохранения данных)

**Запуск:**
- Запускается через cron или systemd
- Или вызывается через Backend API (`/api/parsers/run-all`), который запускает парсеры асинхронно

---

### Database (VM 230)

**Роль:** Хранилище данных

**Функции:**
- Хранение уязвимостей, операторов, пользователей, истории парсинга
- Поддержка двух схем: Legacy и Modern
- Индексы для быстрого поиска

**Таблицы (Legacy схема):**
- `turn` — уязвимости (основная таблица)
- `cvelist` — список CVE с переводами
- `cwelist` — список CWE
- `operators_legacy` — операторы
- `actids` — назначения уязвимостей операторам
- `parsing_history` — история парсинга

**Таблицы (Modern схема):**
- `vulnerabilities` — уязвимости (с NVD-полями)
- `operators` — операторы
- `users` — пользователи
- `user_vulnerability_assignments` — назначения
- `login_attempts` — аудит входа

**Ограничения:**
- **Только PostgreSQL** (нет поддержки других БД)
- **Нет репликации** (в текущей конфигурации)

---

## 🔄 ЗАВИСИМОСТИ И СВЯЗИ

### Зависимости файлов

#### Backend (`services/backend/app.py`)

**Зависит от:**
- `config.py` — конфигурация (IP адреса, порты, настройки БД)
- `models/database.py` — DatabaseManager
- `models/legacy_repositories.py` — LegacyVulnerabilityRepository
- `models/postgres_repositories.py` — PostgresVulnerabilityRepository
- `services/vulnerability_service.py` — VulnerabilityService
- `services/operator_service.py` — OperatorService
- `services/analytics_service.py` — AnalyticsService
- `services/export_service.py` — ExportService
- `services/auth_service.py` — AuthService
- `services/assignment_manager.py` — AssignmentManager
- `services/data_manager.py` — DataManager
- `services/unified_parser_service.py` — UnifiedParserService (для запуска парсеров)
- `utils/decorators.py` — декораторы `@login_required`, `@admin_required`

**Используется в:**
- Frontend (через API-запросы)
- Parsers (косвенно, через общую БД)

---

#### UnifiedParserService (`services/unified_parser_service.py`)

**Зависит от:**
- `models/database.py` — DatabaseManager
- `models/legacy_repositories.py` — LegacyVulnerabilityRepository
- `models/postgres_repositories.py` — PostgresVulnerabilityRepository
- `config.py` — NVD API ключ, настройки парсеров
- Все парсеры из `services/legacy_parsers/` (17 парсеров)
- `services/nvd_integration_service.py` — NVDIntegrationService
- `services/osv_api_parser.py` — OSVApiParser
- `services/cve_org_integration_service.py` — CVEOrgIntegrationService

**Используется в:**
- Backend API (`/api/parsers/run-all`)
- Parsers VM (прямой запуск скриптов)

---

#### VulnerabilityService (`services/vulnerability_service.py`)

**Зависит от:**
- `models/legacy_repositories.py` или `models/postgres_repositories.py` — репозитории
- `models/entities.py` — Vulnerability dataclass

**Используется в:**
- Backend API (для всех операций с уязвимостями)
- Frontend (косвенно, через API)

---

#### LegacyVulnerabilityRepository (`models/legacy_repositories.py`)

**Зависит от:**
- `psycopg` — для работы с PostgreSQL
- `models/entities.py` — Vulnerability dataclass
- `models/database.py` — DatabaseManager (для соединения)

**Используется в:**
- VulnerabilityService
- UnifiedParserService
- Parsers (напрямую)

---

### Зависимости сервисов

#### Сервисы → Репозитории

```
VulnerabilityService → LegacyVulnerabilityRepository / PostgresVulnerabilityRepository
OperatorService → OperatorRepository (через DataManager)
AnalyticsService → VulnerabilityService, OperatorService
ExportService → VulnerabilityService, OperatorService
AuthService → DatabaseManager (прямые SQL-запросы к users)
AssignmentManager → DataManager → VulnerabilityService, OperatorService
UnifiedParserService → LegacyVulnerabilityRepository / PostgresVulnerabilityRepository
```

#### Сервисы → Сервисы

```
AnalyticsService → VulnerabilityService, OperatorService
ExportService → VulnerabilityService, OperatorService
AssignmentManager → DataManager → VulnerabilityService, OperatorService
UnifiedParserService → NVDIntegrationService, OSVApiParser, CVEOrgIntegrationService
```

---

### Влияние APP_ROLE

**Текущая ситуация:** В проекте НЕТ переменной `APP_ROLE`, но пользователь хочет разделить на 4 VM.

**Предлагаемая реализация:**

#### 1. Frontend (APP_ROLE=frontend)

```python
# В app.py (или отдельный файл для frontend)
import os
APP_ROLE = os.getenv('APP_ROLE', 'full')

if APP_ROLE == 'frontend':
    # Только UI-маршруты
    @app.route('/')
    def index():
        return render_template('dashboard.html', stats={}, vulnerabilities=[], operators=[])
    
    # НЕТ подключения к БД
    # НЕТ API-маршрутов
    # Статические файлы через Nginx
```

#### 2. Backend (APP_ROLE=backend)

```python
# В services/backend/app.py
if APP_ROLE == 'backend':
    # Только API-маршруты
    @app.route('/api/vulnerabilities', methods=['GET'])
    def api_vulnerabilities():
        # ... бизнес-логика
    
    # НЕТ render_template (кроме error handlers)
    # ЕСТЬ подключение к БД
    db_manager = DatabaseManager()
    vulnerability_repo = LegacyVulnerabilityRepository(db_manager.connection)
```

#### 3. Parsers (APP_ROLE=parsers)

```python
# В services/parsers/run_parsers.py
if APP_ROLE == 'parsers':
    # НЕТ Flask сервера
    # Только фоновые задачи
    db_manager = DatabaseManager()
    unified_parser = UnifiedParserService()
    results = unified_parser.parse_all(...)
```

#### 4. Full (APP_ROLE=full)

```python
# Старое поведение (все в одном)
if APP_ROLE == 'full':
    # Все маршруты (UI + API)
    # Подключение к БД
    # Все функции доступны
```

---

## 🎯 РЕКОМЕНДАЦИИ ПО УЛУЧШЕНИЮ

### 1. Разделение Frontend и Backend

**Текущая проблема:**
- Frontend и Backend находятся в одном файле `services/backend/app.py`
- Оба используют Flask, что создает путаницу

**Решение:**
- **Frontend VM**: Отдельный Flask app только для UI-маршрутов (`render_template()`), без подключения к БД
- **Backend VM**: Отдельный Flask app только для API-маршрутов (`/api/*`), с подключением к БД
- Использовать `APP_ROLE` для контроля поведения

**Преимущества:**
- Минимизация поверхности атаки (Frontend не имеет доступа к БД)
- Масштабируемость (можно масштабировать Frontend и Backend независимо)
- Упрощение развертывания (каждая VM имеет свою роль)

---

### 2. Использование API Gateway / Reverse Proxy

**Текущая проблема:**
- Nginx на Frontend VM проксирует только `/api/*`
- Нет единой точки входа для всех API-запросов

**Решение:**
- Использовать Nginx как API Gateway на Frontend VM
- Или отдельный API Gateway (например, Kong, Traefik)
- Централизованная обработка CORS, rate limiting, authentication

**Преимущества:**
- Единая точка входа
- Централизованная безопасность
- Мониторинг и логирование

---

### 3. Разделение схем БД (Legacy и Modern)

**Текущая проблема:**
- Две схемы БД (Legacy и Modern) используются одновременно через `Config.USE_LEGACY_SCHEMA`
- Сложность миграции

**Решение:**
- Постепенная миграция с Legacy на Modern
- Создать адаптер для одновременной работы с обеими схемами
- Или полностью мигрировать на Modern схему

**Преимущества:**
- Упрощение кода
- Лучшая производительность (Modern схема оптимизирована)
- Поддержка NVD-полей из коробки

---

### 4. Вынос парсеров в отдельные микросервисы

**Текущая проблема:**
- Все парсеры в одном `UnifiedParserService`
- Сложность управления и масштабирования

**Решение:**
- Каждый тип парсера — отдельный микросервис
- Использовать очередь задач (например, Celery + Redis/RabbitMQ)
- Backend отправляет задачи в очередь, парсеры обрабатывают

**Преимущества:**
- Масштабируемость (можно запустить несколько экземпляров парсера)
- Отказоустойчивость (если один парсер упал, остальные работают)
- Мониторинг (отдельные метрики для каждого парсера)

---

### 5. Кэширование данных

**Текущая проблема:**
- Каждый запрос к API идет в БД
- Нет кэширования для часто запрашиваемых данных

**Решение:**
- Использовать Redis для кэширования
- Кэшировать статистику, списки операторов, часто запрашиваемые уязвимости
- TTL для кэша (например, 5 минут для статистики)

**Преимущества:**
- Снижение нагрузки на БД
- Улучшение производительности API
- Масштабируемость

---

### 6. Асинхронная обработка длительных операций

**Текущая проблема:**
- Парсинг уязвимостей выполняется синхронно через API (`/api/parsers/run-all`)
- Может привести к таймауту запроса

**Решение:**
- Использовать Celery для асинхронных задач
- Backend создает задачу в очереди, возвращает task_id
- Frontend опрашивает статус задачи через `/api/tasks/<task_id>/status`
- Или использовать WebSockets/SSE для real-time обновлений

**Преимущества:**
- Нет таймаутов
- Лучший UX (пользователь видит прогресс)
- Масштабируемость

---

### 7. Безопасность

**Улучшения:**

1. **HTTPS**: Использовать HTTPS для всех соединений (SSL/TLS сертификаты)
2. **API Keys**: Для внешних API (NVD) использовать переменные окружения, не хардкодить
3. **Rate Limiting**: Ограничить количество запросов от одного IP (защита от DDoS)
4. **Input Validation**: Валидация всех входных данных на backend
5. **SQL Injection**: Использовать параметризованные запросы (уже используется через psycopg)
6. **CORS**: Ограничить CORS только необходимыми доменами
7. **Session Security**: Использовать secure cookies, httpOnly, sameSite

---

### 8. Мониторинг и логирование

**Текущая проблема:**
- Логирование через `logging`, но нет централизованного сбора логов
- Нет мониторинга производительности

**Решение:**
- Использовать ELK Stack (Elasticsearch, Logstash, Kibana) или Loki + Grafana
- Централизованный сбор логов со всех VM
- Мониторинг через Prometheus + Grafana
- Алерты при ошибках

**Преимущества:**
- Видимость всей системы
- Быстрое обнаружение проблем
- Аналитика производительности

---

### 9. Контейнеризация и оркестрация

**Текущая ситуация:**
- Используется Docker, но нет оркестрации

**Решение:**
- Использовать Docker Compose для локальной разработки
- Использовать Kubernetes для production (если нужна оркестрация)
- Или остаться на Docker Compose для простоты

**Преимущества:**
- Автоматическое масштабирование
- Self-healing (автоматический перезапуск упавших контейнеров)
- Упрощение развертывания

---

### 10. Тестирование

**Текущая проблема:**
- Минимальное покрытие тестами

**Решение:**
- Unit-тесты для сервисов и репозиториев
- Integration-тесты для API endpoints
- E2E-тесты для критических сценариев
- Использовать pytest для Python, Jest для JavaScript (если добавится frontend-тестирование)

**Преимущества:**
- Надежность кода
- Быстрое обнаружение регрессий
- Уверенность при рефакторинге

---

## 📊 ИТОГОВАЯ СХЕМА АРХИТЕКТУРЫ (РЕКОМЕНДУЕМАЯ)

```
┌─────────────────────────────────────────────────────────────────┐
│  FRONTEND VM (10.0.88.231)                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Nginx                                                    │  │
│  │  - Static files (HTML, CSS, JS)                          │  │
│  │  - Proxy /api/* → Backend                                │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Flask App (APP_ROLE=frontend)                           │  │
│  │  - UI routes only (render_template)                      │  │
│  │  - NO DB connection                                      │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS (/api/*)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  BACKEND VM (10.0.88.232)                                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Flask App (APP_ROLE=backend)                            │  │
│  │  - API routes only (/api/*)                              │  │
│  │  - DB connection                                         │  │
│  │  - Services Layer                                        │  │
│  │  - Repositories Layer                                    │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Redis (Cache)                                           │  │
│  │  - Statistics cache                                      │  │
│  │  - Session storage (optional)                            │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ SQL (psycopg)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  DATABASE VM (10.0.88.230)                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  PostgreSQL                                              │  │
│  │  - Legacy schema (turn, cvelist, ...)                    │  │
│  │  - Modern schema (vulnerabilities, operators, ...)       │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ SQL (psycopg)
                              │
┌─────────────────────────────────────────────────────────────────┐
│  PARSERS VM (10.0.88.233)                                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Python Scripts (APP_ROLE=parsers)                       │  │
│  │  - UnifiedParserService                                  │  │
│  │  - NVD Parser                                            │  │
│  │  - Legacy Parsers (17 sources)                           │  │
│  │  - CVE.org Integration                                   │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Celery Workers (optional, для асинхронности)            │  │
│  │  - Task queue (Redis/RabbitMQ)                           │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## ✅ ЧЕКЛИСТ ДЛЯ РЕДИЗАЙНА

- [ ] Разделить `app.py` на `frontend_app.py` и `backend_app.py`
- [ ] Добавить `APP_ROLE` переменную окружения
- [ ] Обновить `config.py` с IP адресами для каждой VM
- [ ] Настроить Nginx на Frontend VM для проксирования API
- [ ] Обновить все HTML-шаблоны для использования `API_BASE_URL`
- [ ] Вынести парсеры в отдельный модуль/сервис
- [ ] Настроить Docker Compose для каждой VM
- [ ] Добавить Redis для кэширования (опционально)
- [ ] Добавить мониторинг и логирование
- [ ] Написать тесты для критических компонентов
- [ ] Обновить документацию
- [ ] Провести тестирование на всех VM

---

**Дата создания:** 2025-01-05  
**Версия:** 1.0  
**Автор:** AI Architect Analysis

