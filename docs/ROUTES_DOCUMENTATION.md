# 🛣️ Полная документация по маршрутам (Routes)

**Для разработчиков**  
**Версия:** 1.0  
**Дата:** 2025-01-18

---

## 📋 Содержание

1. [Как посмотреть все маршруты](#как-посмотреть-все-маршруты)
2. [Разделение маршрутов на JSON и XML](#разделение-маршрутов-на-json-и-xml)
3. [Полный список маршрутов](#полный-список-маршрутов)
4. [API Endpoints (JSON)](#api-endpoints-json)
5. [HTML Страницы](#html-страницы)
6. [Расширение маршрутов](#расширение-маршрутов)

---

## 🔍 Как посмотреть все маршруты

### Метод 1: Использование скрипта анализа

```bash
# Запуск скрипта анализа маршрутов
python3 scripts/list_routes.py
```

**Результат:**
- Выводит все маршруты в консоль
- Группирует по типам (JSON, HTML, REDIRECT, FILE)
- Сохраняет JSON файл: `docs/routes_analysis.json`

### Метод 2: Использование Flask CLI

```bash
# В интерактивном режиме Python
python3
>>> from app import app
>>> for rule in app.url_map.iter_rules():
...     print(f"{rule.endpoint:30} {rule.rule:50} {rule.methods}")
```

### Метод 3: Использование Flask-RESTful (если используется)

```bash
python3
>>> from app import app
>>> import json
>>> routes = []
>>> for rule in app.url_map.iter_rules():
...     routes.append({
...         'endpoint': rule.endpoint,
...         'path': rule.rule,
...         'methods': list(rule.methods)
...     })
>>> print(json.dumps(routes, indent=2))
```

---

## 📊 Разделение маршрутов на JSON и XML

### Текущая реализация

В проекте используется **только JSON** для API endpoints. XML не используется.

### Как добавить поддержку XML

#### Вариант 1: Через расширение файла в URL

```python
@app.route('/api/vulnerabilities.<format>')
def get_vulnerabilities(format='json'):
    """Получить уязвимости в формате JSON или XML"""
    vulnerabilities = vuln_service.get_all_vulnerabilities()
    
    if format == 'xml':
        from flask import Response
        xml_data = convert_to_xml(vulnerabilities)
        return Response(xml_data, mimetype='application/xml')
    else:
        return jsonify({'success': True, 'vulnerabilities': vulnerabilities})
```

**Использование:**
- JSON: `GET /api/vulnerabilities.json`
- XML: `GET /api/vulnerabilities.xml`

#### Вариант 2: Через Content-Type заголовок

```python
@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Получить уязвимости в формате JSON или XML"""
    vulnerabilities = vuln_service.get_all_vulnerabilities()
    
    # Проверяем Accept заголовок
    accept_header = request.headers.get('Accept', 'application/json')
    
    if 'application/xml' in accept_header or 'text/xml' in accept_header:
        from flask import Response
        xml_data = convert_to_xml(vulnerabilities)
        return Response(xml_data, mimetype='application/xml')
    else:
        return jsonify({'success': True, 'vulnerabilities': vulnerabilities})
```

**Использование:**
```bash
# JSON (по умолчанию)
curl http://localhost:5000/api/vulnerabilities

# XML
curl -H "Accept: application/xml" http://localhost:5000/api/vulnerabilities
```

#### Вариант 3: Через параметр запроса

```python
@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Получить уязвимости в формате JSON или XML"""
    format_type = request.args.get('format', 'json')
    vulnerabilities = vuln_service.get_all_vulnerabilities()
    
    if format_type == 'xml':
        from flask import Response
        xml_data = convert_to_xml(vulnerabilities)
        return Response(xml_data, mimetype='application/xml')
    else:
        return jsonify({'success': True, 'vulnerabilities': vulnerabilities})
```

**Использование:**
- JSON: `GET /api/vulnerabilities?format=json`
- XML: `GET /api/vulnerabilities?format=xml`

### Утилита для конвертации в XML

```python
def convert_to_xml(data, root_tag='response'):
    """Конвертировать данные в XML"""
    from xml.etree.ElementTree import Element, tostring
    
    def dict_to_xml(d, parent):
        for key, value in d.items():
            if isinstance(value, dict):
                elem = Element(str(key))
                parent.append(elem)
                dict_to_xml(value, elem)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        elem = Element(str(key))
                        parent.append(elem)
                        dict_to_xml(item, elem)
                    else:
                        elem = Element(str(key))
                        elem.text = str(item)
                        parent.append(elem)
            else:
                elem = Element(str(key))
                elem.text = str(value) if value is not None else ''
                parent.append(elem)
    
    root = Element(root_tag)
    if isinstance(data, dict):
        dict_to_xml(data, root)
    elif isinstance(data, list):
        for item in data:
            dict_to_xml(item, root)
    
    return tostring(root, encoding='unicode')
```

---

## 📡 Полный список маршрутов

### Статистика

- **Всего маршрутов:** ~234
- **JSON API:** ~146
- **HTML страницы:** ~39
- **Редиректы:** ~23
- **Файлы:** ~2
- **Неопределенные:** ~24

---

## 🔌 API Endpoints (JSON)

### Аутентификация

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| `POST` | `/api/auth/login` | Вход в систему | Публичный |
| `POST` | `/api/auth/logout` | Выход из системы | Авторизованный |
| `GET` | `/api/auth/check` | Проверка авторизации | Публичный |

**Пример запроса:**
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

**Пример ответа:**
```json
{
  "success": true,
  "user": {
    "id": 1,
    "username": "user",
    "email": "user@example.com",
    "role": "user",
    "full_name": "User Name"
  }
}
```

### Уязвимости

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| `GET` | `/api/vulnerabilities` | Список уязвимостей (с пагинацией) | Авторизованный |
| `GET` | `/api/vulnerabilities/<id>` | Получить уязвимость по ID | Авторизованный |
| `PUT` | `/api/vulnerabilities/<id>` | Обновить уязвимость | Авторизованный |
| `GET` | `/get-vulnerability/<id>` | Получить уязвимость (legacy) | Авторизованный |
| `POST` | `/api/vulnerabilities/clear` | Очистить все уязвимости | Admin |

**Параметры запроса для `/api/vulnerabilities`:**
- `page` - номер страницы (по умолчанию: 1)
- `per_page` - элементов на странице (по умолчанию: 50)
- `status` - фильтр по статусу (new, in_progress, completed, rejected)
- `severity` - фильтр по серьезности (low, medium, high, critical)
- `search` - поиск по тексту
- `ai_only` - только уязвимости с AI анализом (true/false)
- `tags` - фильтр по тегам (через запятую)

**Пример запроса:**
```bash
GET /api/vulnerabilities?page=1&per_page=50&status=new&severity=high
```

**Пример ответа:**
```json
{
  "success": true,
  "vulnerabilities": [
    {
      "id": 1,
      "title": "CVE-2024-0001",
      "description": "Описание уязвимости",
      "severity": "high",
      "status": "new",
      "cvss_score": 8.5,
      "risk_level": "high",
      "category": "web"
    }
  ],
  "total_count": 150,
  "page": 1,
  "per_page": 50,
  "total_pages": 3
}
```

### Теги уязвимостей

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| `GET` | `/api/vulnerabilities/<id>/tags` | Получить теги уязвимости | Авторизованный |
| `PUT` | `/api/vulnerabilities/<id>/tags` | Заменить все теги | Admin |
| `POST` | `/api/vulnerabilities/<id>/tags` | Добавить тег | Admin |
| `DELETE` | `/api/vulnerabilities/<id>/tags` | Удалить тег | Admin |

### Операторы

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| `GET` | `/api/operators` | Список операторов | Admin |
| `POST` | `/api/operators` | Создать оператора | Admin |
| `POST` | `/api/assign-operator` | Назначить оператора на уязвимость | Admin |
| `POST` | `/api/assign-multiple` | Назначить оператора на несколько уязвимостей | Admin |
| `POST` | `/api/unassign-vulnerability` | Снять назначение | Admin |

### AI и ML Platform

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| `POST` | `/api/ai/analyze` | Анализ уязвимости через AI | Авторизованный |
| `POST` | `/api/ai/batch-analyze` | Пакетный анализ | Авторизованный |
| `POST` | `/api/ai/classify/<id>` | Классификация уязвимости | Авторизованный |
| `GET` | `/api/ai/statistics` | Статистика AI анализа | Авторизованный |
| `GET` | `/api/ai/keywords` | Ключевые слова | Авторизованный |
| `POST` | `/api/ai/train` | Обучение модели | Admin |
| `POST` | `/api/ai/generate-passport/<id>` | Генерация паспорта | Авторизованный |
| `GET` | `/api/ai/passport/<id>` | Получить паспорт | Авторизованный |
| `GET` | `/api/ai/graph3d/data` | Данные для 3D графика | Авторизованный |
| `POST` | `/api/ai/monitor-start` | Запуск мониторинга | Admin |
| `POST` | `/api/ai/monitor-stop` | Остановка мониторинга | Admin |
| `GET` | `/api/ai/monitor-status` | Статус мониторинга | Admin |

### ML Platform Integration

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| `GET` | `/api/ml-platform/connection` | Проверка подключения | Авторизованный |
| `POST` | `/api/ml-platform/training/start` | Запуск обучения | Admin |
| `GET` | `/api/ml-platform/training/status/<task_id>` | Статус обучения | Авторизованный |
| `GET` | `/api/ml-platform/training/history` | История обучения | Авторизованный |
| `GET` | `/api/ml-platform/passports` | Список паспортов | Авторизованный |
| `GET` | `/api/ml-platform/passports/<cve_id>` | Паспорт по CVE ID | Авторизованный |

### Парсеры

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| `POST` | `/api/parsers/run-all` | Запустить все парсеры | Admin |
| `GET` | `/api/parsing-status` | Статус парсинга | Авторизованный |
| `GET` | `/api/parsers/stats` | Статистика парсеров | Авторизованный |
| `GET` | `/api/parsers/history` | История парсинга | Авторизованный |
| `GET` | `/api/parsers/status` | Статус парсеров | Авторизованный |
| `POST` | `/api/html-parser/parse` | Парсинг HTML | Admin |
| `POST` | `/api/vendors/parse` | Парсинг вендоров | Admin |
| `POST` | `/api/ai-tagger/scan-all` | Сканирование AI тегами | Admin |
| `POST` | `/api/redhat/import` | Импорт RedHat CVE | Admin |
| `POST` | `/api/redhat/import-sync` | Синхронный импорт RedHat | Admin |
| `GET` | `/api/parsers/debug` | Отладочная информация | Admin |

### Аналитика

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| `GET` | `/api/dashboard-stats` | Статистика дашборда | Авторизованный |
| `GET` | `/api/analytics/refresh` | Обновить аналитику | Авторизованный |
| `GET` | `/api/analytics/current` | Текущая аналитика | Авторизованный |

### Excel импорт

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| `POST` | `/api/excel/import/preview` | Предпросмотр Excel файла | Авторизованный |
| `POST` | `/api/excel/import` | Импорт из Excel | Авторизованный |

### CVE синхронизация

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| `GET` | `/api/cve-sync/status` | Статус синхронизации CVE | Авторизованный |
| `POST` | `/api/cve-sync/reset` | Сброс синхронизации | Admin |

### Диагностика

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| `GET` | `/api/health` | Проверка здоровья сервиса | Публичный |
| `GET` | `/api/diagnostics/connectivity` | Проверка подключений | Авторизованный |

### Безопасность (Security Methodologies)

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| `GET` | `/api/security/methodologies` | Список методологий | Авторизованный |
| `GET` | `/api/security/methodologies/<id>` | Получить методологию | Авторизованный |
| `GET` | `/api/security/methodologies/<id>/tests` | Тесты методологии | Авторизованный |
| `GET`, `POST` | `/api/security/projects` | Проекты безопасности | Авторизованный |
| `GET` | `/api/security/projects/<id>` | Получить проект | Авторизованный |
| `GET`, `POST` | `/api/security/projects/<id>/results` | Результаты проекта | Авторизованный |
| `GET` | `/api/security/projects/<id>/metrics` | Метрики проекта | Авторизованный |

---

## 🌐 HTML Страницы

### Основные страницы

| Путь | Описание | Доступ |
|------|----------|--------|
| `/` | Главная (редирект) | Публичный |
| `/auth/login` | Страница входа | Публичный |
| `/dashboard` | Дашборд | Авторизованный |
| `/profile` | Профиль пользователя | Авторизованный |
| `/vulnerabilities` | Список уязвимостей | Авторизованный |
| `/operators` | Управление операторами | Admin |
| `/admin/users` | Управление пользователями | Admin |
| `/performance` | Аналитика производительности | Авторизованный |
| `/analytics` | Аналитика (алиас) | Авторизованный |
| `/review` | Проверка уязвимостей | Admin |
| `/import-excel` | Импорт из Excel | Авторизованный |
| `/parsers` | Управление парсерами | Admin |
| `/my-assignments` | Мои назначения | Авторизованный |

### AI страницы

| Путь | Описание | Доступ |
|------|----------|--------|
| `/ai/dashboard` | AI дашборд | Авторизованный |
| `/ai/statistics` | AI статистика | Авторизованный |
| `/ai/training` | Обучение AI | Admin |
| `/ai/graph3d` | 3D визуализация | Авторизованный |
| `/ai/monitoring` | Мониторинг AI | Авторизованный |
| `/ai/passports` | Паспорта уязвимостей | Авторизованный |

---

## 🔧 Расширение маршрутов

### Добавление нового JSON API endpoint

```python
@app.route('/api/custom/endpoint', methods=['GET', 'POST'])
@login_required  # Опционально
def custom_endpoint():
    """Описание endpoint"""
    try:
        if request.method == 'GET':
            # Обработка GET запроса
            data = get_custom_data()
            return jsonify({
                'success': True,
                'data': data
            })
        elif request.method == 'POST':
            # Обработка POST запроса
            data = request.get_json()
            result = process_custom_data(data)
            return jsonify({
                'success': True,
                'result': result
            })
    except Exception as e:
        logger.error(f"Ошибка в custom_endpoint: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
```

### Добавление нового HTML маршрута

```python
@app.route('/custom/page')
@login_required
def custom_page():
    """Страница с кастомным контентом"""
    data = get_page_data()
    return render_template('custom_page.html', data=data)
```

### Добавление маршрута с поддержкой XML

```python
@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Получить уязвимости в JSON или XML"""
    vulnerabilities = vuln_service.get_all_vulnerabilities()
    
    # Проверяем формат через параметр или заголовок
    format_type = request.args.get('format', 'json')
    accept_header = request.headers.get('Accept', 'application/json')
    
    if format_type == 'xml' or 'application/xml' in accept_header:
        from flask import Response
        xml_data = convert_to_xml({
            'success': True,
            'vulnerabilities': vulnerabilities
        })
        return Response(xml_data, mimetype='application/xml')
    else:
        return jsonify({
            'success': True,
            'vulnerabilities': vulnerabilities
        })
```

---

## 📝 Чеклист для разработчика

- [ ] Использован скрипт `scripts/list_routes.py` для анализа
- [ ] Новые маршруты добавлены в документацию
- [ ] Определен тип ответа (JSON/HTML/XML)
- [ ] Добавлены декораторы доступа (`@login_required`, `@admin_required`)
- [ ] Обработка ошибок реализована
- [ ] Логирование добавлено
- [ ] Тесты написаны

---

## 🔗 Связанные файлы

- `app.py` - Основной файл с маршрутами
- `services/backend/app.py` - Backend маршруты
- `scripts/list_routes.py` - Скрипт анализа маршрутов
- `docs/routes_analysis.json` - JSON файл с анализом маршрутов

---

**Статус:** ✅ Документация актуальна  
**Последнее обновление:** 2025-01-18

