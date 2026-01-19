# 🔍 Как посмотреть маршруты (Routes) в проекте

**Краткое руководство для разработчиков**

---

## 🎯 Быстрый способ

### Использование готового скрипта

```bash
# Запуск анализа всех маршрутов
python3 scripts/list_routes.py
```

**Результат:**
- Выводит все маршруты в консоль
- Группирует по типам (JSON, HTML, REDIRECT, FILE)
- Сохраняет JSON: `docs/routes_analysis.json`

---

## 📋 Методы просмотра маршрутов

### Метод 1: Скрипт анализа (Рекомендуется)

```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager
python3 scripts/list_routes.py
```

**Вывод:**
```
================================================================================
АНАЛИЗ МАРШРУТОВ FLASK ПРИЛОЖЕНИЯ
================================================================================

📄 Анализ файла: app.py
   Найдено маршрутов: 87
📄 Анализ файла: services/backend/app.py
   Найдено маршрутов: 84

📊 Статистика:
   JSON API: 146
   HTML страницы: 39
   Редиректы: 23
   Файлы: 2
   Всего: 234

📡 JSON API МАРШРУТЫ
  GET             /api/auth/check                                    → api_auth_check
  POST            /api/auth/login                                    → api_auth_login
  ...
```

### Метод 2: Flask CLI (в Python)

```python
# В интерактивном режиме
python3
>>> from app import app
>>> 
>>> # Просмотр всех маршрутов
>>> for rule in app.url_map.iter_rules():
...     print(f"{rule.endpoint:30} {rule.rule:50} {list(rule.methods)}")
```

### Метод 3: Через Flask приложение

```python
from app import app

# Получить все маршруты
routes = []
for rule in app.url_map.iter_rules():
    routes.append({
        'endpoint': rule.endpoint,
        'path': rule.rule,
        'methods': list(rule.methods)
    })

# Вывод
import json
print(json.dumps(routes, indent=2))
```

### Метод 4: Поиск в коде

```bash
# Поиск всех декораторов @app.route
grep -r "@app.route" app.py services/backend/app.py

# С подсветкой
grep -rn "@app.route" --color=always app.py services/backend/app.py
```

---

## 🔍 Разделение маршрутов на JSON и XML

### Текущее состояние

**В проекте используется только JSON** для API endpoints.

### Как определить тип ответа маршрута

#### 1. По коду функции

```python
# JSON маршрут
@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    return jsonify({'success': True, 'data': []})  # ← jsonify = JSON

# HTML маршрут
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')  # ← render_template = HTML
```

#### 2. По пути маршрута

- **JSON API:** начинаются с `/api/`
- **HTML страницы:** без префикса `/api/`
- **Редиректы:** используют `redirect()`

#### 3. Использование скрипта

```bash
python3 scripts/list_routes.py | grep "JSON API"
```

---

## 📊 Добавление поддержки XML

### Вариант 1: Через расширение файла

```python
@app.route('/api/vulnerabilities.<format>')
def get_vulnerabilities(format='json'):
    """Поддержка JSON и XML через расширение"""
    data = get_vulnerabilities_data()
    
    if format == 'xml':
        from flask import Response
        xml_data = convert_to_xml(data)
        return Response(xml_data, mimetype='application/xml')
    else:
        return jsonify(data)
```

**Использование:**
- `GET /api/vulnerabilities.json` → JSON
- `GET /api/vulnerabilities.xml` → XML

### Вариант 2: Через Accept заголовок

```python
@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Поддержка JSON и XML через Accept заголовок"""
    data = get_vulnerabilities_data()
    accept = request.headers.get('Accept', 'application/json')
    
    if 'application/xml' in accept:
        from flask import Response
        xml_data = convert_to_xml(data)
        return Response(xml_data, mimetype='application/xml')
    else:
        return jsonify(data)
```

**Использование:**
```bash
# JSON (по умолчанию)
curl http://localhost:5000/api/vulnerabilities

# XML
curl -H "Accept: application/xml" http://localhost:5000/api/vulnerabilities
```

### Вариант 3: Через параметр запроса

```python
@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Поддержка JSON и XML через параметр format"""
    format_type = request.args.get('format', 'json')
    data = get_vulnerabilities_data()
    
    if format_type == 'xml':
        from flask import Response
        xml_data = convert_to_xml(data)
        return Response(xml_data, mimetype='application/xml')
    else:
        return jsonify(data)
```

**Использование:**
- `GET /api/vulnerabilities?format=json` → JSON
- `GET /api/vulnerabilities?format=xml` → XML

---

## 🛠️ Утилита для конвертации в XML

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

## 📝 Примеры использования

### Просмотр только JSON маршрутов

```bash
python3 scripts/list_routes.py | grep -A 200 "JSON API"
```

### Просмотр только HTML маршрутов

```bash
python3 scripts/list_routes.py | grep -A 100 "HTML СТРАНИЦЫ"
```

### Сохранение в файл

```bash
python3 scripts/list_routes.py > routes_output.txt
```

### Фильтрация по пути

```bash
python3 scripts/list_routes.py | grep "/api/vulnerabilities"
```

---

## 🔗 Связанные документы

- [ROUTES_DOCUMENTATION.md](./ROUTES_DOCUMENTATION.md) - Полная документация по маршрутам
- [scripts/list_routes.py](../scripts/list_routes.py) - Скрипт анализа маршрутов
- [docs/routes_analysis.json](./routes_analysis.json) - JSON файл с анализом

---

**Статус:** ✅ Готово к использованию

