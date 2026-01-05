# 🎯 Техническое задание: Система авторизации с ролями и адаптивным UI

## 📋 Обзор

Реализовать систему ролевого доступа с тремя уровнями прав:
- **Admin** — полный доступ
- **Operator** — работа только с назначенными уязвимостями
- **User** — просмотр уязвимостей без управления

---

## 1. Обновление структуры БД

### 1.1. Обновить таблицу `users`

**Файл**: `models/database.py` → метод `create_tables()`

**Текущее состояние** (строка 64):
```python
role VARCHAR(20) CHECK (role IN ('admin', 'user')) DEFAULT 'user',
```

**Изменить на**:
```python
role VARCHAR(20) CHECK (role IN ('admin', 'operator', 'user')) DEFAULT 'user',
```

**Действия**:
1. Обновить CHECK constraint в SQL-запросе создания таблицы
2. Создать миграционный скрипт для обновления существующей таблицы:
   ```sql
   ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
   ALTER TABLE users ADD CONSTRAINT users_role_check 
       CHECK (role IN ('admin', 'operator', 'user'));
   ```

---

## 2. Обновление AuthService

### 2.1. Добавить метод `get_user_by_id()`

**Файл**: `services/auth_service.py`

**Добавить после метода `_get_user_by_email()`** (после строки 66):

```python
def get_user_by_id(self, user_id: int) -> Optional[dict]:
    """Получить пользователя по ID"""
    query = """
        SELECT id, username, email, password_hash, role, is_active, is_locked,
               locked_until, failed_login_attempts, full_name, department
        FROM users WHERE id = %s
    """
    result = self.db.execute_query(query, (user_id,))
    if result:
        row = result[0]
        return {
            'id': row[0], 'username': row[1], 'email': row[2], 
            'password_hash': row[3], 'role': row[4], 'is_active': row[5], 
            'is_locked': row[6], 'locked_until': row[7],
            'failed_login_attempts': row[8], 'full_name': row[9],
            'department': row[10] if len(row) > 10 else None
        }
    return None
```

### 2.2. Обновить метод `create_user()`

**Файл**: `services/auth_service.py` → строка 99

**Текущее состояние**:
```python
if role not in ('admin', 'user'):
    return False
```

**Изменить на**:
```python
if role not in ('admin', 'operator', 'user'):
    return False
```

### 2.3. Обновить метод `_get_user_by_email()`

**Файл**: `services/auth_service.py` → строка 52

**Текущее состояние**: возвращает `full_name`, но не `department`

**Обновить SELECT запрос**:
```python
query = """
    SELECT id, username, email, password_hash, role, is_active, is_locked,
           locked_until, failed_login_attempts, full_name, department
    FROM users WHERE email = %s
"""
```

**И обновить возвращаемый словарь**:
```python
return {
    'id': row[0], 'username': row[1], 'email': row[2], 'password_hash': row[3],
    'role': row[4], 'is_active': row[5], 'is_locked': row[6], 'locked_until': row[7],
    'failed_login_attempts': row[8], 'full_name': row[9],
    'department': row[10] if len(row) > 10 else None
}
```

---

## 3. Создание декораторов доступа

### 3.1. Добавить `@operator_required` и `@user_required`

**Файл**: `utils/decorators.py`

**Добавить после `@admin_required`** (после строки 25):

```python
def operator_required(f):
    """Требуется роль admin или operator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        role = session.get('role')
        if role not in ('admin', 'operator'):
            if request.is_json:
                return jsonify({'error': 'Operator access required'}), 403
            from flask import flash
            flash('Доступ запрещён: требуется роль оператора или администратора', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def user_required(f):
    """Требуется любая роль (admin, operator, user)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        role = session.get('role')
        if role not in ('admin', 'operator', 'user'):
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 403
            return redirect(url_for('auth_login'))
        return f(*args, **kwargs)
    return decorated_function
```

**Важно**: Добавить импорт `flash` в начало файла, если его нет:
```python
from flask import session, redirect, url_for, jsonify, request, flash
```

---

## 4. Создание функции получения уязвимостей по ролям

### 4.1. Добавить `get_vulnerabilities_for_user()`

**Файл**: `app.py` → после функции `get_vulnerabilities_with_operators_old()` (после строки 97)

**Добавить новую функцию**:

```python
def get_vulnerabilities_for_user(user_id: int, role: str, page: int = 1, per_page: int = 50,
                                 status: Optional[str] = None, severity: Optional[str] = None,
                                 search: Optional[str] = None):
    """
    Получить уязвимости в зависимости от роли пользователя
    
    Args:
        user_id: ID пользователя
        role: Роль пользователя ('admin', 'operator', 'user')
        page: Номер страницы
        per_page: Элементов на странице
        status: Фильтр по статусу
        severity: Фильтр по серьезности
        search: Поисковый запрос
    
    Returns:
        tuple: (vulnerabilities, operators, total_count)
    """
    operators = operator_service.get_all_operators()
    
    if role == 'admin':
        # Админ видит все уязвимости
        vulnerabilities, total_count = vuln_service.get_paginated_vulnerabilities(
            page=page, per_page=per_page,
            status=status, severity=severity, search=search
        )
    elif role == 'operator':
        # Оператор видит только назначенные ему уязвимости
        query = """
            SELECT v.* FROM vulnerabilities v
            INNER JOIN user_vulnerability_assignments uva ON v.id = uva.vulnerability_id
            WHERE uva.user_id = %s
            AND (%s IS NULL OR v.status = %s)
            AND (%s IS NULL OR v.severity = %s)
            AND (%s IS NULL OR v.title ILIKE %s OR v.description ILIKE %s)
            ORDER BY v.created_date DESC
            LIMIT %s OFFSET %s
        """
        search_pattern = f"%{search}%" if search else None
        offset = (page - 1) * per_page
        
        # Получаем уязвимости
        db_manager = DatabaseManager()
        rows = db_manager.execute_query(
            query, 
            (user_id, status, status, severity, severity, 
             search_pattern, search_pattern, search_pattern,
             per_page, offset)
        )
        
        # Преобразуем в объекты Vulnerability
        from models.entities import Vulnerability
        vulnerabilities = []
        for row in rows:
            vuln = Vulnerability(
                id=row[0], title=row[1], description=row[2],
                severity=row[3], status=row[4], cvss_score=row[9],
                risk_level=row[10], category=row[11]
            )
            vulnerabilities.append(vuln)
        
        # Получаем общее количество
        count_query = """
            SELECT COUNT(*) FROM vulnerabilities v
            INNER JOIN user_vulnerability_assignments uva ON v.id = uva.vulnerability_id
            WHERE uva.user_id = %s
            AND (%s IS NULL OR v.status = %s)
            AND (%s IS NULL OR v.severity = %s)
            AND (%s IS NULL OR v.title ILIKE %s OR v.description ILIKE %s)
        """
        count_result = db_manager.execute_query(
            count_query,
            (user_id, status, status, severity, severity,
             search_pattern, search_pattern, search_pattern)
        )
        total_count = count_result[0][0] if count_result else 0
        
    else:  # role == 'user'
        # Обычный пользователь видит только свои назначенные уязвимости (без пагинации для простоты)
        my_vulns = vuln_service.get_vulnerabilities_by_operator(user_id)
        vulnerabilities = my_vulns[(page-1)*per_page:page*per_page]
        total_count = len(my_vulns)
    
    return vulnerabilities, operators, total_count
```

---

## 5. Обновление маршрутов в app.py

### 5.1. Админские маршруты

**Файл**: `app.py`

**Защитить следующие маршруты декоратором `@admin_required`**:

1. `/parsers` (строка 177) — уже защищён ✓
2. `/admin/users` (строка 243) — добавить `@admin_required`
3. `/operators` (строка 276) — добавить `@admin_required`
4. `/review` (строка 294) — добавить `@admin_required`

**Пример**:
```python
@app.route('/admin/users')
@login_required
@admin_required  # ← ДОБАВИТЬ
def admin_users():
    ...
```

### 5.2. Операторские маршруты

**Создать новые маршруты** (после строки 300):

```python
@app.route('/operator/my-vulnerabilities')
@login_required
@operator_required
def operator_my_vulnerabilities():
    """Страница с назначенными уязвимостями для оператора"""
    user_id = session['user_id']
    role = session['role']
    
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    status = request.args.get('status')
    severity = request.args.get('severity')
    search = request.args.get('search')
    
    vulnerabilities, operators, total_count = get_vulnerabilities_for_user(
        user_id, role, page, per_page, status, severity, search
    )
    
    total_pages = (total_count + per_page - 1) // per_page
    
    return render_template('operator/my_vulnerabilities.html',
                         vulnerabilities=vulnerabilities,
                         operators=operators,
                         current_page=page,
                         total_pages=total_pages,
                         total_count=total_count,
                         per_page=per_page,
                         status=status,
                         severity=severity,
                         search=search)

@app.route('/operator/my-stats')
@login_required
@operator_required
def operator_my_stats():
    """Статистика оператора"""
    user_id = session['user_id']
    my_vulnerabilities = vuln_service.get_vulnerabilities_by_operator(user_id)
    
    stats = {
        'total_assigned': len(my_vulnerabilities),
        'in_progress': len([v for v in my_vulnerabilities if v.status == 'in_progress']),
        'completed': len([v for v in my_vulnerabilities if v.status == 'completed']),
        'high_priority': len([v for v in my_vulnerabilities if v.severity == 'high']),
    }
    
    return render_template('operator/my_stats.html', stats=stats, vulnerabilities=my_vulnerabilities)
```

### 5.3. Обновить маршрут `/import-excel`

**Файл**: `app.py` → строка 213

**Изменить декоратор**:
```python
@app.route('/import-excel')
@login_required
@operator_required  # ← ИЗМЕНИТЬ с @permission_required('upload_excel')
def import_excel_page():
    ...
```

### 5.4. Обновить маршрут `/dashboard`

**Файл**: `app.py` → строка 189

**Обновить логику**:
```python
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session['user_id']
    role = session['role']
    
    # Получаем данные в зависимости от роли
    if role == 'admin':
        vulnerabilities, operators = get_vulnerabilities_with_operators_old()
        stats = get_dashboard_stats()
        my_vulnerabilities = []
    elif role == 'operator':
        my_vulnerabilities = vuln_service.get_vulnerabilities_by_operator(user_id)
        stats = {
            'total_assigned': len(my_vulnerabilities),
            'in_progress': len([v for v in my_vulnerabilities if v.status == 'in_progress']),
            'completed': len([v for v in my_vulnerabilities if v.status == 'completed']),
        }
        vulnerabilities = []
        operators = []
    else:  # user
        my_vulnerabilities = vuln_service.get_vulnerabilities_by_operator(user_id)
        stats = {
            'total_assigned': len(my_vulnerabilities),
        }
        vulnerabilities = []
        operators = []
    
    return render_template('dashboard.html',
                         vulnerabilities=vulnerabilities,
                         operators=operators,
                         stats=stats,
                         my_vulnerabilities=my_vulnerabilities,
                         user_role=role)  # ← ДОБАВИТЬ user_role
```

### 5.5. Обновить маршрут `/vulnerabilities`

**Файл**: `app.py` → строка 219

**Изменить логику получения уязвимостей**:
```python
@app.route('/vulnerabilities')
@login_required
@user_required  # ← ИЗМЕНИТЬ на @user_required
def vulnerabilities_list():
    user_id = session['user_id']
    role = session['role']
    
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    status = request.args.get('status', None)
    severity = request.args.get('severity', None)
    search = request.args.get('search', None)
    
    vulnerabilities, operators, total_count = get_vulnerabilities_for_user(
        user_id, role, page, per_page, status, severity, search
    )
    
    total_pages = (total_count + per_page - 1) // per_page
    
    return render_template('vulnerabilities_list.html',
                         vulnerabilities=vulnerabilities,
                         operators=operators,
                         current_page=page,
                         total_pages=total_pages,
                         total_count=total_count,
                         per_page=per_page,
                         status=status,
                         severity=severity,
                         search=search,
                         user_role=role)  # ← ДОБАВИТЬ
```

---

## 6. Обновление UI (base.html)

### 6.1. Динамическое меню для админа

**Файл**: `templates/base.html` → строка 78

**Текущее состояние**: Некоторые пункты уже скрыты через `{% if session.role == 'admin' %}`

**Обновить навигацию** (строки 78-118):

```html
<div class="hidden md:flex items-center space-x-1 ml-8">
    <!-- Дашборд - для всех -->
    <a href="{{ url_for('dashboard') }}" class="nav-item text-white px-4 py-2 rounded-lg font-medium flex items-center space-x-2">
        <i class="fas fa-chart-dashboard"></i>
        <span>Дашборд</span>
    </a>

    <!-- Уязвимости - для всех -->
    <a href="{{ url_for('vulnerabilities_list') }}" class="nav-item text-white px-4 py-2 rounded-lg font-medium flex items-center space-x-2">
        <i class="fas fa-bug"></i>
        <span>Уязвимости</span>
    </a>

    <!-- Только для админа -->
    {% if session.role == 'admin' %}
    <a href="{{ url_for('operators_page') }}" class="nav-item text-white px-4 py-2 rounded-lg font-medium flex items-center space-x-2">
        <i class="fas fa-users"></i>
        <span>Операторы</span>
    </a>
    <a href="{{ url_for('parsers_page') }}" class="nav-item text-white px-4 py-2 rounded-lg font-medium flex items-center space-x-2">
        <i class="fas fa-cogs"></i>
        <span>Парсеры</span>
    </a>
    <a href="{{ url_for('review_vulnerabilities') }}" class="nav-item text-white px-4 py-2 rounded-lg font-medium flex items-center space-x-2">
        <i class="fas fa-check-double"></i>
        <span>Проверка</span>
    </a>
    {% endif %}

    <!-- Только для оператора -->
    {% if session.role == 'operator' %}
    <a href="{{ url_for('operator_my_vulnerabilities') }}" class="nav-item text-white px-4 py-2 rounded-lg font-medium flex items-center space-x-2">
        <i class="fas fa-tasks"></i>
        <span>Мои уязвимости</span>
    </a>
    <a href="{{ url_for('operator_my_stats') }}" class="nav-item text-white px-4 py-2 rounded-lg font-medium flex items-center space-x-2">
        <i class="fas fa-chart-bar"></i>
        <span>Моя статистика</span>
    </a>
    {% endif %}

    <!-- Аналитика - для админа и оператора -->
    {% if session.role in ['admin', 'operator'] %}
    <a href="{{ url_for('performance_analytics') }}" class="nav-item text-white px-4 py-2 rounded-lg font-medium flex items-center space-x-2">
        <i class="fas fa-chart-line"></i>
        <span>Аналитика</span>
    </a>
    {% endif %}
</div>
```

### 6.2. Обновить кнопку импорта Excel

**Файл**: `templates/base.html` → строка 124

**Изменить условие видимости**:
```html
<!-- Импорт Excel - только для оператора и админа -->
{% if session.role in ['admin', 'operator'] %}
<a href="{{ url_for('import_excel_page') }}" class="bg-green-500 hover:bg-green-600 text-white font-bold py-2 px-4 rounded-lg transition duration-300 flex items-center space-x-2">
    <i class="fas fa-file-excel"></i>
    <span>Импорт Excel</span>
</a>
{% endif %}
```

### 6.3. Обновить выпадающее меню пользователя

**Файл**: `templates/base.html` → строка 143

**Обновить пункты меню**:
```html
<div x-show="open" @click.away="open = false" class="absolute right-0 mt-2 w-56 bg-white rounded-md shadow-lg py-1 z-50">
    <a href="{{ url_for('profile') }}" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
        <i class="fas fa-user-circle mr-2 text-gray-500"></i>Мой профиль
    </a>
    
    {% if session.role == 'operator' %}
    <a href="{{ url_for('operator_my_vulnerabilities') }}" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
        <i class="fas fa-tasks mr-2 text-gray-500"></i>Мои уязвимости
    </a>
    <a href="{{ url_for('operator_my_stats') }}" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
        <i class="fas fa-chart-bar mr-2 text-gray-500"></i>Моя статистика
    </a>
    {% endif %}
    
    <!-- Только для админа -->
    {% if session.role == 'admin' %}
    <a href="{{ url_for('admin_users') }}" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">
        <i class="fas fa-users-gear mr-2 text-gray-500"></i>Управление пользователями
    </a>
    {% endif %}

    <hr class="my-1">
    <a href="{{ url_for('auth_logout') }}" class="block px-4 py-2 text-sm text-red-600 hover:bg-red-50">
        <i class="fas fa-sign-out-alt mr-2 text-red-500"></i>Выйти
    </a>
</div>
```

### 6.4. Добавить отображение роли в шапке

**Файл**: `templates/base.html` → строка 134

**Обновить**:
```html
<span>{{ session.full_name or session.username }}</span>
{% if session.role == 'admin' %}
    <span class="bg-red-500 text-white text-xs px-2 py-0.5 rounded ml-1">Admin</span>
{% elif session.role == 'operator' %}
    <span class="bg-blue-500 text-white text-xs px-2 py-0.5 rounded ml-1">Operator</span>
{% elif session.role == 'user' %}
    <span class="bg-gray-500 text-white text-xs px-2 py-0.5 rounded ml-1">User</span>
{% endif %}
```

---

## 7. Обновление dashboard.html

### 7.1. Добавить условный рендеринг по ролям

**Файл**: `templates/dashboard.html`

**В начале файла добавить проверку роли**:

```html
{% extends 'base.html' %}
{% block content %}

{% if user_role == 'admin' %}
    <!-- Админский дашборд -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <!-- Статистические карточки -->
        <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold text-gray-700 mb-2">Всего уязвимостей</h3>
            <p class="text-3xl font-bold text-blue-600">{{ stats.total_vulnerabilities }}</p>
        </div>
        <!-- ... остальные карточки ... -->
    </div>
    
    <!-- Блок управления пользователями -->
    <div class="bg-white rounded-lg shadow p-6 mb-6">
        <h2 class="text-xl font-bold mb-4">Управление пользователями</h2>
        <div class="flex flex-wrap gap-4">
            <a href="{{ url_for('admin_users') }}" class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded">
                Пользователи
            </a>
            <a href="{{ url_for('operators_page') }}" class="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded">
                Назначить уязвимости
            </a>
        </div>
    </div>

{% elif user_role == 'operator' %}
    <!-- Операторский дашборд -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold text-gray-700 mb-2">Назначено мне</h3>
            <p class="text-3xl font-bold text-blue-600">{{ stats.total_assigned }}</p>
        </div>
        <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold text-gray-700 mb-2">В работе</h3>
            <p class="text-3xl font-bold text-orange-600">{{ stats.in_progress }}</p>
        </div>
        <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold text-gray-700 mb-2">Завершено</h3>
            <p class="text-3xl font-bold text-green-600">{{ stats.completed }}</p>
        </div>
    </div>
    
    <div class="bg-white rounded-lg shadow p-6 mb-6">
        <h2 class="text-xl font-bold mb-4">Мои уязвимости</h2>
        <a href="{{ url_for('operator_my_vulnerabilities') }}" class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded">
            Просмотр назначенных
        </a>
    </div>

{% else %}
    <!-- Пользовательский дашборд -->
    <div class="bg-white rounded-lg shadow p-6 mb-6">
        <h2 class="text-xl font-bold mb-4">Мои назначенные уязвимости</h2>
        <p class="text-gray-600 mb-4">Всего назначено: {{ stats.total_assigned }}</p>
        <a href="{{ url_for('vulnerabilities_list') }}" class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded">
            Просмотр уязвимостей
        </a>
    </div>
    
    <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4 mb-6">
        <p class="text-yellow-700">
            <i class="fas fa-info-circle mr-2"></i>
            Вы не можете управлять уязвимостями. Доступен только просмотр.
        </p>
    </div>
{% endif %}

{% endblock %}
```

---

## 8. Создание новых шаблонов

### 8.1. Создать `templates/operator/my_vulnerabilities.html`

```html
{% extends 'base.html' %}

{% block content %}
<h1 class="text-3xl font-bold text-gray-900 mb-6">Мои назначенные уязвимости</h1>

<!-- Фильтры -->
<div class="bg-white rounded-lg shadow p-4 mb-6">
    <form method="GET" class="flex flex-wrap gap-4">
        <input type="text" name="search" placeholder="Поиск..." 
               value="{{ search }}" class="border rounded px-3 py-2">
        <select name="status" class="border rounded px-3 py-2">
            <option value="">Все статусы</option>
            <option value="pending" {% if status == 'pending' %}selected{% endif %}>Ожидает</option>
            <option value="in_progress" {% if status == 'in_progress' %}selected{% endif %}>В работе</option>
            <option value="completed" {% if status == 'completed' %}selected{% endif %}>Завершено</option>
        </select>
        <button type="submit" class="bg-blue-500 text-white px-4 py-2 rounded">Применить</button>
    </form>
</div>

<!-- Таблица уязвимостей -->
<div class="bg-white rounded-lg shadow overflow-hidden">
    <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
            <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Название</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Серьезность</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Статус</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Действия</th>
            </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-200">
            {% for vuln in vulnerabilities %}
            <tr>
                <td class="px-6 py-4 whitespace-nowrap">{{ vuln.title }}</td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="px-2 py-1 text-xs rounded {% if vuln.severity == 'high' %}bg-red-100 text-red-800{% elif vuln.severity == 'medium' %}bg-yellow-100 text-yellow-800{% else %}bg-green-100 text-green-800{% endif %}">
                        {{ vuln.severity }}
                    </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">{{ vuln.status }}</td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <a href="/get-vulnerability/{{ vuln.id }}" class="text-blue-600 hover:text-blue-800">Просмотр</a>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>

<!-- Пагинация -->
{% if total_pages > 1 %}
<div class="mt-6 flex justify-center">
    {% for p in range(1, total_pages + 1) %}
    <a href="?page={{ p }}" class="px-3 py-2 {% if p == current_page %}bg-blue-500 text-white{% else %}bg-white text-gray-700{% endif %} rounded mx-1">
        {{ p }}
    </a>
    {% endfor %}
</div>
{% endif %}
{% endblock %}
```

### 8.2. Создать `templates/operator/my_stats.html`

```html
{% extends 'base.html' %}

{% block content %}
<h1 class="text-3xl font-bold text-gray-900 mb-6">Моя статистика</h1>

<div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
    <div class="bg-white rounded-lg shadow p-6">
        <h3 class="text-lg font-semibold text-gray-700 mb-2">Всего назначено</h3>
        <p class="text-3xl font-bold text-blue-600">{{ stats.total_assigned }}</p>
    </div>
    <div class="bg-white rounded-lg shadow p-6">
        <h3 class="text-lg font-semibold text-gray-700 mb-2">В работе</h3>
        <p class="text-3xl font-bold text-orange-600">{{ stats.in_progress }}</p>
    </div>
    <div class="bg-white rounded-lg shadow p-6">
        <h3 class="text-lg font-semibold text-gray-700 mb-2">Завершено</h3>
        <p class="text-3xl font-bold text-green-600">{{ stats.completed }}</p>
    </div>
    <div class="bg-white rounded-lg shadow p-6">
        <h3 class="text-lg font-semibold text-gray-700 mb-2">Высокий приоритет</h3>
        <p class="text-3xl font-bold text-red-600">{{ stats.high_priority }}</p>
    </div>
</div>

<div class="bg-white rounded-lg shadow p-6">
    <h2 class="text-xl font-bold mb-4">Экспорт данных</h2>
    <a href="{{ url_for('export_vulnerabilities') }}" class="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded">
        Экспорт в Excel
    </a>
</div>
{% endblock %}
```

---

## 9. Адаптивность (мобильная версия)

### 9.1. Добавить мобильное меню

**Файл**: `templates/base.html` → после строки 170

**Добавить мобильное меню**:
```html
<!-- Мобильное меню -->
<div id="mobile-menu" class="hidden md:hidden fixed inset-0 bg-gray-800 bg-opacity-75 z-50">
    <div class="bg-white w-64 h-full p-4">
        <button id="close-mobile-menu" class="text-gray-600 mb-4">
            <i class="fas fa-times text-xl"></i>
        </button>
        <nav class="space-y-2">
            <a href="{{ url_for('dashboard') }}" class="block px-4 py-2 text-gray-700 hover:bg-gray-100 rounded">
                Дашборд
            </a>
            <a href="{{ url_for('vulnerabilities_list') }}" class="block px-4 py-2 text-gray-700 hover:bg-gray-100 rounded">
                Уязвимости
            </a>
            {% if session.role == 'admin' %}
            <a href="{{ url_for('operators_page') }}" class="block px-4 py-2 text-gray-700 hover:bg-gray-100 rounded">
                Операторы
            </a>
            {% endif %}
            {% if session.role == 'operator' %}
            <a href="{{ url_for('operator_my_vulnerabilities') }}" class="block px-4 py-2 text-gray-700 hover:bg-gray-100 rounded">
                Мои уязвимости
            </a>
            {% endif %}
        </nav>
    </div>
</div>

<script>
document.getElementById('mobile-menu-button').addEventListener('click', function() {
    document.getElementById('mobile-menu').classList.remove('hidden');
});
document.getElementById('close-mobile-menu').addEventListener('click', function() {
    document.getElementById('mobile-menu').classList.add('hidden');
});
</script>
```

---

## 10. Миграция БД

### 10.1. Создать скрипт миграции

**Файл**: `migrations/add_operator_role.py`

```python
from models.database import DatabaseManager

def migrate():
    db = DatabaseManager()
    try:
        # Удаляем старый constraint
        db.execute_query("ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check")
        # Добавляем новый constraint с operator
        db.execute_query("""
            ALTER TABLE users ADD CONSTRAINT users_role_check 
            CHECK (role IN ('admin', 'operator', 'user'))
        """)
        print("✅ Миграция выполнена успешно")
    except Exception as e:
        print(f"❌ Ошибка миграции: {e}")

if __name__ == '__main__':
    migrate()
```

---

## 11. Тестирование

### 11.1. Создать тестовых пользователей

```python
from services.auth_service import AuthService

auth = AuthService()
auth.create_user('admin', 'admin@test.com', 'admin123', 'admin', 'Администратор')
auth.create_user('operator1', 'operator@test.com', 'operator123', 'operator', 'Оператор 1')
auth.create_user('user1', 'user@test.com', 'user123', 'user', 'Пользователь 1')
```

### 11.2. Проверка декораторов

- ✅ `/dashboard` доступен всем авторизованным
- ✅ `/admin/users` доступен только админу
- ✅ `/operator/my-vulnerabilities` доступен только оператору и админу
- ✅ `/vulnerabilities` доступен всем авторизованным

---

## ✅ Чеклист выполнения

- [ ] Обновлена таблица `users` (добавлена роль `operator`)
- [ ] Обновлён `AuthService` (метод `get_user_by_id`, поддержка `operator`)
- [ ] Созданы декораторы `@operator_required` и `@user_required`
- [ ] Создана функция `get_vulnerabilities_for_user()`
- [ ] Обновлены маршруты с правильными декораторами
- [ ] Обновлён `base.html` с динамическим меню
- [ ] Обновлён `dashboard.html` с условным рендерингом
- [ ] Создан шаблон `operator/my_vulnerabilities.html`
- [ ] Создан шаблон `operator/my_stats.html`
- [ ] Добавлена мобильная версия меню
- [ ] Выполнена миграция БД
- [ ] Протестированы все роли

---

## 📝 Примечания

1. **Безопасность**: Все маршруты должны быть защищены соответствующими декораторами
2. **Производительность**: Для операторов использовать индексы на `user_vulnerability_assignments`
3. **UX**: Четко показывать пользователю его роль и доступные действия
4. **Адаптивность**: Все страницы должны корректно отображаться на мобильных устройствах

