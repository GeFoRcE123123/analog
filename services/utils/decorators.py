# utils/decorators.py
from functools import wraps
from flask import session, redirect, url_for, jsonify, request
from models.database import DatabaseManager

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.is_json:
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('auth_login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            if request.is_json:
                return jsonify({'error': 'Admin access required'}), 403
            flash('Доступ запрещён: требуется роль администратора', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            role = session.get('role')
            # Простая реализация: admin имеет все права
            if role == 'admin':
                return f(*args, **kwargs)
            # Для user — проверка по списку разрешённых действий
            allowed_for_user = {
                'upload_excel', 'view_vulnerabilities', 'view_general_stats', 'change_status'
            }
            if permission in allowed_for_user:
                return f(*args, **kwargs)
            return jsonify({'error': 'Insufficient permissions'}), 403
        return decorated_function
    return decorator