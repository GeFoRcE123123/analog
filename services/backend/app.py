"""
Backend API сервис для Vulnerability Manager
VM: 10.0.88.20
API маршруты + рендеринг HTML страниц
"""
from flask import Flask, request, jsonify, Response, session, render_template, redirect, url_for, flash
from flask_cors import CORS
import json
import time
import logging
from datetime import datetime
from typing import Optional

# Импорты сервисов (без парсеров)
from services.vulnerability_service import VulnerabilityService
from services.operator_service import OperatorService
from services.export_service import ExportService
from services.assignment_manager import AssignmentManager
from services.data_manager import DataManager
from services.analytics_service import analytics_service
from services.auth_service import AuthService
import sys
import os

# Добавляем путь к корню проекта для импортов
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

# Импорты после добавления пути
from models.database import DatabaseManager
from models.postgres_repositories import PostgresVulnerabilityRepository
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config
from flask import stream_with_context
from utils.decorators import login_required, admin_required
from flask_wtf import CSRFProtect

# Настройка логирования
logging.basicConfig(level=getattr(logging, Config.LOG_LEVEL))
logger = logging.getLogger(__name__)

# Создание Flask приложения
app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = Config.SECRET_KEY

# CORS для работы с frontend
CORS(app, origins=[Config.FRONTEND_URL], supports_credentials=True)

# CSRF защита
csrf = CSRFProtect(app)

# Подключение к БД
db_manager = DatabaseManager()
db_manager.configure(
    host=Config.DATABASE_CONFIG.host,
    port=Config.DATABASE_CONFIG.port,
    database=Config.DATABASE_CONFIG.database,
    username=Config.DATABASE_CONFIG.username,
    password=Config.DATABASE_CONFIG.password
)

if not db_manager.connect():
    logger.error("Не удалось подключиться к базе данных")
    raise ConnectionError("Database connection failed")

db = db_manager.connection

# Создаем репозиторий
if Config.USE_LEGACY_SCHEMA:
    vulnerability_repo = LegacyVulnerabilityRepository(db)
    logger.info("Используется legacy схема БД")
else:
    vulnerability_repo = PostgresVulnerabilityRepository(db)
    logger.info("Используется modern схема БД")

# Инициализация сервисов
auth_service = AuthService()
# Используем стандартный репозиторий (не optimized), так как optimized_postgres_repositories требует psycopg2
vuln_service = VulnerabilityService(use_optimized=False)
operator_service = OperatorService()
export_service = ExportService()
data_manager = DataManager()
assignment_manager = AssignmentManager(data_manager)

logger.info(f"Backend API запущен на {Config.BACKEND_HOST}:{Config.BACKEND_PORT}")


# === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===

def get_vulnerabilities_with_operators(page: int = 1, per_page: int = 50,
                                       status: Optional[str] = None, 
                                       severity: Optional[str] = None,
                                       search: Optional[str] = None):
    """Получить уязвимости с операторами с пагинацией"""
    vulnerabilities, total_count = vuln_service.get_paginated_vulnerabilities(
        page=page, per_page=per_page,
        status=status, severity=severity, search=search
    )
    operators = operator_service.get_all_operators()
    return vulnerabilities, operators, total_count


def get_vulnerabilities_with_operators_old():
    """Получить уязвимости с операторами (старый API)"""
    vulnerabilities = vuln_service.get_all_vulnerabilities()
    operators = operator_service.get_all_operators()
    return vulnerabilities, operators

def get_dashboard_stats():
    """Получить статистику для дашборда"""
    vulnerabilities, operators = get_vulnerabilities_with_operators_old()
    return {
        'total_vulnerabilities': len(vulnerabilities),
        'high_risk': len([v for v in vulnerabilities if v.severity == 'high']),
        'new_vulnerabilities': len([v for v in vulnerabilities if v.status == 'new']),
        'completion_rate': (len([v for v in vulnerabilities if v.status in ['completed', 'approved']]) / len(vulnerabilities) * 100) if vulnerabilities else 0,
        'active_operators': len(operators),
        'total_operators': len(operators)
    }

def get_analytics_data():
    """Получить данные для аналитики"""
    from services.analytics_service import analytics_service
    analytics_data = analytics_service.get_analytics_data()
    vulnerabilities, operators = get_vulnerabilities_with_operators_old()
    result = {
        'vulnerabilities': vulnerabilities,
        'operators': operators,
        'severity_counts': analytics_data.get('severity_counts', {}),
        'status_counts': analytics_data.get('status_counts', {}),
        'total_vulnerabilities': analytics_data.get('total_vulnerabilities', 0),
        'active_operators': analytics_data.get('active_operators', 0),
        'completed_vulnerabilities': analytics_data.get('completed_vulnerabilities', 0),
        'avg_performance': analytics_data.get('avg_performance', 0),
        'cvss_distribution': analytics_data.get('cvss_distribution', {}),
        'risk_levels': analytics_data.get('risk_levels', {})
    }
    return result


def serialize_vulnerability(vuln):
    """Сериализовать уязвимость для JSON"""
    operator_name = None
    if vuln.assigned_operator:
        operator = operator_service.get_operator_by_id(vuln.assigned_operator)
        operator_name = operator.name if operator else None
    
    return {
        'id': vuln.id,
        'title': vuln.title,
        'description': vuln.description,
        'severity': vuln.severity,
        'status': vuln.status,
        'cvss_score': vuln.cvss_score,
        'category': vuln.category,
        'assigned_operator': operator_name
    }


# === HTML МАРШРУТЫ ДЛЯ РЕНДЕРИНГА СТРАНИЦ ===

@app.route('/')
def index():
    """Главная страница"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('auth_login'))

@app.route('/auth/login', methods=['GET', 'POST'])
def auth_login():
    """Страница входа"""
    from services.forms import LoginForm
    form = LoginForm()
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        user = auth_service.authenticate(email, password, ip, user_agent)
        if user:
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['username'] = user['username']
            session['email'] = user['email']
            session['full_name'] = user.get('full_name') or user['username']
            session.permanent = True
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный email или пароль', 'error')
    
    return render_template('auth/login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    """Страница дашборда"""
    vulnerabilities, operators = get_vulnerabilities_with_operators_old()
    stats = get_dashboard_stats()
    
    my_vulnerabilities = []
    if session.get('role') == 'user':
        my_vulnerabilities = vuln_service.get_vulnerabilities_by_operator(session['user_id'])
    
    return render_template('dashboard.html',
                           vulnerabilities=vulnerabilities,
                           operators=operators,
                           stats=stats,
                           my_vulnerabilities=my_vulnerabilities)

@app.route('/profile')
@login_required
def profile():
    """Страница профиля"""
    operator_id = session['user_id']
    assigned_vulns = vuln_service.get_vulnerabilities_by_operator(operator_id)
    return render_template('profile.html', vulnerabilities=assigned_vulns)

@app.route('/vulnerabilities')
@login_required
def vulnerabilities_list():
    """Страница со всеми уязвимостями"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    status = request.args.get('status', None)
    severity = request.args.get('severity', None)
    search = request.args.get('search', None)
    
    vulnerabilities, operators, total_count = get_vulnerabilities_with_operators(
        page=page, per_page=per_page,
        status=status, severity=severity, search=search
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
                           search=search)

@app.route('/operators')
@login_required
@admin_required
def operators_page():
    """Страница операторов"""
    vulnerabilities, operators = get_vulnerabilities_with_operators_old()
    return render_template('operators.html',
                           vulnerabilities=vulnerabilities,
                           operators=operators)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    """Страница управления пользователями"""
    query = "SELECT id, username, email, role, is_active, created_at FROM users ORDER BY created_at DESC"
    users = db_manager.execute_query(query)
    users_list = []
    for row in users:
        users_list.append({
            'id': row[0],
            'username': row[1],
            'email': row[2],
            'role': row[3],
            'is_active': row[4],
            'created_at': row[5].strftime('%Y-%m-%d %H:%M') if row[5] else ''
        })
    return render_template('admin/users.html', users=users_list)

@app.route('/performance')
@login_required
def performance_analytics():
    """Страница аналитики"""
    try:
        analytics_data = get_analytics_data()
        return render_template('performance_analytics.html', **analytics_data)
    except Exception as e:
        flash(f'Ошибка при загрузке аналитики: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/review')
@login_required
@admin_required
def review_vulnerabilities():
    """Страница проверки уязвимостей"""
    operators = operator_service.get_all_operators()
    return render_template('review.html', operators=operators)

@app.route('/import-excel')
@login_required
def import_excel_page():
    """Страница импорта Excel"""
    return render_template('import_excel.html')

@app.route('/parsers')
@login_required
@admin_required
def parsers_page():
    """Страница парсеров"""
    return render_template('parsers.html')

@app.route('/my-assignments')
@login_required
def my_assignments():
    """Мои назначения"""
    assigned_vulns = vuln_service.get_vulnerabilities_by_operator(session['user_id'])
    return render_template('my_assignments.html', vulnerabilities=assigned_vulns)

@app.route('/auth/logout')
def auth_logout():
    """Выход из системы"""
    session.clear()
    flash('Вы успешно вышли из системы.', 'info')
    return redirect(url_for('auth_login'))


# === API МАРШРУТЫ ДЛЯ АВТОРИЗАЦИИ ===

@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    """API авторизации"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        user = auth_service.authenticate(email, password, ip, user_agent)
        if user:
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['username'] = user['username']
            session['full_name'] = user.get('full_name') or user['username']
            session.permanent = True
            
            return jsonify({
                'success': True,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'role': user['role'],
                    'full_name': user.get('full_name')
                }
            })
        else:
            return jsonify({'success': False, 'error': 'Неверный email или пароль'}), 401
    except Exception as e:
        logger.error(f"Auth error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/auth/logout', methods=['POST'])
def api_auth_logout():
    """API выхода"""
    session.clear()
    return jsonify({'success': True})


@app.route('/api/auth/check', methods=['GET'])
def api_auth_check():
    """Проверка авторизации"""
    if 'user_id' in session:
        return jsonify({
            'success': True,
            'authenticated': True,
            'user': {
                'id': session.get('user_id'),
                'username': session.get('username'),
                'role': session.get('role'),
                'full_name': session.get('full_name')
            }
        })
    return jsonify({'success': True, 'authenticated': False})


# === API МАРШРУТЫ ДЛЯ ДАШБОРДА ===

@app.route('/api/dashboard-stats', methods=['GET'])
def api_dashboard_stats():
    """Получить статистику для дашборда"""
    try:
        stats = get_dashboard_stats()
        return jsonify({'success': True, 'stats': stats})
    except Exception as e:
        logger.error(f"Dashboard stats error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# === API МАРШРУТЫ ДЛЯ УЯЗВИМОСТЕЙ ===

@app.route('/api/vulnerabilities', methods=['GET'])
def api_vulnerabilities():
    """Получить список уязвимостей с пагинацией"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        status = request.args.get('status')
        severity = request.args.get('severity')
        search = request.args.get('search')
        
        vulnerabilities, operators, total_count = get_vulnerabilities_with_operators(
            page=page, per_page=per_page,
            status=status, severity=severity, search=search
        )
        
        return jsonify({
            'success': True,
            'vulnerabilities': [serialize_vulnerability(v) for v in vulnerabilities],
            'operators': [{'id': op.id, 'name': op.name, 'email': op.email} for op in operators],
            'total_count': total_count,
            'page': page,
            'per_page': per_page,
            'total_pages': (total_count + per_page - 1) // per_page
        })
    except Exception as e:
        logger.error(f"Vulnerabilities API error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vulnerabilities/<int:vuln_id>', methods=['GET'])
def api_get_vulnerability(vuln_id):
    """Получить уязвимость по ID"""
    try:
        vulnerability = vuln_service.get_vulnerability_by_id(vuln_id)
        if vulnerability:
            return jsonify({'success': True, 'vulnerability': serialize_vulnerability(vulnerability)})
        return jsonify({'success': False, 'error': 'Уязвимость не найдена'}), 404
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vulnerabilities/<int:vuln_id>', methods=['PUT'])
def api_update_vulnerability(vuln_id):
    """Обновить уязвимость"""
    try:
        data = request.get_json()
        updates = data.get('updates', {})
        success = vuln_service.update_vulnerability(vuln_id, **updates)
        return jsonify({'success': success})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# === API МАРШРУТЫ ДЛЯ ОПЕРАТОРОВ ===

@app.route('/api/operators', methods=['GET'])
def api_operators():
    """Получить список операторов"""
    try:
        operators = operator_service.get_all_operators()
        return jsonify({
            'success': True,
            'operators': [{
                'id': op.id,
                'name': op.name,
                'email': op.email,
                'current_metric': op.current_metric,
                'experience_level': op.experience_level
            } for op in operators]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/operators', methods=['POST'])
def api_create_operator():
    """Создать оператора"""
    try:
        data = request.get_json()
        name = data.get('name')
        email = data.get('email')
        experience_level = float(data.get('experience_level', 50.0))
        
        if not name or not email:
            return jsonify({'success': False, 'error': 'Имя и email обязательны'}), 400
        
        new_operator = operator_service.create_operator(name, email, experience_level)
        return jsonify({
            'success': True,
            'operator': {
                'id': new_operator.id,
                'name': new_operator.name,
                'email': new_operator.email
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# === API МАРШРУТЫ ДЛЯ НАЗНАЧЕНИЙ ===

@app.route('/api/assign-operator', methods=['POST'])
def api_assign_operator():
    """Назначить оператора уязвимости"""
    try:
        data = request.get_json()
        vuln_id = data.get('vulnerability_id')
        operator_id = data.get('operator_id')
        
        if not vuln_id or not operator_id:
            return jsonify({'success': False, 'message': 'Не указаны ID уязвимости или оператора'}), 400
        
        result = assignment_manager.assign_operator_to_vulnerability(vuln_id, operator_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/assign-multiple', methods=['POST'])
def api_assign_multiple():
    """Назначить несколько уязвимостей оператору"""
    try:
        data = request.get_json()
        operator_id = data.get('operator_id')
        vulnerability_ids = data.get('vulnerability_ids', [])
        
        if not operator_id or not vulnerability_ids:
            return jsonify({'success': False, 'message': 'Не указаны ID оператора или уязвимостей'}), 400
        
        result = assignment_manager.assign_multiple_vulnerabilities(operator_id, vulnerability_ids)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/unassign-vulnerability', methods=['POST'])
def api_unassign_vulnerability():
    """Снять назначение с уязвимости"""
    try:
        data = request.get_json()
        vuln_id = data.get('vulnerability_id')
        
        if not vuln_id:
            return jsonify({'success': False, 'message': 'Не указан ID уязвимости'}), 400
        
        result = assignment_manager.unassign_vulnerability(vuln_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# === API МАРШРУТЫ ДЛЯ АНАЛИТИКИ ===

@app.route('/api/analytics/refresh', methods=['GET'])
def api_refresh_analytics():
    """Обновить аналитику"""
    try:
        analytics_service.invalidate_cache()
        analytics_data = analytics_service.get_analytics_data(force_refresh=True)
        return jsonify({'success': True, 'data': analytics_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/analytics/current', methods=['GET'])
def api_current_analytics():
    """Получить текущую аналитику"""
    try:
        analytics_data = analytics_service.get_analytics_data()
        return jsonify({'success': True, 'data': analytics_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# === API МАРШРУТЫ ДЛЯ ПАРСЕРОВ (статусы, без запуска) ===

@app.route('/api/parsers/status', methods=['GET'])
def api_parsers_status():
    """Получить статус парсеров"""
    try:
        # Базовая информация о парсерах
        # Реальные статусы будут приходить с VM парсеров
        return jsonify({
            'success': True,
            'parsers': {
                'osv': {'status': 'available', 'note': 'Запускается на VM 10.0.88.23'},
                'nvd': {'status': 'available', 'note': 'Запускается на VM 10.0.88.23'},
                'redhat': {'status': 'available', 'note': 'Запускается на VM 10.0.88.23'},
                'scheduler': {'status': 'available', 'note': 'Запускается на VM 10.0.88.23'}
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# === HEALTH CHECK ===

@app.route('/api/health', methods=['GET'])
def api_health():
    """Проверка здоровья сервиса"""
    try:
        # Проверка подключения к БД
        db_status = db_manager.is_connected()
        
        return jsonify({
            'status': 'healthy' if db_status else 'degraded',
            'database': 'connected' if db_status else 'disconnected',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500


if __name__ == '__main__':
    app.run(host=Config.BACKEND_HOST, port=Config.BACKEND_PORT, debug=False)

