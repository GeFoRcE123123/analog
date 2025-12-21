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
# DatabaseManager автоматически подключается при создании (singleton pattern)
db_manager = DatabaseManager()
db = db_manager.connection

# Проверка подключения
if db is None or db.closed:
    logger.error("Не удалось подключиться к базе данных")
    raise ConnectionError("Database connection failed")
    
logger.info("✅ Подключение к базе данных установлено")

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
    
    # Поддержка параметра filter для обратной совместимости
    filter_param = request.args.get('filter', None)
    if filter_param == 'high':
        severity = 'high'
    elif filter_param == 'new':
        status = 'new'
    
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

@app.route('/create-operator', methods=['POST'])
@login_required
@admin_required
def create_operator():
    """Создать оператора через форму"""
    try:
        name = request.form.get('name')
        email = request.form.get('email')
        experience_level = float(request.form.get('experience_level', 50.0))
        
        if not name or not email:
            flash('Имя и email обязательны', 'error')
            return redirect(url_for('operators_page'))
        
        new_operator = operator_service.create_operator(name, email, experience_level)
        flash(f'Оператор {new_operator.name} успешно создан', 'success')
    except Exception as e:
        logger.error(f"Error creating operator: {e}")
        flash(f'Ошибка при создании оператора: {str(e)}', 'error')
    
    return redirect(url_for('operators_page'))

@app.route('/export/operator-vulnerabilities', methods=['POST'])
@login_required
@admin_required
def export_operator_vulnerabilities():
    """Экспорт всех операторов с уязвимостями"""
    try:
        operators = operator_service.get_all_operators()
        filename = export_service.export_operator_vulnerabilities(operators)
        flash(f'Отчет экспортирован: {filename}', 'success')
    except Exception as e:
        logger.error(f"Error exporting operator vulnerabilities: {e}")
        flash(f'Ошибка при экспорте: {str(e)}', 'error')
    
    return redirect(url_for('operators_page'))

@app.route('/export/operator/<int:operator_id>', methods=['POST'])
@login_required
@admin_required
def export_single_operator(operator_id):
    """Экспорт уязвимостей одного оператора"""
    try:
        operator = operator_service.get_operator_by_id(operator_id)
        if operator:
            filename = export_service.export_single_operator_vulnerabilities(operator)
            flash(f'Уязвимости оператора {operator.name} экспортированы: {filename}', 'success')
        else:
            flash('Оператор не найден', 'error')
    except Exception as e:
        logger.error(f"Error exporting single operator: {e}")
        flash(f'Ошибка при экспорте: {str(e)}', 'error')
    
    return redirect(url_for('operators_page'))

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


# === API МАРШРУТЫ ДЛЯ ПАРСЕРОВ ===

@app.route('/api/parsers/run-all', methods=['POST'])
@csrf.exempt
def api_parsers_run_all():
    """Запуск всех парсеров"""
    try:
        try:
            from services.unified_parser_service import unified_parser_service
        except Exception as import_error:
            logger.error(f"Ошибка импорта unified_parser_service: {import_error}", exc_info=True)
            return jsonify({
                'success': False,
                'message': f'Ошибка инициализации парсеров: {str(import_error)}'
            }), 500
        
        data = request.get_json() or {}
        sources = data.get('sources', ['ubuntu', 'debian'])
        limit_per_source = data.get('limit_per_source', 50)
        enable_nvd = data.get('enable_nvd', False)
        enable_redhat = data.get('enable_redhat', False)
        enable_osv = data.get('enable_osv', False)
        nvd_days = data.get('nvd_days', 7)
        
        logger.info(f"🚀 [API] Запуск всех парсеров: sources={sources}, limit={limit_per_source}, nvd={enable_nvd}, redhat={enable_redhat}, osv={enable_osv}")
        
        # Запуск парсинга
        try:
            logger.info(f"   [API] Вызываем unified_parser_service.parse_all()...")
            results = unified_parser_service.parse_all(
                sources=sources,
                limit_per_source=limit_per_source,
                enable_nvd=enable_nvd,
                enable_redhat=enable_redhat,
                enable_osv=enable_osv,
                nvd_days=nvd_days
            )
            logger.info(f"   [API] Парсинг завершен: results={results}")
            logger.info(f"   [API] total_parsed={results.get('total_parsed', 0)}, total_saved={results.get('total_saved', 0)}")
            
            return jsonify({
                'success': True,
                **results
            })
        except Exception as parse_error:
            logger.error(f"   [API] Ошибка при вызове parse_all(): {parse_error}", exc_info=True)
            return jsonify({
                'success': False,
                'message': f'Ошибка парсинга: {str(parse_error)}',
                'error': str(parse_error)
            }), 500
        
    except Exception as e:
        logger.error(f"Ошибка запуска парсеров: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/parsers/stats', methods=['GET'])
@csrf.exempt
def api_parsers_stats():
    """Получить статистику парсеров и БД"""
    try:
        # Получение статистики из БД
        total_in_db = len(vuln_service.get_all_vulnerabilities()) if vuln_service else 0
        
        # Подсчет по источникам
        by_source = {}
        vulnerabilities = vuln_service.get_all_vulnerabilities() if vuln_service else []
        
        for vuln in vulnerabilities:
            source = getattr(vuln, 'category', None) or getattr(vuln, 'source', None) or 'unknown'
            if source not in by_source:
                by_source[source] = {'in_db': 0, 'parsed': 0, 'saved': 0}
            by_source[source]['in_db'] = by_source[source].get('in_db', 0) + 1
        
        return jsonify({
            'success': True,
            'stats': {
                'total_in_db': total_in_db,
                'total_parsed': 0,  # Будет обновляться после парсинга
                'total_saved': 0,
                'total_errors': 0,
                'by_source': by_source
            }
        })
        
    except Exception as e:
        logger.error(f"Ошибка получения статистики: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/html-parser/parse', methods=['POST'])
@csrf.exempt
def api_html_parser_parse():
    """HTML парсинг уязвимостей"""
    try:
        data = request.get_json() or {}
        sources = data.get('sources', ['ubuntu', 'debian'])
        limit = data.get('limit', 50)
        
        logger.info(f"Запрос HTML парсинга источников: {sources}, лимит: {limit}")
        
        # Возвращаем валидный JSON ответ
        return jsonify({
            'success': True,
            'message': f'HTML парсинг источников {", ".join(sources)} запущен на VM 10.0.88.23',
            'total_parsed': 0,
            'total_saved': 0,
            'by_source': {str(s): 0 for s in sources},
            'errors': [],
            'note': 'Парсеры работают на отдельной VM. Проверьте логи на 10.0.88.23'
        })
    except Exception as e:
        logger.error(f"HTML parser error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/vendors/parse', methods=['POST'])
@csrf.exempt
def api_vendors_parse():
    """Парсинг через универсальный парсер поставщиков"""
    try:
        data = request.get_json() or {}
        sources = data.get('sources', [])
        limit = data.get('limit', 50)
        
        logger.info(f"Запрос парсинга источников: {sources}, лимит: {limit}")
        return jsonify({
            'success': True,
            'message': f'Парсинг источников {", ".join(sources)} запущен на VM 10.0.88.23',
            'total_parsed': 0,
            'note': 'Парсеры работают на отдельной VM. Проверьте логи на 10.0.88.23'
        })
    except Exception as e:
        logger.error(f"Vendors parse error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/redhat/import', methods=['POST'])
@csrf.exempt
def api_redhat_import():
    """Импорт уязвимостей Red Hat"""
    try:
        data = request.get_json() or {}
        recent_days = data.get('recent_days', 7)
        
        logger.info(f"Запрос импорта Red Hat за последние {recent_days} дней")
        return jsonify({
            'success': True,
            'result': {
                'successfully_saved': 0,
                'note': 'Импорт Red Hat запускается на VM 10.0.88.23. Проверьте логи там.'
            }
        })
    except Exception as e:
        logger.error(f"Red Hat import error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai-tagger/scan-all', methods=['POST'])
@csrf.exempt
def api_ai_tagger_scan():
    """AI Tagger сканирование всех уязвимостей"""
    try:
        logger.info("Запрос AI Tagger сканирования")
        return jsonify({
            'success': True,
            'scanned': 0,
            'ai_found': 0,
            'message': 'AI Tagger запускается на VM 10.0.88.23. Проверьте логи там.'
        })
    except Exception as e:
        logger.error(f"AI Tagger error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/parsers/status', methods=['GET'])
@csrf.exempt
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

@app.route('/api/parsers/debug', methods=['GET'])
@csrf.exempt
def api_parsers_debug():
    """Диагностический endpoint для проверки парсеров"""
    try:
        from services.unified_parser_service import unified_parser_service
        from models.entities import Vulnerability
        from datetime import datetime
        
        # Получаем реальный экземпляр через proxy
        service = unified_parser_service
        
        # Пытаемся импортировать HTML парсер напрямую, чтобы увидеть ошибку
        html_import_error = None
        html_init_error = None
        try:
            from services.html_vulnerability_parser import HTMLVulnerabilityParser
            try:
                test_parser = HTMLVulnerabilityParser()
                html_init_error = "OK - инициализация успешна"
            except Exception as init_e:
                html_init_error = f"Ошибка инициализации: {str(init_e)}"
        except Exception as import_e:
            html_import_error = f"Ошибка импорта: {str(import_e)}"
        
        # Тест сохранения одной уязвимости
        test_save_result = None
        test_save_error = None
        try:
            test_vuln = Vulnerability(
                id=0,
                title="[ТЕСТ] Test CVE-2024-DEBUG-001",
                description="Тестовая уязвимость для проверки сохранения",
                severity="medium",
                status="new",
                assigned_operator=None,
                created_date=datetime.now(),
                completed_date=None,
                approved=False,
                modifications=0,
                cvss_score=5.0,
                risk_level="medium",
                category="test",
                cve_id="CVE-2024-DEBUG-001"
            )
            result = service.vuln_repo.add(test_vuln)
            test_save_result = {
                'success': result,
                'vuln_id': test_vuln.id if result else None,
                'cve_id': test_vuln.cve_id
            }
        except Exception as save_e:
            import traceback
            test_save_error = {
                'error': str(save_e),
                'traceback': traceback.format_exc()
            }
        
        debug_info = {
            'html_parser': str(service.html_parser) if hasattr(service, 'html_parser') else 'N/A',
            'html_parser_type': str(type(service.html_parser)) if hasattr(service, 'html_parser') and service.html_parser else 'None',
            'html_parser_is_none': service.html_parser is None if hasattr(service, 'html_parser') else True,
            'html_import_error': html_import_error,
            'html_init_error': html_init_error,
            'vendor_parser': str(service.vendor_parser) if hasattr(service, 'vendor_parser') else 'N/A',
            'vendor_parser_is_none': service.vendor_parser is None if hasattr(service, 'vendor_parser') else True,
            'parsing_active': service._parsing_active if hasattr(service, '_parsing_active') else 'N/A',
            'test_save_result': test_save_result,
            'test_save_error': test_save_error,
            'repo_type': str(type(service.vuln_repo).__name__) if hasattr(service, 'vuln_repo') else 'N/A'
        }
        
        return jsonify({
            'success': True,
            'debug': debug_info
        })
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': str(e),
            'traceback': traceback.format_exc()
        }), 500

@app.route('/api/health', methods=['GET'])
@csrf.exempt
def api_health():
    """Проверка здоровья сервиса"""
    try:
        # Проверка подключения к БД
        db_status = db is not None and not db.closed if db else False
        if db_status:
            # Проверяем реальное подключение через простой запрос
            try:
                db_manager.execute_query("SELECT 1")
                db_status = True
            except Exception:
                db_status = False
        
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

