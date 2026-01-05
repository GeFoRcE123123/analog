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
# Передаем db соединение для использования LegacyVulnerabilityRepository
vuln_service = VulnerabilityService(use_optimized=False, db_connection=db)
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
    try:
        vulnerabilities, total_count = vuln_service.get_paginated_vulnerabilities(
            page=page, per_page=per_page,
            status=status, severity=severity, search=search
        )
        operators = operator_service.get_all_operators()
        logger.info(f"📊 Получено уязвимостей: {len(vulnerabilities)} из {total_count} (страница {page})")
        return vulnerabilities, operators, total_count
    except Exception as e:
        logger.error(f"❌ Ошибка получения уязвимостей: {e}", exc_info=True)
        return [], [], 0


def save_parsing_history(sources, total_parsed, total_saved, total_errors, by_source, settings, status='completed', error_message=None, duration_seconds=0):
    """Сохранить историю парсинга в БД"""
    try:
        import json
        query = """
            INSERT INTO parsing_history (
                sources, total_parsed, total_saved, total_errors, 
                by_source, settings, status, error_message, duration_seconds
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        db_manager.execute_query(
            query,
            (
                sources,
                total_parsed,
                total_saved,
                total_errors,
                json.dumps(by_source),
                json.dumps(settings),
                status,
                error_message,
                duration_seconds
            )
        )
        logger.info(f"✅ История парсинга сохранена: parsed={total_parsed}, saved={total_saved}")
    except Exception as e:
        logger.error(f"❌ Ошибка сохранения истории парсинга: {e}", exc_info=True)


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
    try:
        operator_id = session['user_id']
        assigned_vulns = vuln_service.get_vulnerabilities_by_operator(operator_id)
        logger.debug(f"📊 [profile] Получено {len(assigned_vulns)} уязвимостей для пользователя ID {operator_id}")
        return render_template('profile.html', vulnerabilities=assigned_vulns)
    except Exception as e:
        logger.error(f"❌ [profile] Ошибка загрузки профиля: {e}", exc_info=True)
        flash(f'Ошибка при загрузке профиля: {str(e)}', 'error')
        return render_template('profile.html', vulnerabilities=[])

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

# === ИИ-ИНТЕГРАЦИЯ СТРАНИЦЫ ===

@app.route('/ai/dashboard')
@login_required
def ai_dashboard():
    """Главная страница ИИ-интерфейса"""
    return render_template('ai/dashboard.html')

@app.route('/ai/statistics')
@login_required
def ai_statistics():
    """Страница статистики по ключевым словам"""
    return render_template('ai/statistics.html')

@app.route('/ai/training')
@login_required
@admin_required
def ai_training():
    """Страница управления обучением"""
    return render_template('ai/training.html')

@app.route('/ai/monitoring')
@login_required
@admin_required
def ai_monitoring():
    """Страница управления мониторингом сайтов"""
    return render_template('ai/monitoring.html')

@app.route('/ai/passports')
@login_required
def ai_passports():
    """Страница просмотра паспортов уязвимостей"""
    return render_template('ai/passports.html')

@app.route('/my-assignments')
@login_required
def my_assignments():
    """Мои назначения"""
    assigned_vulns = vuln_service.get_vulnerabilities_by_operator(session['user_id'])
    return render_template('my_assignments.html', vulnerabilities=assigned_vulns)

@app.route('/create-operator', methods=['POST'])
@csrf.exempt
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


@app.route('/get-vulnerability/<int:vuln_id>', methods=['GET'])
@login_required
def get_vulnerability(vuln_id):
    """Получить уязвимость по ID (для фронтенда)"""
    try:
        vulnerability = vuln_service.get_vulnerability_by_id(vuln_id)
        if vulnerability:
            operator_name = None
            operator_id = None
            if vulnerability.assigned_operator:
                operator = operator_service.get_operator_by_id(vulnerability.assigned_operator)
                if operator:
                    operator_name = operator.name
                    operator_id = operator.id
            import json
            
            # Подготовка данных уязвимости с новыми NVD полями
            vuln_data = {
                'id': vulnerability.id,
                'title': vulnerability.title,
                'description': vulnerability.description,
                'severity': vulnerability.severity,
                'status': vulnerability.status,
                'cvss_score': vulnerability.cvss_score,
                'risk_level': vulnerability.risk_level,
                'category': vulnerability.category,
                'modifications': vulnerability.modifications,
                'approved': vulnerability.approved,
                'assigned_operator': operator_name,
                'assigned_operator_id': operator_id,
                'cve_id': getattr(vulnerability, 'cve_id', None),
                'created_date': vulnerability.created_date.isoformat() if vulnerability.created_date else None,
                'completed_date': vulnerability.completed_date.isoformat() if vulnerability.completed_date else None,
                # Новые NVD поля
                'cvss_v2_vector': getattr(vulnerability, 'cvss_v2_vector', None),
                'cvss_v3_vector': getattr(vulnerability, 'cvss_v3_vector', None),
                'cvss_v4_vector': getattr(vulnerability, 'cvss_v4_vector', None),
                'cvss_version': getattr(vulnerability, 'cvss_version', None),
                'epss_score': float(getattr(vulnerability, 'epss_score', 0)) if getattr(vulnerability, 'epss_score', None) else None,
                'epss_percentile': float(getattr(vulnerability, 'epss_percentile', 0)) if getattr(vulnerability, 'epss_percentile', None) else None,
                'cwe_ids': getattr(vulnerability, 'cwe_ids', []),
                'affected_products': getattr(vulnerability, 'affected_products', []),
                'references': getattr(vulnerability, 'references', []),
                'vendor_comments': getattr(vulnerability, 'vendor_comments', []),
                'configurations': getattr(vulnerability, 'configurations', []),
                'weaknesses': getattr(vulnerability, 'weaknesses', []),
                'source_identifier': getattr(vulnerability, 'source_identifier', None),
                'nvd_status': getattr(vulnerability, 'vuln_status', None),
                'nvd_published': getattr(vulnerability, 'published', None).isoformat() if getattr(vulnerability, 'published', None) else None,
                'nvd_last_modified': getattr(vulnerability, 'last_modified', None).isoformat() if getattr(vulnerability, 'last_modified', None) else None,
                'nvd_descriptions': getattr(vulnerability, 'descriptions', []),
                'metrics': getattr(vulnerability, 'metrics', {}),
                'has_kev': getattr(vulnerability, 'has_kev', False),
                'has_cert_alerts': getattr(vulnerability, 'has_cert_alerts', False)
            }
            
            return jsonify({
                'success': True,
                'vulnerability': vuln_data
            })
        return jsonify({'success': False, 'message': 'Уязвимость не найдена'}), 404
    except Exception as e:
        logger.error(f"Ошибка получения уязвимости {vuln_id}: {e}", exc_info=True)
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
@csrf.exempt
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
@csrf.exempt
def api_assign_operator():
    """Назначить оператора уязвимости"""
    try:
        data = request.get_json()
        vuln_id = data.get('vulnerability_id')
        operator_id = data.get('operator_id')
        
        if not vuln_id or not operator_id:
            return jsonify({'success': False, 'message': 'Не указаны ID уязвимости или оператора'}), 400
        
        # Используем VulnerabilityService для назначения (работает с legacy схемой)
        success = vuln_service.assign_vulnerability(vuln_id, operator_id)
        if success:
            # Получаем обновленную уязвимость для ответа
            vulnerability = vuln_service.get_vulnerability_by_id(vuln_id)
            operator = operator_service.get_operator_by_id(operator_id)
            
            return jsonify({
                'success': True,
                'message': f'Уязвимость назначена оператору {operator.name if operator else "Unknown"}',
                'vulnerability': {
                    'id': vulnerability.id if vulnerability else vuln_id,
                    'title': vulnerability.title if vulnerability else 'Unknown',
                    'status': vulnerability.status if vulnerability else 'new'
                },
                'operator': {
                    'id': operator.id if operator else operator_id,
                    'name': operator.name if operator else 'Unknown'
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Ошибка назначения оператора'}), 500
    except Exception as e:
        logger.error(f"Ошибка назначения оператора: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/assign-multiple', methods=['POST'])
@csrf.exempt
def api_assign_multiple():
    """Назначить несколько уязвимостей оператору"""
    try:
        data = request.get_json()
        operator_id = data.get('operator_id')
        vulnerability_ids = data.get('vulnerability_ids', [])
        
        if not operator_id or not vulnerability_ids:
            return jsonify({'success': False, 'message': 'Не указаны ID оператора или уязвимостей'}), 400
        
        # Используем VulnerabilityService для назначения каждой уязвимости (работает с legacy схемой)
        assigned_count = 0
        failed_assignments = []
        
        for vuln_id in vulnerability_ids:
            success = vuln_service.assign_vulnerability(vuln_id, operator_id)
            if success:
                assigned_count += 1
            else:
                failed_assignments.append({'vuln_id': vuln_id, 'error': 'Ошибка назначения'})
        
        operator = operator_service.get_operator_by_id(operator_id)
        
        return jsonify({
            'success': True,
            'message': f'Назначено {assigned_count} из {len(vulnerability_ids)} уязвимостей',
            'assigned_count': assigned_count,
            'failed_assignments': failed_assignments,
            'operator': {
                'id': operator.id if operator else operator_id,
                'name': operator.name if operator else 'Unknown'
            }
        })
    except Exception as e:
        logger.error(f"Ошибка массового назначения: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/assign-vulnerabilities', methods=['POST'])
@csrf.exempt
def assign_vulnerabilities():
    """Назначить несколько уязвимостей оператору (старый маршрут для совместимости)"""
    try:
        data = request.get_json()
        operator_id = data.get('operator_id')
        vulnerability_ids = data.get('vulnerability_ids', [])
        
        if not operator_id or not vulnerability_ids:
            return jsonify({'success': False, 'message': 'Не указаны ID оператора или уязвимостей'}), 400
        
        # Используем VulnerabilityService для назначения каждой уязвимости (работает с legacy схемой)
        assigned_count = 0
        failed_assignments = []
        
        for vuln_id in vulnerability_ids:
            success = vuln_service.assign_vulnerability(vuln_id, operator_id)
            if success:
                assigned_count += 1
            else:
                failed_assignments.append({'vuln_id': vuln_id, 'error': 'Ошибка назначения'})
        
        operator = operator_service.get_operator_by_id(operator_id)
        
        return jsonify({
            'success': True,
            'message': f'Назначено {assigned_count} из {len(vulnerability_ids)} уязвимостей',
            'assigned_count': assigned_count,
            'failed_assignments': failed_assignments,
            'operator': {
                'id': operator.id if operator else operator_id,
                'name': operator.name if operator else 'Unknown'
            }
        })
    except Exception as e:
        logger.error(f"Ошибка массового назначения: {e}", exc_info=True)
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
        enable_vendors = data.get('enable_vendors', False)
        vendor_sources = data.get('vendor_sources', [])
        nvd_days = data.get('nvd_days', 7)
        # ⭐ Поддержка Legacy парсеров
        enable_legacy_parsers = data.get('enable_legacy_parsers', False)
        legacy_parser_sources = data.get('legacy_parser_sources', [])
        
        logger.info(f"🚀 [API] Запуск всех парсеров: sources={sources}, limit={limit_per_source}, nvd={enable_nvd}, redhat={enable_redhat}, osv={enable_osv}, vendors={enable_vendors}, vendor_sources={vendor_sources}, legacy={enable_legacy_parsers}, legacy_sources={legacy_parser_sources}")
        
        # Запуск парсинга
        start_time = time.time()
        try:
            logger.info(f"   [API] Вызываем unified_parser_service.parse_all()...")
            results = unified_parser_service.parse_all(
                sources=sources,
                limit_per_source=limit_per_source,
                enable_nvd=enable_nvd,
                enable_redhat=enable_redhat,
                enable_osv=enable_osv,
                enable_vendors=enable_vendors,
                vendor_sources=vendor_sources,
                nvd_days=nvd_days,
                enable_legacy_parsers=enable_legacy_parsers,
                legacy_parser_sources=legacy_parser_sources
            )
            duration = int(time.time() - start_time)
            logger.info(f"   [API] Парсинг завершен: results={results}")
            logger.info(f"   [API] total_parsed={results.get('total_parsed', 0)}, total_saved={results.get('total_saved', 0)}")
            
            # Сохранение истории парсинга
            try:
                save_parsing_history(
                    sources=sources,
                    total_parsed=results.get('total_parsed', 0),
                    total_saved=results.get('total_saved', 0),
                    total_errors=len(results.get('errors', [])),
                    by_source=results.get('by_source', {}),
                    settings={
                        'limit_per_source': limit_per_source,
                        'enable_nvd': enable_nvd,
                        'enable_redhat': enable_redhat,
                        'enable_osv': enable_osv,
                        'nvd_days': nvd_days,
                        'enable_legacy_parsers': enable_legacy_parsers,
                        'legacy_parser_sources': legacy_parser_sources
                    },
                    status='completed',
                    duration_seconds=duration
                )
            except Exception as history_error:
                logger.error(f"Ошибка сохранения истории парсинга: {history_error}", exc_info=True)
            
            # Добавляем детальную информацию о прогрессе в ответ
            response_data = {
                'success': True,
                **results
            }
            
            # Если есть progress_messages, добавляем их
            if 'progress_messages' not in response_data:
                response_data['progress_messages'] = []
            
            return jsonify(response_data)
        except Exception as parse_error:
            duration = int(time.time() - start_time)
            logger.error(f"   [API] Ошибка при вызове parse_all(): {parse_error}", exc_info=True)
            
            # Сохранение истории парсинга с ошибкой
            try:
                save_parsing_history(
                    sources=sources,
                    total_parsed=0,
                    total_saved=0,
                    total_errors=1,
                    by_source={},
                    settings={
                        'limit_per_source': limit_per_source,
                        'enable_nvd': enable_nvd,
                        'enable_redhat': enable_redhat,
                        'enable_osv': enable_osv,
                        'nvd_days': nvd_days,
                        'enable_legacy_parsers': enable_legacy_parsers,
                        'legacy_parser_sources': legacy_parser_sources
                    },
                    status='failed',
                    error_message=str(parse_error),
                    duration_seconds=duration
                )
            except Exception as history_error:
                logger.error(f"Ошибка сохранения истории парсинга: {history_error}", exc_info=True)
            
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
            source = getattr(vuln, 'category', None) or getattr(vuln, 'source', None) or getattr(vuln, 'source_identifier', None) or 'unknown'
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


@app.route('/api/parsers/history', methods=['GET'])
@csrf.exempt
def api_parsers_history():
    """Получить историю сканирования"""
    try:
        limit = int(request.args.get('limit', 10))
        query = """
            SELECT id, scan_date, sources, total_parsed, total_saved, 
                   total_errors, by_source, settings, status, error_message, duration_seconds
            FROM parsing_history
            ORDER BY scan_date DESC
            LIMIT %s
        """
        results = db_manager.execute_query(query, (limit,))
        
        history = []
        for row in results:
            import json
            history.append({
                'id': row[0],
                'scan_date': row[1].isoformat() if row[1] else None,
                'sources': row[2] if row[2] else [],
                'total_parsed': row[3] or 0,
                'total_saved': row[4] or 0,
                'total_errors': row[5] or 0,
                'by_source': row[6] if isinstance(row[6], dict) else (json.loads(row[6]) if row[6] else {}),
                'settings': row[7] if isinstance(row[7], dict) else (json.loads(row[7]) if row[7] else {}),
                'status': row[8] or 'completed',
                'error_message': row[9],
                'duration_seconds': row[10] or 0
            })
        
        return jsonify({
            'success': True,
            'history': history
        })
    except Exception as e:
        logger.error(f"Ошибка получения истории парсинга: {e}", exc_info=True)
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

@app.route('/api/vulnerabilities/clear', methods=['POST'])
@csrf.exempt
@login_required
@admin_required
def api_clear_vulnerabilities():
    """Очистка всех данных по уязвимостям из БД (только для админов)"""
    try:
        data = request.get_json() or {}
        confirm = data.get('confirm', False)
        
        if not confirm:
            return jsonify({
                'success': False,
                'message': 'Требуется подтверждение. Отправьте {"confirm": true}'
            }), 400
        
        logger.warning(f"⚠️  [CLEAR] Пользователь {session.get('user_id')} запросил очистку всех уязвимостей")
        
        with db_manager.connection.cursor() as cursor:
            # Подсчет записей
            tables_to_check = ['turn', 'cvelist', 'cwelist', 'map_table', 'actids', 'parsing_history']
            counts = {}
            
            for table in tables_to_check:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    counts[table] = cursor.fetchone()[0]
                except:
                    counts[table] = 0
            
            total_count = sum(counts.values())
            
            if total_count == 0:
                return jsonify({
                    'success': True,
                    'message': 'База данных уже пуста',
                    'deleted': counts
                })
            
            # Очистка в правильном порядке
            deleted = {}
            
            # 1. actids
            cursor.execute("DELETE FROM actids")
            deleted['actids'] = cursor.rowcount
            
            # 2. map_table
            cursor.execute("DELETE FROM map_table")
            deleted['map_table'] = cursor.rowcount
            
            # 3. cwelist
            cursor.execute("DELETE FROM cwelist")
            deleted['cwelist'] = cursor.rowcount
            
            # 4. cvelist
            cursor.execute("DELETE FROM cvelist")
            deleted['cvelist'] = cursor.rowcount
            
            # 5. turn
            cursor.execute("DELETE FROM turn")
            deleted['turn'] = cursor.rowcount
            
            # 6. parsing_history
            cursor.execute("DELETE FROM parsing_history")
            deleted['parsing_history'] = cursor.rowcount
            
            db_manager.connection.commit()
            
            logger.warning(f"✅ [CLEAR] Очищено {total_count} записей из БД пользователем {session.get('user_id')}")
            
            return jsonify({
                'success': True,
                'message': f'Успешно очищено {total_count} записей',
                'deleted': deleted,
                'total_deleted': total_count
            })
            
    except Exception as e:
        logger.error(f"❌ Ошибка очистки уязвимостей: {e}", exc_info=True)
        if db_manager.connection:
            db_manager.connection.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# === ИИ-ИНТЕГРАЦИЯ API ===

# Условный импорт ИИ-сервиса (может отсутствовать)
try:
    from services.ai_integration_service import ai_integration_service
    AI_SERVICE_AVAILABLE = True
except ImportError:
    AI_SERVICE_AVAILABLE = False
    logger.warning("⚠️ AI Integration Service не доступен (модуль не найден)")

@app.route('/api/ai/analyze', methods=['POST'])
@csrf.exempt
@login_required
def api_ai_analyze():
    """Анализ уязвимости с помощью ИИ"""
    try:
        data = request.get_json()
        vulnerability_data = data.get('vulnerability_data', {})
        
        if not vulnerability_data:
            return jsonify({'error': 'vulnerability_data required'}), 400
        
        if not AI_SERVICE_AVAILABLE:
            return jsonify({"success": False, "error": "AI Integration Service недоступен"}), 503
        result = ai_integration_service.analyze_vulnerability(vulnerability_data)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        logger.error(f"Ошибка ИИ-анализа: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/classify/<int:vulnerability_id>', methods=['POST'])
@csrf.exempt
@login_required
def api_ai_classify(vulnerability_id):
    """Классификация уязвимости (ИИ или нет)"""
    try:
        if not AI_SERVICE_AVAILABLE:
            return jsonify({"success": False, "error": "AI Integration Service недоступен"}), 503
        result = ai_integration_service.classify_vulnerability(vulnerability_id)
        if 'error' in result:
            return jsonify({'success': False, 'error': result['error']}), 400
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        logger.error(f"Ошибка классификации: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/batch-analyze', methods=['POST'])
@csrf.exempt
@login_required
@admin_required
def api_ai_batch_analyze():
    """Пакетный анализ уязвимостей"""
    try:
        data = request.get_json() or {}
        vulnerability_ids = data.get('vulnerability_ids', [])
        
        # Проверка наличия и валидности списка ID
        if not vulnerability_ids:
            return jsonify({
                'success': False,
                'error': 'vulnerability_ids required',
                'message': 'Необходимо передать список ID уязвимостей для анализа'
            }), 400
        
        # Проверка что это список
        if not isinstance(vulnerability_ids, list):
            return jsonify({
                'success': False,
                'error': 'vulnerability_ids must be a list',
                'message': 'vulnerability_ids должен быть массивом'
            }), 400
        
        if not AI_SERVICE_AVAILABLE:
            return jsonify({"success": False, "error": "AI Integration Service недоступен"}), 503
        
        result = ai_integration_service.batch_analyze(vulnerability_ids)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        logger.error(f"Ошибка пакетного анализа: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/statistics', methods=['GET'])
@csrf.exempt
@login_required
def api_ai_statistics():
    """Статистика по ключевым словам"""
    if not AI_SERVICE_AVAILABLE:
        return jsonify({'success': False, 'error': 'AI Integration Service недоступен'}), 503
    try:
        stats = ai_integration_service.get_keywords_statistics()
        return jsonify({'success': True, 'statistics': stats})
    except Exception as e:
        logger.error(f"Ошибка получения статистики: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/keywords', methods=['GET'])
@csrf.exempt
@login_required
def api_ai_keywords():
    """Список ключевых слов"""
    if not AI_SERVICE_AVAILABLE:
        return jsonify({'success': False, 'error': 'AI Integration Service недоступен'}), 503
    try:
        stats = ai_integration_service.get_keywords_statistics()
        return jsonify({
            'success': True,
            'keywords': stats.get('keywords', []),
            'category_stats': stats.get('category_stats', {})
        })
    except Exception as e:
        logger.error(f"Ошибка получения ключевых слов: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/train', methods=['POST'])
@csrf.exempt
@login_required
@admin_required
def api_ai_train():
    """Обучение модели на новых данных"""
    try:
        data = request.get_json()
        training_data = data.get('training_data', [])
        
        if not training_data:
            return jsonify({'error': 'training_data required'}), 400
        
        if not AI_SERVICE_AVAILABLE:
            return jsonify({"success": False, "error": "AI Integration Service недоступен"}), 503
        result = ai_integration_service.train_model(training_data)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        logger.error(f"Ошибка обучения: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/generate-passport/<int:vulnerability_id>', methods=['POST'])
@csrf.exempt
@login_required
def api_ai_generate_passport(vulnerability_id):
    """Создание паспорта уязвимости при помощи ИИ"""
    if not AI_SERVICE_AVAILABLE:
        return jsonify({'success': False, 'error': 'AI Integration Service недоступен'}), 503
    try:
        passport = ai_integration_service.generate_passport(vulnerability_id)
        if 'error' in passport:
            return jsonify({'success': False, 'error': passport['error']}), 400
        return jsonify({'success': True, 'passport': passport})
    except Exception as e:
        logger.error(f"Ошибка генерации паспорта: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/passport/<int:vulnerability_id>', methods=['GET'])
@csrf.exempt
@login_required
def api_ai_get_passport(vulnerability_id):
    """Получение паспорта уязвимости"""
    try:
        cursor = db_manager.connection.cursor()
        cursor.execute("""
            SELECT passport_data, generated_at, updated_at
            FROM ai_vulnerability_passports
            WHERE vulnerability_id = %s
            ORDER BY generated_at DESC
            LIMIT 1
        """, (vulnerability_id,))
        
        row = cursor.fetchone()
        cursor.close()
        
        if row:
            import json
            return jsonify({
                'success': True,
                'passport': json.loads(row[0]) if isinstance(row[0], str) else row[0],
                'generated_at': str(row[1]),
                'updated_at': str(row[2])
            })
        else:
            return jsonify({'success': False, 'error': 'Паспорт не найден'}), 404
    except Exception as e:
        logger.error(f"Ошибка получения паспорта: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/monitor-start', methods=['POST'])
@csrf.exempt
@login_required
@admin_required
def api_ai_monitor_start():
    """Запуск мониторинга сайтов"""
    try:
        # TODO: Реализовать запуск мониторинга
        return jsonify({'success': True, 'message': 'Мониторинг запущен'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/monitor-stop', methods=['POST'])
@csrf.exempt
@login_required
@admin_required
def api_ai_monitor_stop():
    """Остановка мониторинга"""
    try:
        return jsonify({'success': True, 'message': 'Мониторинг остановлен'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/monitor-status', methods=['GET'])
@csrf.exempt
@login_required
def api_ai_monitor_status():
    """Статус мониторинга"""
    try:
        return jsonify({'success': True, 'status': 'stopped', 'sites': []})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# === API МАРШРУТЫ ДЛЯ МЕТОДОЛОГИЙ БЕЗОПАСНОСТИ ===

# Условный импорт сервисов методологий
try:
    from services.security_methodology_service import security_methodology_service
    from services.security_testing_service import security_testing_service
    SECURITY_METHODOLOGIES_AVAILABLE = True
except ImportError:
    SECURITY_METHODOLOGIES_AVAILABLE = False
    logger.warning("⚠️ Security Methodology Services не доступны (модули не найдены)")

if SECURITY_METHODOLOGIES_AVAILABLE:
    @app.route('/api/security/methodologies', methods=['GET'])
    @csrf.exempt
    @login_required
    def api_security_methodologies():
        """Получить список методологий"""
        try:
            methodologies = security_methodology_service.get_all_methodologies()
            return jsonify({'success': True, 'methodologies': methodologies})
        except Exception as e:
            logger.error(f"Ошибка получения методологий: {e}", exc_info=True)
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/security/methodologies/<int:methodology_id>', methods=['GET'])
    @csrf.exempt
    @login_required
    def api_security_methodology_detail(methodology_id):
        """Получить детали методологии"""
        try:
            methodology = security_methodology_service.get_methodology_by_id(methodology_id)
            if not methodology:
                return jsonify({'success': False, 'error': 'Методология не найдена'}), 404
            
            categories = security_methodology_service.get_categories(methodology_id)
            statistics = security_methodology_service.get_methodology_statistics(methodology_id)
            
            return jsonify({
                'success': True,
                'methodology': methodology,
                'categories': categories,
                'statistics': statistics
            })
        except Exception as e:
            logger.error(f"Ошибка получения методологии {methodology_id}: {e}", exc_info=True)
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/security/methodologies/<int:methodology_id>/tests', methods=['GET'])
    @csrf.exempt
    @login_required
    def api_security_methodology_tests(methodology_id):
        """Получить тесты методологии"""
        try:
            tests = security_methodology_service.get_tests(methodology_id=methodology_id)
            return jsonify({'success': True, 'tests': tests})
        except Exception as e:
            logger.error(f"Ошибка получения тестов методологии {methodology_id}: {e}", exc_info=True)
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/security/projects', methods=['GET', 'POST'])
    @csrf.exempt
    @login_required
    def api_security_projects():
        """Получить список проектов или создать новый"""
        if request.method == 'GET':
            try:
                status = request.args.get('status')
                projects = security_testing_service.get_all_projects(status=status)
                return jsonify({'success': True, 'projects': projects})
            except Exception as e:
                logger.error(f"Ошибка получения проектов: {e}", exc_info=True)
                return jsonify({'success': False, 'error': str(e)}), 500
        else:  # POST
            try:
                if 'user_id' not in session:
                    return jsonify({'success': False, 'error': 'Не авторизован'}), 401
                
                data = request.get_json()
                project_id = security_testing_service.create_project(data, session['user_id'])
                
                if project_id:
                    return jsonify({'success': True, 'project_id': project_id})
                else:
                    return jsonify({'success': False, 'error': 'Ошибка создания проекта'}), 500
            except Exception as e:
                logger.error(f"Ошибка создания проекта: {e}", exc_info=True)
                return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/security/projects/<int:project_id>', methods=['GET'])
    @csrf.exempt
    @login_required
    def api_security_project_detail(project_id):
        """Получить детали проекта"""
        try:
            project = security_testing_service.get_project(project_id)
            if not project:
                return jsonify({'success': False, 'error': 'Проект не найден'}), 404
            
            results = security_testing_service.get_project_results(project_id)
            metrics = security_testing_service.calculate_project_metrics(project_id)
            
            return jsonify({
                'success': True,
                'project': project,
                'results': results,
                'metrics': metrics
            })
        except Exception as e:
            logger.error(f"Ошибка получения проекта {project_id}: {e}", exc_info=True)
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/security/projects/<int:project_id>/results', methods=['GET', 'POST'])
    @csrf.exempt
    @login_required
    def api_security_project_results(project_id):
        """Получить или сохранить результаты проекта"""
        if request.method == 'GET':
            try:
                results = security_testing_service.get_project_results(project_id)
                return jsonify({'success': True, 'results': results})
            except Exception as e:
                logger.error(f"Ошибка получения результатов проекта {project_id}: {e}", exc_info=True)
                return jsonify({'success': False, 'error': str(e)}), 500
        else:  # POST
            try:
                if 'user_id' not in session:
                    return jsonify({'success': False, 'error': 'Не авторизован'}), 401
                
                data = request.get_json()
                data['project_id'] = project_id
                result_id = security_testing_service.save_test_result(data, session['user_id'])
                
                if result_id:
                    # Пересчитываем метрики
                    security_testing_service.calculate_project_metrics(project_id)
                    return jsonify({'success': True, 'result_id': result_id})
                else:
                    return jsonify({'success': False, 'error': 'Ошибка сохранения результата'}), 500
            except Exception as e:
                logger.error(f"Ошибка сохранения результата: {e}", exc_info=True)
                return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/security/projects/<int:project_id>/metrics', methods=['GET'])
    @csrf.exempt
    @login_required
    def api_security_project_metrics(project_id):
        """Получить метрики проекта"""
        try:
            metrics = security_testing_service.calculate_project_metrics(project_id)
            return jsonify({'success': True, 'metrics': metrics})
        except Exception as e:
            logger.error(f"Ошибка получения метрик проекта {project_id}: {e}", exc_info=True)
            return jsonify({'success': False, 'error': str(e)}), 500


# === API МАРШРУТЫ ДЛЯ СТАТУСА СИНХРОНИЗАЦИИ CVE ===

try:
    from services.backend.cve_sync_status import get_sync_status, reset_sync_status
    SYNC_STATUS_AVAILABLE = True
except ImportError:
    SYNC_STATUS_AVAILABLE = False
    logger.warning("cve_sync_status модуль не доступен, статус синхронизации не будет работать")


@app.route('/api/cve-sync/status', methods=['GET'])
@login_required
def get_cve_sync_status():
    """Получить статус синхронизации CVE"""
    try:
        if SYNC_STATUS_AVAILABLE:
            status = get_sync_status()
            return jsonify({
                'success': True,
                'status': status.to_dict()
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Статус синхронизации не доступен'
            })
    except Exception as e:
        logger.error(f"Ошибка получения статуса синхронизации: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/cve-sync/reset', methods=['POST'])
@login_required
def reset_cve_sync_status():
    """Сбросить статус синхронизации CVE"""
    try:
        if SYNC_STATUS_AVAILABLE:
            reset_sync_status()
            return jsonify({'success': True, 'message': 'Статус синхронизации сброшен'})
        else:
            return jsonify({'success': False, 'message': 'Статус синхронизации не доступен'})
    except Exception as e:
        logger.error(f"Ошибка сброса статуса синхронизации: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host=Config.BACKEND_HOST, port=Config.BACKEND_PORT, debug=False)

