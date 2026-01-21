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
from typing import Optional, List, Dict, Any

# Импорты сервисов (без парсеров)
from services.vulnerability_service import VulnerabilityService
from services.operator_service import OperatorService
from services.export_service import ExportService
from services.assignment_manager import AssignmentManager
from services.data_manager import DataManager
from services.analytics_service import analytics_service
from services.auth_service import AuthService
from services.ml_platform_client import ml_platform_client
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
from services.risk_calculator import RiskItem, compute_risk, fetch_epss_scores
import time
import requests
import os

try:
    import pandas as pd
except ImportError:
    pd = None

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
                                       search: Optional[str] = None,
                                       ai_only: Optional[bool] = None,
                                       tags: Optional[List[str]] = None):
    """Получить уязвимости с операторами с пагинацией"""
    try:
        vulnerabilities, total_count = vuln_service.get_paginated_vulnerabilities(
            page=page, per_page=per_page,
            status=status, severity=severity, search=search, ai_only=ai_only, tags=tags
        )
        operators = operator_service.get_all_operators()
        logger.info(f"📊 Получено уязвимостей: {len(vulnerabilities)} из {total_count} (страница {page})")
        return vulnerabilities, operators, total_count
    except Exception as e:
        logger.error(f"❌ Ошибка получения уязвимостей: {e}", exc_info=True)
        return [], [], 0


def get_global_vulnerability_stats(per_page: int = 50) -> Dict[str, Any]:
    """
    Быстрые агрегаты по всей БД (НЕ по текущей странице).
    Для legacy схемы считаем напрямую из turn/actids.
    """
    try:
        from models.database import DatabaseManager
        dbm = DatabaseManager()
        # total (only real CVEs)
        total = dbm.execute_query("SELECT COUNT(*) FROM turn WHERE cve IS NOT NULL AND cve != ''")
        total_count = int(total[0][0]) if total else 0

        high = dbm.execute_query(
            "SELECT COUNT(*) FROM turn WHERE cve IS NOT NULL AND cve != '' AND cvss >= 7.0"
        )
        high_risk = int(high[0][0]) if high else 0

        newq = dbm.execute_query(
            "SELECT COUNT(*) FROM turn WHERE cve IS NOT NULL AND cve != '' AND status = TRUE"
        )
        new_count = int(newq[0][0]) if newq else 0

        doneq = dbm.execute_query(
            "SELECT COUNT(*) FROM turn WHERE cve IS NOT NULL AND cve != '' AND status = FALSE"
        )
        completed_count = int(doneq[0][0]) if doneq else 0

        inworkq = dbm.execute_query(
            "SELECT COUNT(DISTINCT cve) FROM actids WHERE active = TRUE"
        )
        in_work = int(inworkq[0][0]) if inworkq else 0

        total_pages = (total_count + per_page - 1) // per_page if total_count else 0
        return {
            "total_count": total_count,
            "high_risk": high_risk,
            "new": new_count,
            "in_work": in_work,
            "completed": completed_count,
            "total_pages": total_pages,
        }
    except Exception as e:
        logger.error(f"❌ Ошибка глобальной статистики уязвимостей: {e}", exc_info=True)
        return {
            "total_count": 0,
            "high_risk": 0,
            "new": 0,
            "in_work": 0,
            "completed": 0,
            "total_pages": 0,
        }


def _detect_severity_from_bdu(text: str) -> str:
    """Грубое определение severity из русской формулировки BDU."""
    if not text:
        return "medium"
    t = text.lower()
    if "критическ" in t:
        return "critical"
    if "высокий" in t or "высокая" in t:
        return "high"
    if "низк" in t:
        return "low"
    return "medium"


def _parse_cvss_from_text(text: str) -> float:
    """Попробовать вытащить числовое значение CVSS из текстового описания."""
    if not text:
        return 0.0
    import re
    nums = re.findall(r"(\\d+(?:[\\.,]\\d+)?)", text)
    if not nums:
        return 0.0
    try:
        # Берем последнее число (часто после 'CVSS 3.1 составляет X,X')
        val = nums[-1].replace(",", ".")
        return float(val)
    except Exception:
        return 0.0


def save_parsing_history(sources, total_parsed, total_saved, total_errors, by_source, settings, status='completed', error_message=None, duration_seconds=0, parsing_id=None):
    """Сохранить или обновить историю парсинга в БД"""
    try:
        import json
        # Убеждаемся, что db_manager доступен
        if 'db_manager' not in globals():
            from models.database import DatabaseManager
            global db_manager
            db_manager = DatabaseManager()
        
        if parsing_id:
            # Обновляем существующую запись
            query = """
                UPDATE parsing_history SET
                    total_parsed = %s,
                    total_saved = %s,
                    total_errors = %s,
                    by_source = %s,
                    status = %s,
                    error_message = %s,
                    duration_seconds = %s
                WHERE id = %s
            """
            db_manager.execute_query(
                query,
                (
                    total_parsed,
                    total_saved,
                    total_errors,
                    json.dumps(by_source) if by_source else '{}',
                    status,
                    error_message,
                    duration_seconds,
                    parsing_id
                )
            )
            logger.info(f"✅ История парсинга обновлена (ID: {parsing_id}): parsed={total_parsed}, saved={total_saved}")
            return parsing_id
        else:
            # Создаем новую запись
            query = """
                INSERT INTO parsing_history (
                    sources, total_parsed, total_saved, total_errors, 
                    by_source, settings, status, error_message, duration_seconds, scan_date
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                RETURNING id
            """
            # PostgreSQL ожидает массив для sources, а не JSON строку
            sources_array = sources if isinstance(sources, list) else (sources if sources else [])
            
            result = db_manager.execute_query(
                query,
                (
                    sources_array,  # PostgreSQL массив напрямую
                    total_parsed,
                    total_saved,
                    total_errors,
                    json.dumps(by_source) if by_source else '{}',
                    json.dumps(settings) if settings else '{}',
                    status,
                    error_message,
                    duration_seconds
                )
            )
            # Обработка результата: может быть список кортежей или просто значение
            if result:
                if isinstance(result, list) and len(result) > 0:
                    if isinstance(result[0], (list, tuple)) and len(result[0]) > 0:
                        parsing_id = result[0][0]
                    elif isinstance(result[0], (int, str)):
                        parsing_id = result[0]
                    else:
                        parsing_id = None
                elif isinstance(result, (int, str)):
                    parsing_id = result
                else:
                    parsing_id = None
            else:
                parsing_id = None
            if parsing_id:
                logger.info(f"✅ История парсинга сохранена (ID: {parsing_id}): parsed={total_parsed}, saved={total_saved}")
            else:
                logger.error(f"❌ Не удалось получить ID после INSERT. Result: {result}")
            return parsing_id
    except Exception as e:
        logger.error(f"❌ Ошибка сохранения истории парсинга: {e}", exc_info=True)
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return None

def get_active_parsing_status():
    """Получить текущий активный статус парсинга из БД"""
    try:
        query = """
            SELECT id, sources, total_parsed, total_saved, total_errors, 
                   by_source, settings, status, error_message, duration_seconds, scan_date
            FROM parsing_history
            WHERE status IN ('running', 'pending')
            ORDER BY scan_date DESC
            LIMIT 1
        """
        result = db_manager.execute_query(query)
        if result and len(result) > 0:
            row = result[0]
            import json
            return {
                'id': row[0],
                'sources': row[1],
                'total_parsed': row[2],
                'total_saved': row[3],
                'total_errors': row[4],
                'by_source': json.loads(row[5]) if row[5] else {},
                'settings': json.loads(row[6]) if row[6] else {},
                'status': row[7],
                'error_message': row[8],
                'duration_seconds': row[9],
                'scan_date': row[10].isoformat() if row[10] else None
            }
        return None
    except Exception as e:
        logger.error(f"❌ Ошибка получения статуса парсинга: {e}", exc_info=True)
        return None


def get_vulnerabilities_with_operators_old():
    """Получить уязвимости с операторами (старый API)"""
    vulnerabilities = vuln_service.get_all_vulnerabilities()
    operators = operator_service.get_all_operators()
    return vulnerabilities, operators

def get_dashboard_stats():
    """Получить статистику для дашборда"""
    # В legacy БД (100k+ записей) нельзя тянуть все уязвимости в память ради статистики.
    per_page = 50
    try:
        if Config.USE_LEGACY_SCHEMA:
            from models.database import DatabaseManager
            dbm = DatabaseManager()

            total = dbm.execute_query("SELECT COUNT(*) FROM turn WHERE cve IS NOT NULL AND cve != ''")
            total_vulnerabilities = int(total[0][0]) if total else 0

            high = dbm.execute_query(
                "SELECT COUNT(*) FROM turn WHERE cve IS NOT NULL AND cve != '' AND cvss >= 7.0"
            )
            high_risk = int(high[0][0]) if high else 0

            newq = dbm.execute_query(
                "SELECT COUNT(*) FROM turn WHERE cve IS NOT NULL AND cve != '' AND status = TRUE"
            )
            new_vulnerabilities = int(newq[0][0]) if newq else 0

            doneq = dbm.execute_query(
                "SELECT COUNT(*) FROM turn WHERE cve IS NOT NULL AND cve != '' AND status = FALSE"
            )
            completed_vulnerabilities = int(doneq[0][0]) if doneq else 0

            completion_rate = (completed_vulnerabilities / total_vulnerabilities * 100.0) if total_vulnerabilities else 0.0

            operators = operator_service.get_all_operators()
            total_pages = (total_vulnerabilities + per_page - 1) // per_page if total_vulnerabilities else 0

            return {
                'total_vulnerabilities': total_vulnerabilities,
                'high_risk': high_risk,
                'new_vulnerabilities': new_vulnerabilities,
                'completion_rate': completion_rate,
                'active_operators': len(operators),
                'total_operators': len(operators),
                'per_page': per_page,
                'total_pages': total_pages
            }
        else:
            vulnerabilities, operators = get_vulnerabilities_with_operators_old()
            total_vulnerabilities = len(vulnerabilities)
            total_pages = (total_vulnerabilities + per_page - 1) // per_page if total_vulnerabilities else 0
            return {
                'total_vulnerabilities': total_vulnerabilities,
                'high_risk': len([v for v in vulnerabilities if v.severity == 'high']),
                'new_vulnerabilities': len([v for v in vulnerabilities if v.status == 'new']),
                'completion_rate': (len([v for v in vulnerabilities if v.status in ['completed', 'approved']]) / len(vulnerabilities) * 100) if vulnerabilities else 0,
                'active_operators': len(operators),
                'total_operators': len(operators),
                'per_page': per_page,
                'total_pages': total_pages
            }
    except Exception as e:
        logger.error(f"❌ Ошибка get_dashboard_stats: {e}", exc_info=True)
        return {
            'total_vulnerabilities': 0,
            'high_risk': 0,
            'new_vulnerabilities': 0,
            'completion_rate': 0,
            'active_operators': 0,
            'total_operators': 0,
            'per_page': per_page,
            'total_pages': 0
        }

def get_analytics_data():
    """Получить данные для аналитики"""
    from services.analytics_service import analytics_service
    analytics_data = analytics_service.get_analytics_data()
    # В legacy схеме не тянем все уязвимости в память — только агрегаты + список операторов.
    operators = operator_service.get_all_operators()
    result = {
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
        'assigned_operator': operator_name,
        'cve_id': getattr(vuln, 'cve_id', None),
        'tags': getattr(vuln, 'tags', []) or []
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
    ai_only = request.args.get('ai_only', None)
    ai_only = True if str(ai_only).lower() in ('1', 'true', 'yes', 'on') else None
    tags_q = request.args.get('tags', None)
    tags = None
    if tags_q:
        tags = [t.strip() for t in str(tags_q).split(',') if t.strip()]
    
    # Поддержка параметра filter для обратной совместимости
    filter_param = request.args.get('filter', None)
    if filter_param == 'high':
        severity = 'high'
    elif filter_param == 'new':
        status = 'new'
    
    vulnerabilities, operators, total_count = get_vulnerabilities_with_operators(
        page=page, per_page=per_page,
        status=status, severity=severity, search=search, ai_only=ai_only, tags=tags
    )
    total_pages = (total_count + per_page - 1) // per_page

    global_stats = get_global_vulnerability_stats(per_page=per_page)
    
    return render_template('vulnerabilities_list.html',
                           vulnerabilities=vulnerabilities,
                           operators=operators,
                           global_stats=global_stats,
                           current_page=page,
                           total_pages=total_pages,
                           total_count=total_count,
                           per_page=per_page,
                           status=status,
                           severity=severity,
                           search=search,
                           ai_only=ai_only,
                           tags=tags_q)

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


@app.route('/analytics')
@login_required
def analytics_alias():
    """Alias for analytics page (compatibility with older/expected URL)."""
    return redirect(url_for('performance_analytics'))

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


@app.route('/ai/graph3d')
@login_required
def ai_graph3d():
    """3D визуализация обучения (epochs graph)"""
    return render_template('ai/graph3d.html')


_graph3d_cache = {"ts": 0.0, "data": None}


@app.route('/api/ai/graph3d/data', methods=['GET'])
@login_required
def api_ai_graph3d_data():
    """Server-side prepared graph data (cached) to speed up UI."""
    try:
        now = time.time()
        if _graph3d_cache["data"] is not None and (now - _graph3d_cache["ts"]) < 10:
            return jsonify({"success": True, "graph": _graph3d_cache["data"], "cached": True})

        hist_res = ml_platform_client.get_training_history()
        if not hist_res.get("success"):
            return jsonify({"success": False, "error": hist_res.get("error", "training history failed")}), 502

        history = hist_res.get("data") or []
        if not isinstance(history, list) or not history:
            graph = {"nodes": [], "links": []}
            _graph3d_cache.update({"ts": now, "data": graph})
            return jsonify({"success": True, "graph": graph, "cached": False})

        last = history[0] or {}
        task_id = last.get("task_id") or "unknown_task"
        run_node = f"run:{task_id}"
        model_node = "model:classifier"

        nodes = [
            {"id": model_node, "group": "model", "label": "Vulnerability Classifier"},
            {"id": run_node, "group": "run", "label": f"Training {task_id}", "status": last.get("status"), "best_accuracy": last.get("best_accuracy")},
        ]
        links = [{"source": model_node, "target": run_node, "type": "trained_by"}]

        epochs = last.get("history") if isinstance(last.get("history"), list) else []
        tail = epochs[-60:]  # keep readable
        prev = None
        for e in tail:
            epoch = e.get("epoch", e.get("current_epoch"))
            nid = f"epoch:{task_id}:{epoch if epoch is not None else len(nodes)}"
            nodes.append(
                {
                    "id": nid,
                    "group": "epoch",
                    "epoch": epoch,
                    "train_loss": e.get("train_loss"),
                    "val_loss": e.get("val_loss"),
                    "train_accuracy": e.get("train_accuracy"),
                    "val_accuracy": e.get("val_accuracy"),
                    "lr": e.get("learning_rate"),
                    "batch_size": e.get("batch_size"),
                    "label": f"Epoch {epoch}" if epoch is not None else "Epoch",
                }
            )
            links.append({"source": run_node, "target": nid, "type": "has_epoch"})
            if prev:
                links.append({"source": prev, "target": nid, "type": "next"})
            prev = nid

        graph = {"nodes": nodes, "links": links}
        _graph3d_cache.update({"ts": now, "data": graph})
        return jsonify({"success": True, "graph": graph, "cached": False})
    except Exception as e:
        logger.error(f"Graph3D data error: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500

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
                # NVD / технические метрики (используются совместно с данными из Excel/BDU)
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
                'has_cert_alerts': getattr(vulnerability, 'has_cert_alerts', False),
                'tags': getattr(vulnerability, 'tags', []) or []
            }

            # AI analysis is stored in turn.etc (TEXT JSON) — pull it for transparency UI
            try:
                from models.database import DatabaseManager
                dbm = DatabaseManager()
                rows = dbm.execute_query("SELECT etc FROM turn WHERE id = %s", (vuln_id,))
                etc_text = rows[0][0] if rows else None
                etc_data = json.loads(etc_text) if etc_text else {}
                if not isinstance(etc_data, dict):
                    etc_data = {}
                vuln_data['ai_analysis'] = etc_data.get('ai_analysis')
            except Exception:
                vuln_data['ai_analysis'] = None
            
            return jsonify({
                'success': True,
                'vulnerability': vuln_data
            })
        return jsonify({'success': False, 'message': 'Уязвимость не найдена'}), 404
    except Exception as e:
        logger.error(f"Ошибка получения уязвимости {vuln_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/bdu/import', methods=['POST'])
@login_required
@admin_required
def api_bdu_import():
    """
    Импорт уязвимостей из Excel BDU/FSTEC (`docs/парсеры ии бду.xlsx`).

    Логика:
    - читаем Excel (строка с настоящими заголовками – вторая, header=1);
    - по каждой строке собираем расширенное русскоязычное описание;
    - пытаемся найти существующую уязвимость по CVE ID и ДОБАВИТЬ к ней BDU‑описание;
    - если не нашли – создаем новую уязвимость с основным описанием из BDU.

    Важно: никакого отдельного "раскрытия NVD" – только общие метрики и описание.
    """
    if pd is None:
        return jsonify({'success': False, 'error': 'pandas не установлен на сервере'}), 500

    try:
        project_root = os.path.dirname(os.path.abspath(__file__))
        excel_path = os.path.join(project_root, 'docs', 'парсеры ии бду.xlsx')

        if not os.path.exists(excel_path):
            return jsonify({'success': False, 'error': f'Файл не найден: {excel_path}'}), 404

        # Читаем файл: вторая строка содержит реальные заголовки
        df = pd.read_excel(excel_path, header=1)

        # Нормализуем имена колонок
        cols = {c: str(c).strip() for c in df.columns}
        df.rename(columns=cols, inplace=True)

        # Карта колонок (по русским названиям)
        col_status = 'Статус'
        col_bdu_id = 'Идентификатор'
        col_name = 'Наименование уязвимости'
        col_ids_other = 'Идентификаторы других систем описаний уязвимости'
        col_desc = 'Описание уязвимости'
        col_vendor = 'Вендор ПО'
        col_product = 'Название ПО'
        col_version = 'Версия ПО'
        col_os = 'Наименование ОС и тип аппаратной платформы'
        col_date_found = 'Дата выявления'
        col_severity_text = 'Уровень опасности уязвимости'
        col_cvss2 = 'CVSS 2.0'
        col_cvss3 = 'CVSS 3.1'
        col_cvss4 = 'CVSS 4.0'
        col_mitigation = 'Возможные меры по устранению'
        col_fix_status = 'Статус уязвимости'
        col_fix_info = 'Информация об устранении'
        col_fix_date = 'Дата устранения'
        col_exploit = 'Наличие эксплойта'
        col_fix_method = 'Способ устранения'
        col_exploit_method = 'Способ эксплуатации'
        col_refs = 'Ссылки на источники'
        col_cwe_desc = 'Описание ошибки CWE'
        col_cwe_type = 'Тип ошибки CWE'

        # Индексация существующих уязвимостей по CVE
        existing = {}
        try:
            all_vulns = vuln_service.get_all_vulnerabilities_unlimited()
            for v in all_vulns:
                cve = getattr(v, 'cve_id', None)
                if cve:
                    existing.setdefault(cve.upper(), []).append(v)
        except Exception as e:
            logger.error(f"Не удалось получить список существующих уязвимостей: {e}", exc_info=True)

        created = 0
        updated = 0
        errors = []

        for idx, row in df.iterrows():
            try:
                bdu_id = str(row.get(col_bdu_id, '')).strip()
                name = str(row.get(col_name, '')).strip()
                base_desc = str(row.get(col_desc, '')).strip()

                if not bdu_id and not name and not base_desc:
                    continue

                # CVE из поля идентификаторов других систем
                cve_raw = str(row.get(col_ids_other, '') or '')
                cve_id = None
                if 'CVE-' in cve_raw:
                    import re
                    m = re.search(r'(CVE-\\d{4}-\\d+)', cve_raw)
                    if m:
                        cve_id = m.group(1).upper()

                severity_text = str(row.get(col_severity_text, '') or '')
                severity = _detect_severity_from_bdu(severity_text)

                # Базовый CVSS – пробуем взять из CVSS 3.1, дальше из 2.0
                cvss3_text = str(row.get(col_cvss3, '') or '')
                cvss2_text = str(row.get(col_cvss2, '') or '')
                cvss_score = _parse_cvss_from_text(cvss3_text) or _parse_cvss_from_text(cvss2_text)

                vendor = str(row.get(col_vendor, '') or '').strip()
                product = str(row.get(col_product, '') or '').strip()
                version = str(row.get(col_version, '') or '').strip()
                os_platform = str(row.get(col_os, '') or '').strip()
                date_found = row.get(col_date_found, None)
                mitigation = str(row.get(col_mitigation, '') or '').strip()
                fix_status = str(row.get(col_fix_status, '') or '').strip()
                fix_info = str(row.get(col_fix_info, '') or '').strip()
                date_fix = row.get(col_fix_date, None)
                exploit = str(row.get(col_exploit, '') or '').strip()
                fix_method = str(row.get(col_fix_method, '') or '').strip()
                exploit_method = str(row.get(col_exploit_method, '') or '').strip()
                refs = str(row.get(col_refs, '') or '').strip()
                cwe_desc = str(row.get(col_cwe_desc, '') or '').strip()
                cwe_type = str(row.get(col_cwe_type, '') or '').strip()

                # Собираем расширенное описание (BDU + метрики)
                parts = []
                if base_desc:
                    parts.append(base_desc)
                if vendor or product or version:
                    parts.append(f"[ПО] Вендор: {vendor or '-'}, продукт: {product or '-'}, версия: {version or '-'}")
                if os_platform:
                    parts.append(f"[Платформа] {os_platform}")
                if date_found:
                    parts.append(f"[Дата выявления] {date_found}")
                if severity_text:
                    parts.append(f"[Уровень опасности] {severity_text}")
                if cvss2_text or cvss3_text:
                    parts.append(f"[CVSS] 2.0: {cvss2_text or '-'}; 3.1: {cvss3_text or '-'}")
                if mitigation:
                    parts.append(f"[Меры по устранению] {mitigation}")
                if fix_status:
                    parts.append(f"[Статус BDU] {fix_status}")
                if fix_info:
                    parts.append(f"[Информация об устранении] {fix_info}")
                if date_fix:
                    parts.append(f"[Дата устранения] {date_fix}")
                if exploit:
                    parts.append(f"[Наличие эксплойта] {exploit}")
                if fix_method or exploit_method:
                    parts.append(f"[Методы] Устранение: {fix_method or '-'}; Эксплуатация: {exploit_method or '-'}")
                if refs:
                    parts.append(f"[Источники] {refs}")
                if cwe_type or cwe_desc:
                    parts.append(f"[CWE] {cwe_type or ''} {cwe_desc or ''}".strip())

                full_description = "\\n\\n".join([p for p in parts if p])

                # Пытаемся найти существующую уязвимость по CVE
                target_vuln = None
                if cve_id and cve_id in existing:
                    target_vuln = existing[cve_id][0]

                if target_vuln:
                    # Обновляем существующую уязвимость: дописываем BDU‑описание
                    new_desc = target_vuln.description or ""
                    if full_description and full_description not in new_desc:
                        if new_desc:
                            new_desc = new_desc + "\\n\\n[BDU/FSTEC]\\n" + full_description
                        else:
                            new_desc = full_description

                    new_cvss = max(float(target_vuln.cvss_score or 0.0), float(cvss_score or 0.0))
                    new_severity = target_vuln.severity or severity
                    # Если BDU говорит, что риск выше – повышаем
                    order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
                    if order.get(severity, 1) > order.get(new_severity, 1):
                        new_severity = severity

                    vuln_service.update_vulnerability(
                        target_vuln.id,
                        description=new_desc,
                        cvss_score=new_cvss,
                        severity=new_severity
                    )
                    updated += 1
                else:
                    # Создаем новую уязвимость
                    from models.entities import Vulnerability as BaseVuln

                    title_parts = []
                    if cve_id:
                        title_parts.append(cve_id)
                    if bdu_id:
                        title_parts.append(bdu_id)
                    if name:
                        title_parts.append(name)
                    title = " - ".join(title_parts)[:255] or (name or bdu_id or "BDU Vulnerability")

                    vuln = BaseVuln(
                        id=0,
                        title=title,
                        description=full_description or base_desc or name,
                        severity=severity,
                        status='new',
                        cvss_score=float(cvss_score or 0.0),
                        risk_level=severity,
                        category='bdu',
                        cve_id=cve_id
                    )

                    if vuln_service.add_vulnerability(vuln):
                        created += 1
                    else:
                        errors.append(f"Строка {idx + 2}: не удалось добавить уязвимость")

            except Exception as e:
                logger.error(f"Ошибка импорта BDU на строке {idx + 2}: {e}", exc_info=True)
                errors.append(f"Строка {idx + 2}: {e}")

        return jsonify({
            'success': True,
            'created': created,
            'updated': updated,
            'errors': errors,
            'total_rows': int(df.shape[0])
        })
    except Exception as e:
        logger.error(f"Ошибка импорта BDU Excel: {e}", exc_info=True)
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


# === TAGS API ===

@app.route('/api/vulnerabilities/<int:vuln_id>/tags', methods=['GET'])
@csrf.exempt
@login_required
def api_get_vulnerability_tags(vuln_id: int):
    """Получить теги уязвимости."""
    try:
        tags = vulnerability_repo.get_tags(vuln_id) if hasattr(vulnerability_repo, 'get_tags') else []
        return jsonify({'success': True, 'tags': tags})
    except Exception as e:
        logger.error(f"❌ Ошибка получения тегов vuln_id={vuln_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vulnerabilities/<int:vuln_id>/tags', methods=['PUT'])
@csrf.exempt
@login_required
@admin_required
def api_set_vulnerability_tags(vuln_id: int):
    """Полностью заменить теги уязвимости."""
    try:
        data = request.get_json() or {}
        tags = data.get('tags', [])
        ok = vulnerability_repo.set_tags(vuln_id, tags)
        return jsonify({'success': True, 'tags': vulnerability_repo.get_tags(vuln_id), 'updated': ok})
    except Exception as e:
        logger.error(f"❌ Ошибка обновления тегов vuln_id={vuln_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vulnerabilities/<int:vuln_id>/tags', methods=['POST'])
@csrf.exempt
@login_required
@admin_required
def api_add_vulnerability_tag(vuln_id: int):
    """Добавить один тег."""
    try:
        data = request.get_json() or {}
        tag = (data.get('tag') or '').strip()
        if not tag:
            return jsonify({'success': False, 'error': 'tag required'}), 400
        tags = vulnerability_repo.add_tag(vuln_id, tag)
        return jsonify({'success': True, 'tags': tags})
    except Exception as e:
        logger.error(f"❌ Ошибка добавления тега vuln_id={vuln_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vulnerabilities/<int:vuln_id>/tags', methods=['DELETE'])
@csrf.exempt
@login_required
@admin_required
def api_remove_vulnerability_tag(vuln_id: int):
    """Удалить один тег."""
    try:
        data = request.get_json() or {}
        tag = (data.get('tag') or '').strip()
        if not tag:
            return jsonify({'success': False, 'error': 'tag required'}), 400
        tags = vulnerability_repo.remove_tag(vuln_id, tag)
        return jsonify({'success': True, 'tags': tags})
    except Exception as e:
        logger.error(f"❌ Ошибка удаления тега vuln_id={vuln_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/vulnerabilities/<int:vuln_id>/ai-passport', methods=['GET'])
@login_required
def api_get_ai_passport(vuln_id: int):
    """Get stored AI passport from turn.etc (if exists)."""
    try:
        from models.database import DatabaseManager
        import json as _json
        dbm = DatabaseManager()
        rows = dbm.execute_query("SELECT etc FROM turn WHERE id = %s", (vuln_id,))
        etc = rows[0][0] if rows else None
        etc_data = {}
        try:
            etc_data = _json.loads(etc) if etc else {}
        except Exception:
            etc_data = {}
        passport = etc_data.get("ai_passport")
        if not passport:
            return jsonify({"success": False, "error": "AI passport not found"}), 404
        return jsonify({"success": True, "passport": passport})
    except Exception as e:
        logger.error(f"AI passport get error: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/api/vulnerabilities/<int:vuln_id>/ai-passport', methods=['POST'])
@login_required
@admin_required
def api_generate_ai_passport(vuln_id: int):
    """
    Generate AI passport via k8s-worker and save into turn.etc.ai_passport.
    Uses REAL vulnerability data from DB.
    """
    try:
        from models.database import DatabaseManager
        from models.legacy_repositories import LegacyVulnerabilityRepository
        import json as _json

        dbm = DatabaseManager()
        repo = LegacyVulnerabilityRepository(dbm.connection)
        v = repo.get_by_id(vuln_id)
        if not v:
            return jsonify({"success": False, "error": "Vulnerability not found"}), 404

        payload = {
            "cve_id": getattr(v, "cve_id", None),
            "title": getattr(v, "title", ""),
            "description": getattr(v, "description", ""),
            "cvss_score": getattr(v, "cvss_score", 0.0),
            "epss_score": getattr(v, "epss_score", None),
            "source": getattr(v, "source_identifier", None),
        }

        # Call k8s-worker passport endpoint
        base = f"http://{getattr(Config, 'ML_VM_IP', '10.0.88.25')}:{getattr(Config, 'ML_API_PORT', 8000)}"
        resp = requests.post(f"{base}/api/passport", json=payload, timeout=30)
        resp.raise_for_status()
        passport = resp.json() or {}
        if not passport.get("success"):
            return jsonify({"success": False, "error": passport.get("error", "passport failed")}), 502

        # Merge into etc (TEXT)
        rows = dbm.execute_query("SELECT etc FROM turn WHERE id = %s", (vuln_id,))
        etc_text = rows[0][0] if rows else None
        try:
            etc_data = _json.loads(etc_text) if etc_text else {}
        except Exception:
            etc_data = {}
        if not isinstance(etc_data, dict):
            etc_data = {}

        etc_data["ai_passport"] = passport
        etc_data["ai_passport_generated_at"] = passport.get("generated_at")

        dbm.execute_query("UPDATE turn SET etc = %s WHERE id = %s", (_json.dumps(etc_data, ensure_ascii=False), vuln_id))
        return jsonify({"success": True, "passport": passport})
    except Exception as e:
        logger.error(f"AI passport generate error: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


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
        # Если sources не указаны, используем дефолтные источники
        sources = data.get('sources', None)
        if not sources or len(sources) == 0:
            sources = ['ubuntu', 'debian']  # Дефолтные источники для HTML парсера
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
        
        # Создаем запись о начале парсинга в БД
        parsing_id = None
        try:
            parsing_id = save_parsing_history(
                sources=sources,
                total_parsed=0,
                total_saved=0,
                total_errors=0,
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
                status='running',
                duration_seconds=0
            )
            logger.info(f"✅ [API] Создана запись парсинга в БД (ID: {parsing_id})")
        except Exception as history_error:
            logger.error(f"Ошибка создания записи парсинга: {history_error}", exc_info=True)
        
        # Запуск парсинга в отдельном потоке для неблокирующего выполнения
        import threading
        def run_parsing():
            start_time = time.time()
            try:
                logger.info(f"   [API] Вызываем unified_parser_service.parse_all()...")
                # parse_all не принимает parsing_id, он обновляется внутри через update_parsing_status
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
                # Устанавливаем parsing_id в результаты для обновления статуса
                results['parsing_id'] = parsing_id
                duration = int(time.time() - start_time)
                logger.info(f"   [API] Парсинг завершен: results={results}")
                logger.info(f"   [API] total_parsed={results.get('total_parsed', 0)}, total_saved={results.get('total_saved', 0)}")
                
                # Обновление истории парсинга
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
                        duration_seconds=duration,
                        parsing_id=parsing_id
                    )
                except Exception as history_error:
                    logger.error(f"Ошибка обновления истории парсинга: {history_error}", exc_info=True)
            except Exception as parse_error:
                duration = int(time.time() - start_time)
                logger.error(f"   [API] Ошибка при вызове parse_all(): {parse_error}", exc_info=True)
                
                # Обновление истории парсинга с ошибкой
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
                        duration_seconds=duration,
                        parsing_id=parsing_id
                    )
                except Exception as history_error:
                    logger.error(f"Ошибка обновления истории парсинга: {history_error}", exc_info=True)
        
        # Запускаем парсинг в отдельном потоке
        parsing_thread = threading.Thread(target=run_parsing, daemon=True)
        parsing_thread.start()
        
        # Возвращаем немедленный ответ с ID парсинга
        return jsonify({
            'success': True,
            'message': 'Парсинг запущен',
            'parsing_id': parsing_id,
            'status': 'running'
        })
        
    except Exception as e:
        logger.error(f"Ошибка запуска парсеров: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/parsing-status', methods=['GET'])
@csrf.exempt
def api_parsing_status():
    """Получить текущий активный статус парсинга из БД"""
    try:
        status = get_active_parsing_status()
        if status:
            return jsonify({
                'success': True,
                'status': status
            })
        else:
            return jsonify({
                'success': True,
                'status': {
                    'status': 'idle',
                    'message': 'Парсинг не активен'
                }
            })
    except Exception as e:
        logger.error(f"Ошибка получения статуса парсинга: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/parsers/stats', methods=['GET'])
@csrf.exempt
def api_parsers_stats():
    """Получить статистику парсеров и БД"""
    try:
        # Получение статистики из БД напрямую (без ограничений)
        from models.database import DatabaseManager
        import json
        db_manager = DatabaseManager()
        
        # Считаем общее количество записей напрямую из БД
        if Config.USE_LEGACY_SCHEMA:
            # Считаем все записи, не только с CVE
            # Используем свежий запрос без кеша
            result = db_manager.execute_query("SELECT COUNT(*) FROM turn")
            total_in_db = result[0][0] if result and len(result) > 0 else 0
            
            # Дополнительная проверка: считаем только записи с CVE для точности
            result_with_cve = db_manager.execute_query(
                "SELECT COUNT(*) FROM turn WHERE cve IS NOT NULL AND cve != ''"
            )
            total_with_cve = result_with_cve[0][0] if result_with_cve and len(result_with_cve) > 0 else 0
            
            # Используем более точное значение (с CVE)
            if total_with_cve > 0:
                total_in_db = total_with_cve
            
            # Подсчет по источникам из БД
            source_result = db_manager.execute_query(
                "SELECT source, COUNT(*) as cnt FROM turn WHERE cve IS NOT NULL AND cve != '' AND source IS NOT NULL GROUP BY source ORDER BY cnt DESC"
            )
            by_source = {}
            for row in source_result:
                source = row[0] or 'unknown'
                by_source[source] = {'in_db': row[1], 'parsed': 0, 'saved': 0}
            
            # Логирование для отладки
            logger.debug(f"📊 [STATS] Всего в БД: {total_in_db}, с CVE: {total_with_cve}")
            logger.debug(f"📊 [STATS] Источники: {list(by_source.keys())}")
            
            # Получаем статистику из активного парсинга (если есть) или последнего успешного
            # Сначала проверяем активный парсинг
            active_result = db_manager.execute_query("""
                SELECT by_source, total_parsed, total_saved 
                FROM parsing_history 
                WHERE status = 'running' 
                ORDER BY scan_date DESC 
                LIMIT 1
            """)
            
            # Если активного нет, берем последний completed с реальными данными
            if not active_result or len(active_result) == 0 or (active_result[0][1] == 0 and active_result[0][2] == 0):
                history_result = db_manager.execute_query("""
                    SELECT by_source, total_parsed, total_saved 
                    FROM parsing_history 
                    WHERE status = 'completed' AND (total_parsed > 0 OR total_saved > 0)
                    ORDER BY scan_date DESC 
                    LIMIT 1
                """)
                if history_result and len(history_result) > 0:
                    active_result = history_result
            
            if active_result and len(active_result) > 0:
                # by_source может быть уже dict (JSONB) или строкой (TEXT)
                by_source_value = active_result[0][0]
                if isinstance(by_source_value, dict):
                    history_by_source = by_source_value
                elif isinstance(by_source_value, str):
                    history_by_source = json.loads(by_source_value) if by_source_value else {}
                else:
                    history_by_source = {}
                total_parsed = active_result[0][1] or 0
                total_saved = active_result[0][2] or 0
                
                # Объединяем данные: берем in_db из БД, parsed/saved из истории
                # Но не перезаписываем нулями, если в БД уже есть данные
                for source, stats in history_by_source.items():
                    # Обрабатываем разные форматы данных
                    if isinstance(stats, dict):
                        parsed_val = stats.get('parsed', 0) or stats.get('total_parsed', 0) or 0
                        saved_val = stats.get('saved', 0) or stats.get('total_saved', 0) or 0
                    elif isinstance(stats, (int, float)):
                        parsed_val = int(stats)
                        saved_val = 0
                    else:
                        parsed_val = 0
                        saved_val = 0
                    
                    # Нормализуем имя источника (lowercase для сравнения)
                    source_lower = source.lower() if source else 'unknown'
                    
                    # Ищем соответствующий источник в by_source (case-insensitive)
                    matched_source = None
                    for existing_source in by_source.keys():
                        if existing_source and existing_source.lower() == source_lower:
                            matched_source = existing_source
                            break
                    
                    if matched_source:
                        # Обновляем только если есть реальные данные (не нули)
                        # Или если в БД нет данных для этого источника
                        if parsed_val > 0 or saved_val > 0 or by_source[matched_source]['in_db'] == 0:
                            by_source[matched_source]['parsed'] = parsed_val
                            by_source[matched_source]['saved'] = saved_val
                        # Если в истории нули, но в БД есть данные - оставляем как есть
                    else:
                        # Добавляем новый источник только если есть реальные данные
                        if parsed_val > 0 or saved_val > 0:
                            by_source[source] = {
                                'in_db': 0,
                                'parsed': parsed_val,
                                'saved': saved_val
                            }
            else:
                total_parsed = 0
                total_saved = 0
        else:
            result = db_manager.execute_query("SELECT COUNT(*) FROM vulnerabilities")
            total_in_db = result[0][0] if result else 0
            by_source = {}
            total_parsed = 0
            total_saved = 0
        
        # Логирование итоговой статистики
        logger.debug(f"📊 [STATS API] Возврат статистики: total_in_db={total_in_db}, by_source_count={len(by_source)}")
        
        return jsonify({
            'success': True,
            'stats': {
                'total_in_db': total_in_db,
                'total_parsed': total_parsed,
                'total_saved': total_saved,
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

@app.route('/api/redhat/import', methods=['POST'])
@csrf.exempt
@admin_required
def api_redhat_import():
    """Импорт Red Hat CVE из JSON файлов в БД"""
    try:
        from services.redhat_db_importer import RedHatDBImporter
        from services.redhat_full_downloader import download_all_pages, DATA_DIR
        import threading
        
        data = request.get_json() or {}
        mode = data.get('mode', 'import')  # download, import, csv
        max_pages = data.get('max_pages')
        import_limit = data.get('import_limit')
        skip_existing = data.get('skip_existing', True)
        
        logger.info(f"🚀 [API] Запуск импорта Red Hat CVE: mode={mode}, max_pages={max_pages}, limit={import_limit}")
        
        def run_import():
            try:
                importer = RedHatDBImporter(data_dir=str(DATA_DIR))
                
                # Режим 1: Скачать и импортировать
                if mode == 'download':
                    logger.info(f"Скачивание Red Hat CVE (max_pages={max_pages})...")
                    pages = download_all_pages(max_pages=max_pages)
                    logger.info(f"Скачано страниц: {pages}")
                
                # Режим 2 и 3: Импорт из файлов или CSV
                if mode in ['import', 'download']:
                    result = importer.import_to_database(
                        limit=import_limit,
                        skip_existing=skip_existing
                    )
                elif mode == 'csv':
                    csv_path = data.get('csv_path', str(DATA_DIR / 'redhat_all_cve.csv'))
                    result = importer.import_from_csv(csv_path, limit=import_limit)
                else:
                    result = {
                        'success': False,
                        'message': f'Неизвестный режим: {mode}',
                        'total': 0,
                        'imported': 0,
                        'skipped': 0,
                        'errors': 0
                    }
                
                logger.info(f"✅ [API] Импорт Red Hat завершен: {result}")
                
            except Exception as e:
                logger.error(f"❌ [API] Ошибка импорта Red Hat: {e}", exc_info=True)
        
        # Запуск в отдельном потоке
        import_thread = threading.Thread(target=run_import, daemon=True)
        import_thread.start()
        
        # Возвращаем немедленный ответ
        return jsonify({
            'success': True,
            'message': 'Импорт Red Hat CVE запущен',
            'mode': mode
        })
        
    except Exception as e:
        logger.error(f"Ошибка запуска импорта Red Hat: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/redhat/import-sync', methods=['POST'])
@csrf.exempt
@admin_required
def api_redhat_import_sync():
    """Синхронный импорт Red Hat CVE (для небольших объемов)"""
    try:
        from services.redhat_db_importer import RedHatDBImporter
        from services.redhat_full_downloader import download_all_pages, DATA_DIR
        
        data = request.get_json() or {}
        mode = data.get('mode', 'import')
        max_pages = data.get('max_pages')  # None = без ограничений
        import_limit = data.get('import_limit')  # None = без ограничений
        skip_existing = data.get('skip_existing', True)
        
        logger.info(f"🚀 [API] Синхронный импорт Red Hat CVE: mode={mode}, max_pages={max_pages}, limit={import_limit}")
        
        # Для синхронного режима ограничиваем объемы
        if not import_limit and mode != 'csv':
            import_limit = 500  # Безопасный лимит для синхронного режима
        
        importer = RedHatDBImporter(data_dir=str(DATA_DIR))
        
        # Скачивание если нужно
        if mode == 'download':
            pages = download_all_pages(max_pages=max_pages or 5)  # Ограничиваем для синхронного режима
            logger.info(f"Скачано страниц: {pages}")
        
        # Импорт
        if mode in ['import', 'download']:
            result = importer.import_to_database(
                limit=import_limit,
                skip_existing=skip_existing
            )
        elif mode == 'csv':
            csv_path = data.get('csv_path', str(DATA_DIR / 'redhat_all_cve.csv'))
            result = importer.import_from_csv(csv_path, limit=import_limit)
        else:
            result = {
                'success': False,
                'message': f'Неизвестный режим: {mode}',
                'total': 0,
                'imported': 0,
                'skipped': 0,
                'errors': 0
            }
        
        # Логирование результата импорта
        logger.info(f"✅ [REDHAT IMPORT] Импорт завершен: imported={result.get('imported', 0)}, skipped={result.get('skipped', 0)}, errors={result.get('errors', 0)}")
        
        # Принудительно обновляем статистику после импорта
        # (статистика обновится при следующем запросе, но можно добавить здесь явное обновление)
        
        return jsonify({
            'success': result['success'],
            'message': result.get('message', 'Импорт завершен'),
            'imported': result.get('imported', 0),
            'skipped': result.get('skipped', 0),
            'errors': result.get('errors', 0),
            'total': result.get('total', 0)
        })
        
    except Exception as e:
        logger.error(f"Ошибка импорта Red Hat: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


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

@app.route('/api/ml-platform/connection', methods=['GET'])
@csrf.exempt
@login_required
def api_ml_platform_connection():
    """Проверка подключения к ML платформе"""
    try:
        status = ml_platform_client.check_connection()
        return jsonify({'success': True, 'status': status})
    except Exception as e:
        logger.error(f"Ошибка проверки подключения: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/diagnostics/connectivity', methods=['GET'])
@csrf.exempt
@login_required
@admin_required
def api_diagnostics_connectivity():
    """
    Серверная диагностика связности между VM:
    - backend->DB (SQL/TCP)
    - backend->ML API (HTTP) + SSH to k8s-worker
    - k8s-worker->DB/back (TCP) через SSH
    """
    try:
        report = ml_platform_client.diagnose_connectivity()
        return jsonify({'success': True, 'report': report})
    except Exception as e:
        logger.error(f"❌ Ошибка диагностики связности: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ai/batch-analyze', methods=['POST'])
@csrf.exempt
@login_required
@admin_required
def api_ai_batch_analyze():
    """Пакетный анализ уязвимостей через ML платформу"""
    try:
        data = request.get_json() or {}
        vulnerability_ids = data.get('vulnerability_ids', [])
        
        logger.info(f"🚀 [API] Запрос на ИИ-анализ: vulnerability_ids={len(vulnerability_ids) if vulnerability_ids else 'all'}")
        
        # Используем ML платформу для анализа
        result = ml_platform_client.start_ai_analysis(vulnerability_ids if vulnerability_ids else None)
        
        logger.info(f"📊 [API] Результат ИИ-анализа: success={result.get('success')}, error={result.get('error', 'N/A')}")
        
        if result['success']:
            return jsonify({
                'success': True,
                'result': result.get('data', {}),
                'message': 'Анализ запущен через ML платформу'
            })
        else:
            # Возвращаем детальную информацию об ошибке
            error_response = {
                'success': False,
                'error': result.get('error', 'Ошибка анализа'),
                'hint': result.get('hint', '')
            }
            logger.warning(f"⚠️ [API] Ошибка ИИ-анализа: {error_response}")
            return jsonify(error_response), 500
    except Exception as e:
        logger.error(f"❌ [API] Критическая ошибка пакетного анализа: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/statistics', methods=['GET'])
@csrf.exempt
@login_required
def api_ai_statistics():
    """Статистика по ключевым словам из ML платформы"""
    try:
        result = ml_platform_client.get_ai_statistics()
        if result['success']:
            return jsonify({'success': True, 'statistics': result.get('data', {})})
        else:
            # Fallback на локальный сервис
            if AI_SERVICE_AVAILABLE:
                stats = ai_integration_service.get_keywords_statistics()
                return jsonify({'success': True, 'statistics': stats})
            return jsonify({'success': False, 'error': result.get('error', 'ML платформа недоступна')}), 503
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
    """Обучение модели на новых данных через ML платформу"""
    try:
        data = request.get_json()
        config = data.get('config', {})
        
        # Запускаем обучение на ML платформе
        result = ml_platform_client.start_training(config)
        
        if result['success']:
            return jsonify({
                'success': True,
                'task_id': result.get('data', {}).get('task_id'),
                'message': 'Обучение запущено на ML платформе'
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Ошибка запуска обучения')}), 500
        
        # Старый код для fallback
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
    """Запуск мониторинга сайтов через ML платформу"""
    try:
        data = request.get_json() or {}
        sites = data.get('sites', [])
        
        result = ml_platform_client.start_site_monitoring(sites)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': 'Мониторинг запущен на ML платформе',
                'data': result.get('data', {})
            })
        else:
            return jsonify({'success': False, 'error': result.get('error', 'Ошибка запуска мониторинга')}), 500
    except Exception as e:
        logger.error(f"Ошибка запуска мониторинга: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/monitor-stop', methods=['POST'])
@csrf.exempt
@login_required
@admin_required
def api_ai_monitor_stop():
    """Остановка мониторинга"""
    try:
        # TODO: Реализовать остановку через ML платформу
        return jsonify({'success': True, 'message': 'Мониторинг остановлен'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/monitor-status', methods=['GET'])
@csrf.exempt
@login_required
def api_ai_monitor_status():
    """Статус мониторинга из ML платформы"""
    try:
        result = ml_platform_client.get_monitoring_status()
        if result['success']:
            return jsonify({'success': True, 'status': result.get('data', {})})
        else:
            return jsonify({'success': False, 'error': result.get('error', 'ML платформа недоступна')}), 503
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# === ML ПЛАТФОРМА API ENDPOINTS ===

@app.route('/api/ml-platform/training/start', methods=['POST'])
@csrf.exempt
@login_required
@admin_required
def api_ml_training_start():
    """Запуск обучения модели"""
    try:
        data = request.get_json() or {}
        result = ml_platform_client.start_training(data)
        
        if result['success']:
            return jsonify({
                'success': True,
                'task_id': result.get('data', {}).get('task_id'),
                'message': 'Обучение запущено'
            })
        else:
            return jsonify({'success': False, 'error': result.get('error')}), 500
    except Exception as e:
        logger.error(f"Ошибка запуска обучения: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ml-platform/training/status/<task_id>', methods=['GET'])
@csrf.exempt
@login_required
def api_ml_training_status(task_id):
    """Статус обучения"""
    try:
        result = ml_platform_client.get_training_status(task_id)
        if result['success']:
            return jsonify({'success': True, 'status': result.get('data', {})})
        else:
            return jsonify({'success': False, 'error': result.get('error')}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ml-platform/training/history', methods=['GET'])
@csrf.exempt
@login_required
def api_ml_training_history():
    """История обучения"""
    try:
        result = ml_platform_client.get_training_history()
        if result['success']:
            return jsonify({'success': True, 'history': result.get('data', {})})
        else:
            return jsonify({'success': False, 'error': result.get('error')}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ml-platform/passports/<cve_id>', methods=['GET'])
@csrf.exempt
@login_required
def api_ml_passport(cve_id):
    """Получение паспорта CVE"""
    try:
        result = ml_platform_client.get_cve_passport(cve_id)
        if result['success']:
            return jsonify({'success': True, 'passport': result.get('data', {})})
        else:
            return jsonify({'success': False, 'error': result.get('error')}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ml-platform/passports', methods=['GET'])
@csrf.exempt
@login_required
def api_ml_passports():
    """Получение всех паспортов"""
    try:
        limit = request.args.get('limit', 100, type=int)
        result = ml_platform_client.get_all_passports(limit)
        if result['success']:
            return jsonify({'success': True, 'passports': result.get('data', {})})
        else:
            return jsonify({'success': False, 'error': result.get('error')}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/risk/calculate', methods=['POST'])
@csrf.exempt
@login_required
def api_risk_calculate():
    """
    Calculate Risk_s using CVSS+EPSS formulas (server-side).
    Input:
      - { "cve_ids": ["CVE-..."], "fetch_epss": true|false }
      - OR { "vulnerability_ids": [1,2,3], "fetch_epss": true|false }
    """
    try:
        payload = request.get_json(force=True, silent=True) or {}
        fetch_epss = bool(payload.get("fetch_epss", False))

        cve_ids = payload.get("cve_ids") or []
        vuln_ids = payload.get("vulnerability_ids") or []

        items = []
        missing: List[str] = []

        if vuln_ids:
            # Load from DB
            from models.database import DatabaseManager
            from models.legacy_repositories import LegacyVulnerabilityRepository
            db = DatabaseManager()
            repo = LegacyVulnerabilityRepository(db.connection)
            for vid in vuln_ids:
                v = repo.get_by_id(int(vid))
                if not v:
                    continue
                cve = (getattr(v, "cve_id", None) or "").strip()
                cvss = float(getattr(v, "cvss_score", 0.0) or 0.0)
                epss = getattr(v, "epss_score", None)
                if epss is None and cve:
                    missing.append(cve)
                items.append(RiskItem(cve_id=cve, cvss=cvss, epss=float(epss or 0.0)))
        else:
            # Use CVE list only: CVSS unknown -> 0 unless you send cvss_map
            cvss_map = payload.get("cvss_map") or {}
            epss_map = payload.get("epss_map") or {}
            for cve in cve_ids:
                cve_str = (cve or "").strip()
                if not cve_str:
                    continue
                cvss = float(cvss_map.get(cve_str, 0.0) or 0.0)
                epss = epss_map.get(cve_str)
                if epss is None:
                    missing.append(cve_str)
                items.append(RiskItem(cve_id=cve_str, cvss=cvss, epss=float(epss or 0.0)))

        if fetch_epss and missing:
            fetched = fetch_epss_scores(missing)
            for it in items:
                if (it.epss or 0.0) <= 0.0 and it.cve_id in fetched:
                    it.epss = fetched[it.cve_id]

        result = compute_risk(items)
        # Report CVEs that still have no EPSS after optional fetch
        result["missing_epss"] = [it.cve_id for it in items if (it.epss or 0.0) <= 0.0 and it.cve_id]
        return jsonify(result)
    except Exception as e:
        logger.error(f"Risk calculation error: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


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

