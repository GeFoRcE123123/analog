from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, Response
import json
import time
import logging

# Импорты сервисов
from services.vulnerability_service import VulnerabilityService
from services.operator_service import OperatorService
from services.export_service import ExportService
from services.parser_service import ParserService
from services.parsing_manager import AsyncParser, ParsingProgressManager  # ← ДОБАВИТЬ ParsingManager
from services.assignment_manager import AssignmentManager
from services.data_manager import DataManager
from services.analytics_service import analytics_service
from services.nvd_integration_service import NVDIntegrationService
from services.nvd_scheduler import NVDScheduler
from services.redhat_cve_importer import RedHatCVEImporter
from models.database import DatabaseManager
# Импорты репозиториев и БД
from models.postgres_repositories import PostgresVulnerabilityRepository
from flask import stream_with_context


# Настройка логирования
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'dev-secret-key'

# Получаем подключение к БД
db_manager = DatabaseManager()
db = db_manager.connection

# Создаем репозиторий для NVD интеграции
vulnerability_repo = PostgresVulnerabilityRepository(db)


# Инициализация сервисов
vuln_service = VulnerabilityService()
operator_service = OperatorService()
export_service = ExportService()
parser_service = ParserService()
data_manager = DataManager()
assignment_manager = AssignmentManager(data_manager)
async_parser = AsyncParser()

# ... остальной код без изменений ...


# === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===

def get_vulnerabilities_with_operators():
    """Получить уязвимости с информацией об операторах"""
    vulnerabilities = vuln_service.get_all_vulnerabilities()
    operators = operator_service.get_all_operators()
    return vulnerabilities, operators


def get_dashboard_stats():
    """Получить статистику для дашборда"""
    vulnerabilities, operators = get_vulnerabilities_with_operators()

    return {
        'total_vulnerabilities': len(vulnerabilities),
        'high_risk': len([v for v in vulnerabilities if v.severity == 'high']),
        'new_vulnerabilities': len([v for v in vulnerabilities if v.status == 'new']),
        'completion_rate': (len([v for v in vulnerabilities if v.status in ['completed', 'approved']]) / len(
            vulnerabilities) * 100) if vulnerabilities else 0,
        'active_operators': len(operators),
        'total_operators': len(operators)
    }


def get_analytics_data():
    """Получить данные для аналитики"""
    vulnerabilities, operators = get_vulnerabilities_with_operators()

    # Статистика по уровням риска
    severity_counts = {
        'high': len([v for v in vulnerabilities if v.severity == 'high']),
        'medium': len([v for v in vulnerabilities if v.severity == 'medium']),
        'low': len([v for v in vulnerabilities if v.severity == 'low'])
    }

    # Статистика по статусам
    status_counts = {
        'new': len([v for v in vulnerabilities if v.status == 'new']),
        'in_progress': len([v for v in vulnerabilities if v.status == 'in_progress']),
        'completed': len([v for v in vulnerabilities if v.status == 'completed']),
        'approved': len([v for v in vulnerabilities if v.status == 'approved'])
    }

    # Общая статистика
    total_vulnerabilities = len(vulnerabilities)
    active_operators = len(operators)
    completed_vulnerabilities = status_counts['completed'] + status_counts['approved']
    avg_performance = sum(op.current_metric for op in operators) / len(operators) if operators else 0

    return {
        'vulnerabilities': vulnerabilities,
        'operators': operators,
        'severity_counts': severity_counts,
        'status_counts': status_counts,
        'total_vulnerabilities': total_vulnerabilities,
        'active_operators': active_operators,
        'completed_vulnerabilities': completed_vulnerabilities,
        'avg_performance': avg_performance
    }


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


# === ОСНОВНЫЕ МАРШРУТЫ ===




@app.route('/')
def dashboard():
    """Главная страница - дашборд"""
    vulnerabilities, operators = get_vulnerabilities_with_operators()
    stats = get_dashboard_stats()

    return render_template('dashboard.html',
                           vulnerabilities=vulnerabilities,
                           operators=operators,
                           stats=stats)


@app.route('/vulnerabilities')
def vulnerabilities_list():
    """Страница со всеми уязвимостями"""
    vulnerabilities, operators = get_vulnerabilities_with_operators()
    return render_template('vulnerabilities_list.html',
                           vulnerabilities=vulnerabilities,
                           operators=operators)


@app.route('/operators')
def operators_page():
    """Страница операторов"""
    vulnerabilities, operators = get_vulnerabilities_with_operators()
    return render_template('operators.html',
                           vulnerabilities=vulnerabilities,
                           operators=operators)


@app.route('/performance')
def performance_analytics():
    """Страница аналитики производительности"""
    try:
        analytics_data = get_analytics_data()
        return render_template('performance_analytics.html', **analytics_data)

    except Exception as e:
        flash(f'Ошибка при загрузке аналитики: {str(e)}', 'error')
        return redirect(url_for('dashboard'))


@app.route('/review')
def review_vulnerabilities():
    """Страница проверки уязвимостей"""
    operators = operator_service.get_all_operators()
    return render_template('review.html', operators=operators)


# === API МАРШРУТЫ ДЛЯ ПАРСИНГА С ПРОГРЕСС-БАРОМ ===

@app.route('/api/start-parsing', methods=['POST'])
def start_parsing():
    """Запуск асинхронного парсинга"""
    try:
        if async_parser.is_parsing_active():
            return jsonify({'success': False, 'error': 'Парсинг уже запущен'})

        success = async_parser.start_async_parsing()
        if success:
            return jsonify({'success': True, 'message': 'Парсинг запущен'})
        else:
            return jsonify({'success': False, 'error': 'Не удалось запустить парсинг'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})




# Инициализация сервиса интеграции
nvd_integration = NVDIntegrationService(vulnerability_repo)
scheduler = NVDScheduler(nvd_integration)
redhat_importer = RedHatCVEImporter()

@app.route('/api/nvd/sync/full', methods=['POST'])
def nvd_full_sync():
    """Запуск полной синхронизации с NVD"""
    try:
        result = nvd_integration.full_sync()
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Ошибка синхронизации: {str(e)}'
        }), 500

@app.route('/api/nvd/sync/incremental', methods=['POST'])
def nvd_incremental_sync():
    """Запуск инкрементальной синхронизации"""
    try:
        days = request.json.get('days', 1)
        result = nvd_integration.incremental_sync(days=days)
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Ошибка синхронизации: {str(e)}'
        }), 500

@app.route('/api/nvd/sync/ai', methods=['POST'])
def nvd_ai_sync():
    """Синхронизация только AI уязвимостей"""
    try:
        result = nvd_integration.sync_ai_vulnerabilities()
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Ошибка синхронизации AI: {str(e)}'
        }), 500

@app.route('/api/nvd/status', methods=['GET'])
def nvd_status():
    """Получение статуса интеграции"""
    try:
        status = nvd_integration.get_sync_status()
        connection_status = nvd_integration.validate_connection()
        return jsonify({
            'service_status': status,
            'connection_status': connection_status
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Ошибка получения статуса: {str(e)}'
        }), 500


# === УПРАВЛЕНИЕ ПЛАНИРОВЩИКОМ NVD ===

@app.route('/api/nvd/scheduler/start', methods=['POST'])
def nvd_scheduler_start():
    try:
        data = request.get_json(silent=True) or {}
        mode = data.get('mode', 'hourly')
        if mode == 'daily':
            hour = int(data.get('hour', 2))
            minute = int(data.get('minute', 0))
            scheduler.start_daily_sync(hour=hour, minute=minute)
        else:
            scheduler.start_hourly_sync()
        scheduler.start()
        return jsonify({'success': True, 'mode': mode})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/nvd/scheduler/stop', methods=['POST'])
def nvd_scheduler_stop():
    try:
        scheduler.stop()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/nvd/scheduler/status', methods=['GET'])
def nvd_scheduler_status():
    try:
        return jsonify({'success': True, 'is_running': scheduler.is_running})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# === ИМПОРТ CVE ИЗ RED HAT API ===

@app.route('/api/redhat/import', methods=['POST'])
def redhat_import():
    try:
        data = request.get_json(silent=True) or {}
        limit = data.get('limit')
        severity = data.get('severity')  # critical | important | moderate | low
        product = data.get('product')
        recent_days = data.get('recent_days')

        if recent_days:
            result = redhat_importer.import_recent_cves(days=int(recent_days))
        elif severity:
            result = redhat_importer.import_by_severity(severity=severity, limit=int(limit or 50))
        else:
            filters = {}
            if product:
                filters['product'] = product
            if severity:
                filters['severity'] = severity
            result = redhat_importer.import_cves(limit=limit, **filters)

        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# === СТРАНИЦА И API СТАТУСОВ ПАРСЕРОВ ===

@app.route('/parsers')
def parsers_page():
    try:
        return render_template('parsers.html')
    except Exception as e:
        flash(f'Ошибка загрузки страницы парсеров: {str(e)}', 'error')
        return redirect(url_for('dashboard'))


@app.route('/api/parsers/status', methods=['GET'])
def get_parsers_status():
    """Собранный статус доступных парсеров и интеграций"""
    try:
        # OSV Parser
        osv_status = parser_service.get_parsing_status()

        # NVD Integration
        try:
            nvd_status = nvd_integration.get_sync_status()
            nvd_connection = nvd_integration.validate_connection()
        except Exception as e:
            nvd_status = {'status': 'error', 'error': str(e)}
            nvd_connection = {'status': 'error', 'message': str(e)}

        # Red Hat Importer: базовая заглушка (нет истории в сервисе)
        redhat_status = {
            'available': True,
            'last_run': None,
            'notes': 'Импорт доступен через /api/redhat/import'
        }

        # Scheduler
        scheduler_status = {
            'is_running': scheduler.is_running
        }

        return jsonify({
            'success': True,
            'parsers': {
                'osv': osv_status,
                'nvd': {
                    'service_status': nvd_status,
                    'connection_status': nvd_connection
                },
                'redhat': redhat_status,
                'scheduler': scheduler_status
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/parsing-progress')
def parsing_progress():
    """SSE endpoint для отслеживания прогресса парсинга"""

    def generate():
        progress_manager = ParsingProgressManager()

        while True:
            progress_data = progress_manager.get_progress()
            yield f"data: {json.dumps(progress_data)}\n\n"

            # Если парсинг завершен или ошибка, прекращаем поток
            if progress_data['status'] in ['completed', 'error']:
                break

            time.sleep(1)

    return Response(generate(), mimetype='text/event-stream')


@app.route('/api/parsing-status')
def get_parsing_status():
    """Получить текущий статус парсинга"""
    try:
        progress_data = async_parser.get_parsing_status()
        return jsonify({'success': True, 'status': progress_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# === МАРШРУТЫ ПАРСЕРА (для обратной совместимости) ===

@app.route('/parse_vulnerabilities')
def parse_vulnerabilities():
    """Запуск парсинга уязвимостей с редиректом на дашборд"""
    return handle_parsing_redirect('dashboard')


@app.route('/parse_and_show')
def parse_and_show():
    """Парсинг и отображение результатов на странице уязвимостей"""
    return handle_parsing_redirect('vulnerabilities_list')


def handle_parsing_redirect(redirect_endpoint):
    """Обработка парсинга и редиректа"""
    try:
        count = parser_service.parse_and_save_vulnerabilities()
        if count > 0:
            flash(f'✅ Успешно добавлено {count} новых уязвимостей в базу данных', 'success')
        else:
            flash('ℹ️ Новых уязвимостей не найдено или они уже есть в системе', 'info')
        return redirect(url_for(redirect_endpoint))
    except Exception as e:
        flash(f'❌ Ошибка при сканировании: {str(e)}', 'error')
        return redirect(url_for(redirect_endpoint))


@app.route('/parsing_status')
def parsing_status():
    """Страница статуса парсинга"""
    try:
        status = parser_service.get_parsing_status()
        return render_template('parsing_status.html', status=status)
    except Exception as e:
        return render_template('parsing_status.html',
                               status={'status': 'error', 'error': str(e)})


# === API МАРШРУТЫ ДЛЯ УПРАВЛЕНИЯ УЯЗВИМОСТЯМИ ===

@app.route('/api/assign-operator', methods=['POST'])
def assign_operator():
    """Назначить оператора уязвимости"""
    data = request.get_json()
    vuln_id = data.get('vulnerability_id')
    operator_id = data.get('operator_id')

    if not vuln_id or not operator_id:
        return jsonify({'success': False, 'message': 'Не указаны ID уязвимости или оператора'})

    result = assignment_manager.assign_operator_to_vulnerability(vuln_id, operator_id)
    return jsonify(result)


@app.route('/api/assign-multiple', methods=['POST'])
def assign_multiple():
    """Назначить несколько уязвимостей оператору"""
    data = request.get_json()
    operator_id = data.get('operator_id')
    vulnerability_ids = data.get('vulnerability_ids', [])

    if not operator_id or not vulnerability_ids:
        return jsonify({'success': False, 'message': 'Не указаны ID оператора или уязвимостей'})

    result = assignment_manager.assign_multiple_vulnerabilities(operator_id, vulnerability_ids)
    return jsonify(result)


@app.route('/api/operator-workload/<int:operator_id>')
def get_operator_workload(operator_id):
    """Получить нагрузку оператора"""
    result = assignment_manager.get_operator_workload(operator_id)
    return jsonify(result)


@app.route('/api/unassign-vulnerability', methods=['POST'])
def unassign_vulnerability():
    """Снять назначение с уязвимости"""
    data = request.get_json()
    vuln_id = data.get('vulnerability_id')

    if not vuln_id:
        return jsonify({'success': False, 'message': 'Не указан ID уязвимости'})

    result = assignment_manager.unassign_vulnerability(vuln_id)
    return jsonify(result)


# === API МАРШРУТЫ ДЛЯ АНАЛИТИКИ ===

@app.route('/api/analytics/refresh')
def refresh_analytics():
    """API для принудительного обновления аналитики"""
    try:
        analytics_service.invalidate_cache()
        analytics_data = analytics_service.get_analytics_data(force_refresh=True)
        return jsonify({'success': True, 'data': analytics_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/analytics/current')
def get_current_analytics():
    """API для получения текущей аналитики"""
    try:
        analytics_data = analytics_service.get_analytics_data()
        return jsonify({'success': True, 'data': analytics_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# === СТАРЫЕ API МАРШРУТЫ (для обратной совместимости) ===

@app.route('/assign-operator', methods=['POST'])
def assign_operator_old():
    """Старый endpoint для назначения оператора (обратная совместимость)"""
    data = request.get_json()
    vuln_id = data.get('vulnerability_id')
    operator_id = data.get('operator_id')

    vulnerability = vuln_service.get_vulnerability_by_id(vuln_id)
    if vulnerability and operator_id:
        vulnerability.assigned_operator = int(operator_id)
        vulnerability.status = 'in_progress'
        vuln_service.update_vulnerability(vulnerability)
        return jsonify({'success': True})

    return jsonify({'success': False})


@app.route('/update-vulnerability-status', methods=['POST'])
def update_vulnerability_status():
    """Обновить статус уязвимости"""
    data = request.get_json()
    vuln_id = data.get('vulnerability_id')
    status = data.get('status')

    vulnerability = vuln_service.get_vulnerability_by_id(vuln_id)
    if vulnerability:
        vulnerability.status = status
        vuln_service.update_vulnerability(vulnerability)
        return jsonify({'success': True})

    return jsonify({'success': False})

@app.route('/get-operator/<int:operator_id>')
def get_operator_api(operator_id):
    """API для получения данных оператора"""
    operator = operator_service.get_operator_by_id(operator_id)
    if operator:
        return jsonify({
            'success': True,
            'operator': {
                'id': operator.id,
                'name': operator.name,
                'email': operator.email,
                'current_metric': operator.current_metric
            }
        })
    return jsonify({'success': False, 'message': 'Оператор не найден'})

@app.route('/get-vulnerability/<int:vuln_id>', methods=['GET'])
def get_vulnerability(vuln_id):
    """Получить данные уязвимости для редактирования"""
    vulnerability = vuln_service.get_vulnerability_by_id(vuln_id)
    if vulnerability:
        return jsonify({
            'success': True,
            'vulnerability': {
                'id': vulnerability.id,
                'title': vulnerability.title,
                'description': vulnerability.description,
                'severity': vulnerability.severity,
                'status': vulnerability.status,
                'cvss_score': vulnerability.cvss_score,
                'risk_level': vulnerability.risk_level,
                'category': vulnerability.category,
                'modifications': vulnerability.modifications,
                'approved': vulnerability.approved
            }
        })
    return jsonify({'success': False})


@app.route('/update-vulnerability', methods=['POST'])
def update_vulnerability():
    """Обновить уязвимость"""
    data = request.get_json()
    vuln_id = data.get('vulnerability_id')
    updates = data.get('updates', {})

    success = vuln_service.update_vulnerability(vuln_id, **updates)
    return jsonify({'success': success})


# === МАРШРУТЫ ЭКСПОРТА ===

@app.route('/export/operator-vulnerabilities', methods=['POST'])
def export_operator_vulnerabilities():
    """Экспорт уязвимостей по операторам"""
    operators = operator_service.get_all_operators()
    filename = export_service.export_operator_vulnerabilities(operators)
    flash(f'Отчет уязвимостей операторов экспортирован: {filename}', 'success')
    return redirect(url_for('operators_page'))


@app.route('/export/operator/<int:operator_id>', methods=['POST'])
def export_single_operator(operator_id):
    """Экспорт уязвимостей для одного оператора"""
    operator = operator_service.get_operator_by_id(operator_id)
    if operator:
        filename = export_service.export_single_operator_vulnerabilities(operator)
        flash(f'Уязвимости оператора {operator.name} экспортированы: {filename}', 'success')
    else:
        flash('Оператор не найден', 'error')
    return redirect(url_for('operators_page'))


@app.route('/export/performance', methods=['POST'])
def export_performance():
    """Экспорт отчета производительности"""
    performance_data = operator_service.get_operator_performance_report()
    filename = export_service.export_performance_report(performance_data)
    flash(f'Отчет производительности экспортирован: {filename}', 'success')
    return redirect(url_for('dashboard'))


@app.route('/export/vulnerabilities', methods=['POST'])
def export_vulnerabilities():
    """Экспорт отчета уязвимостей"""
    operators = operator_service.get_all_operators()
    filename = export_service.export_vulnerabilities_report(operators)
    flash(f'Отчет уязвимостей экспортирован: {filename}', 'success')
    return redirect(url_for('dashboard'))


# === МАРШРУТЫ ОПЕРАТОРОВ ===

@app.route('/create-operator', methods=['POST'])
def create_operator():
    """Создать нового оператора"""
    name = request.form.get('name')
    email = request.form.get('email')
    experience_level = float(request.form.get('experience_level', 50.0))

    if not name or not email:
        flash('Имя и email оператора обязательны для заполнения', 'error')
        return redirect(url_for('operators_page'))

    try:
        new_operator = operator_service.create_operator(name, email, experience_level)
        flash(f'Оператор {new_operator.name} успешно создан!', 'success')
    except Exception as e:
        flash(f'Ошибка при создании оператора: {str(e)}', 'error')

    return redirect(url_for('operators_page'))


@app.route('/assign-vulnerabilities', methods=['POST'])
def assign_vulnerabilities():
    """Назначить уязвимости оператору"""
    data = request.get_json()
    operator_id = data.get('operator_id')
    vulnerability_ids = data.get('vulnerability_ids', [])

    print(f"Assigning vulnerabilities {vulnerability_ids} to operator {operator_id}")

    success = operator_service.assign_vulnerabilities(operator_id, vulnerability_ids)

    if success:
        print(f"Successfully assigned {len(vulnerability_ids)} vulnerabilities to operator {operator_id}")
        return jsonify({'success': True, 'assigned': len(vulnerability_ids)})
    else:
        print(f"Failed to assign vulnerabilities to operator {operator_id}")
        return jsonify({'success': False, 'message': 'Failed to assign vulnerabilities'})


@app.route('/api/live-vulnerabilities')
def live_vulnerabilities():
    """SSE endpoint для обновления уязвимостей в реальном времени"""

    def generate():
        # Отправляем текущие уязвимости
        vulnerabilities = vuln_service.get_all_vulnerabilities()
        vuln_data = [serialize_vulnerability(vuln) for vuln in vulnerabilities]

        yield f"data: {json.dumps({'type': 'initial', 'vulnerabilities': vuln_data})}\n\n"

        # Слушаем обновления (упрощенная версия)
        last_count = len(vulnerabilities)
        while True:
            time.sleep(2)
            current_vulns = vuln_service.get_all_vulnerabilities()
            current_count = len(current_vulns)

            if current_count != last_count:
                # Обновляем список
                vuln_data = [serialize_vulnerability(vuln) for vuln in current_vulns]
                yield f"data: {json.dumps({'type': 'update', 'vulnerabilities': vuln_data})}\n\n"
                last_count = current_count

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/api/operators')
def get_all_operators_api():
    """API для получения всех операторов"""
    try:
        operators = operator_service.get_all_operators()
        operators_data = [
            {
                'id': op.id,
                'name': op.name,
                'email': op.email,
                'current_metric': op.current_metric,
                'experience_level': op.experience_level
            }
            for op in operators
        ]
        return jsonify({'success': True, 'operators': operators_data})
    except Exception as e:
        logger.error(f"Error getting operators: {e}")
        return jsonify({'success': False, 'message': 'Ошибка загрузки операторов'})


@app.route('/update-metric', methods=['POST'])
def update_metric():
    """Обновить метрику оператора"""
    data = request.get_json()
    operator_id = data.get('operator_id')
    action = data.get('action')

    success = operator_service.update_operator_metric(operator_id, action)
    return jsonify({'success': success})


@app.route('/review-vulnerability', methods=['POST'])
def review_vulnerability():
    """Проверить уязвимость"""
    data = request.get_json()
    vuln_id = data.get('vulnerability_id')
    action = data.get('action')
    operator_id = data.get('operator_id')

    success = False
    if action == 'approve':
        if vuln_service.approve_vulnerability(vuln_id):
            operator_service.update_operator_metric(operator_id, 'approve')
            operator_service.remove_vulnerability_from_operator(operator_id, vuln_id)
            success = True
    elif action == 'modify':
        if vuln_service.request_modification(vuln_id):
            operator_service.update_operator_metric(operator_id, 'modify')
            success = True
    elif action == 'complete':
        if vuln_service.complete_vulnerability(vuln_id):
            operator_service.update_operator_metric(operator_id, 'complete')
            operator_service.remove_vulnerability_from_operator(operator_id, vuln_id)
            success = True

    return jsonify({'success': success})


# === ДОПОЛНИТЕЛЬНЫЕ API МАРШРУТЫ ===

@app.route('/api/dashboard-stats')
def get_dashboard_stats_api():
    """Получить статистику для дашборда"""
    stats = get_dashboard_stats()
    return jsonify({'success': True, 'stats': stats})


@app.route('/api/live-parsing-vulnerabilities')
def live_parsing_vulnerabilities():
    """SSE endpoint для получения уязвимостей в реальном времени во время парсинга"""

    def generate():
        progress_manager = ParsingProgressManager()

        # Callback для новых уязвимостей
        def on_new_vulnerability(vuln_data):
            yield f"data: {json.dumps({'type': 'vulnerability', 'vulnerability': vuln_data})}\n\n"

        # Регистрируем callback
        progress_manager.add_vulnerability_callback(on_new_vulnerability)

        try:
            # Отправляем существующие уязвимости из текущего парсинга
            current_progress = progress_manager.get_progress()
            recent_vulns = current_progress.get('recent_vulnerabilities', [])

            for vuln in recent_vulns:
                yield f"data: {json.dumps({'type': 'vulnerability', 'vulnerability': vuln})}\n\n"

            # Слушаем новые уязвимости
            while True:
                time.sleep(1)
                # Проверяем статус парсинга
                current_status = progress_manager.get_progress()
                if current_status['status'] in ['completed', 'error']:
                    yield f"data: {json.dumps({'type': 'parsing_complete', 'status': current_status['status']})}\n\n"
                    break

        except GeneratorExit:
            # Убираем callback при отключении клиента
            progress_manager.remove_vulnerability_callback(on_new_vulnerability)
        except Exception as e:
            logger.error(f"Ошибка в SSE: {e}")
        finally:
            progress_manager.remove_vulnerability_callback(on_new_vulnerability)

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/api/recent-vulnerabilities')
def get_recent_vulnerabilities():
    """Получить последние уязвимости"""
    vulnerabilities = vuln_service.get_all_vulnerabilities()
    recent_vulns = vulnerabilities[:5]  # Последние 5

    result = [serialize_vulnerability(vuln) for vuln in recent_vulns]
    return jsonify({'success': True, 'vulnerabilities': result})


@app.route('/api/parse_nvd', methods=['POST'])
def parse_nvd_vulnerabilities():
    """API endpoint для запуска парсинга NVD"""
    try:
        # Используем уже инициализированный nvd_integration
        result = nvd_integration.incremental_sync(days=30)

        return jsonify(result)

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Ошибка при парсинге: {str(e)}'
        }), 500



@app.route('/get-vulnerability/<int:vuln_id>')
def get_vulnerability_api(vuln_id):
    """API для получения данных уязвимости для редактирования"""
    vulnerability = vuln_service.get_vulnerability_by_id(vuln_id)
    if vulnerability:
        return jsonify({
            'success': True,
            'vulnerability': {
                'id': vulnerability.id,
                'title': vulnerability.title,
                'description': vulnerability.description,
                'severity': vulnerability.severity,
                'status': vulnerability.status,
                'cvss_score': vulnerability.cvss_score,
                'risk_level': vulnerability.risk_level,
                'category': vulnerability.category,
                'modifications': vulnerability.modifications,
                'approved': vulnerability.approved
            }
        })
    return jsonify({'success': False, 'message': 'Уязвимость не найдена'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5002)