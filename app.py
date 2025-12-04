from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, Response
import json
import time
import logging
from datetime import datetime
from typing import Optional
import os
import tempfile
from werkzeug.utils import secure_filename

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

# Для импорта Excel
import pandas as pd
from models.entities import Vulnerability


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
vuln_service = VulnerabilityService(use_optimized=True)
operator_service = OperatorService()
export_service = ExportService()
parser_service = ParserService()
data_manager = DataManager()
assignment_manager = AssignmentManager(data_manager)
async_parser = AsyncParser()

# === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===

def get_vulnerabilities_with_operators(page: int = 1, per_page: int = 50,
                                   status: Optional[str] = None, severity: Optional[str] = None,
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
        'completion_rate': (len([v for v in vulnerabilities if v.status in ['completed', 'approved']]) / len(
            vulnerabilities) * 100) if vulnerabilities else 0,
        'active_operators': len(operators),
        'total_operators': len(operators)
    }


def get_analytics_data():
    """Получить данные для аналитики"""
    # Используем AnalyticsService для получения данных
    analytics_data = analytics_service.get_analytics_data()
    
    # Получаем уязвимости и операторов для обратной совместимости
    vulnerabilities, operators = get_vulnerabilities_with_operators_old()
    
    # Объединяем данные
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


# === ОСНОВНЫЕ МАРШРУТЫ ===




@app.route('/dashboard')
def dashboard():
    """Главная страница - дашборд"""
    vulnerabilities, operators = get_vulnerabilities_with_operators_old()
    stats = get_dashboard_stats()

    return render_template('dashboard.html',
                           vulnerabilities=vulnerabilities,
                           operators=operators,
                           stats=stats)


@app.route('/vulnerabilities')
def vulnerabilities_list():
    """Страница со всеми уязвимостями с пагинацией"""
    # Получаем параметры пагинации и фильтрации
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    status = request.args.get('status', None)
    severity = request.args.get('severity', None)
    search = request.args.get('search', None)
    
    vulnerabilities, operators, total_count = get_vulnerabilities_with_operators(
        page=page, per_page=per_page,
        status=status, severity=severity, search=search
    )
    
    # Вычисляем пагинацию
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
def operators_page():
    """Страница операторов"""
    vulnerabilities, operators = get_vulnerabilities_with_operators_old()
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


@app.route('/import-excel')
def import_excel_page():
    """Страница импорта уязвимостей из Excel"""
    return render_template('import_excel.html')


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
    """Собранный статус доступных парсеров и интеграций с реальной статистикой из БД"""
    try:
        # Подключение к БД для статистики  
        # Используем существующее подключение
        conn = db
        
        # OSV Parser - реальная статистика
        osv_status = parser_service.get_parsing_status()
        
        # Подсчет OSV уязвимостей в БД
        with conn.cursor() as cur:
                # OSV уязвимости (источники: osv.dev, BIT-*, CGA-*, GHSA-*, etc.)
                cur.execute("""
                    SELECT COUNT(*) FROM vulnerabilities 
                    WHERE source_identifier IN ('osv.dev', 'osv') 
                       OR title LIKE 'BIT-%' OR title LIKE 'CGA-%' 
                       OR title LIKE 'GHSA-%' OR title LIKE 'BELL-%'
                """)
                osv_count = cur.fetchone()[0] if cur.rowcount > 0 else 0
                
                # NVD уязвимости (CVE с source_identifier)
                cur.execute("""
                    SELECT COUNT(*), 
                           MAX(published) as last_sync,
                           COUNT(CASE WHEN published > NOW() - INTERVAL '7 days' THEN 1 END) as recent_week
                    FROM vulnerabilities 
                    WHERE cve_id IS NOT NULL 
                      AND source_identifier IS NOT NULL
                      AND source_identifier != 'redhat'
                      AND source_identifier != 'ubuntu'
                      AND source_identifier != 'debian'
                """)
                nvd_row = cur.fetchone()
                nvd_count = nvd_row[0] if nvd_row else 0
                nvd_last_sync = nvd_row[1].strftime('%Y-%m-%d %H:%M:%S') if nvd_row and nvd_row[1] else None
                nvd_recent_week = nvd_row[2] if nvd_row else 0
                
                # Red Hat уязвимости
                cur.execute("""
                    SELECT COUNT(*),
                           MAX(published) as last_import,
                           COUNT(CASE WHEN severity IN ('critical', 'important') THEN 1 END) as high_severity
                    FROM vulnerabilities 
                    WHERE source_identifier = 'redhat'
                """)
                redhat_row = cur.fetchone()
                redhat_count = redhat_row[0] if redhat_row else 0
                redhat_last_import = redhat_row[1].strftime('%Y-%m-%d %H:%M:%S') if redhat_row and redhat_row[1] else None
                redhat_high_severity = redhat_row[2] if redhat_row else 0
                
                # Ubuntu уязвимости
                cur.execute("""
                    SELECT COUNT(*),
                           MAX(published) as last_import
                    FROM vulnerabilities 
                    WHERE source_identifier = 'ubuntu'
                """)
                ubuntu_row = cur.fetchone()
                ubuntu_count = ubuntu_row[0] if ubuntu_row else 0
                ubuntu_last_import = ubuntu_row[1].strftime('%Y-%m-%d %H:%M:%S') if ubuntu_row and ubuntu_row[1] else None
                
                # Debian уязвимости
                cur.execute("""
                    SELECT COUNT(*),
                           MAX(published) as last_import
                    FROM vulnerabilities 
                    WHERE source_identifier = 'debian'
                """)
                debian_row = cur.fetchone()
                debian_count = debian_row[0] if debian_row else 0
                debian_last_import = debian_row[1].strftime('%Y-%m-%d %H:%M:%S') if debian_row and debian_row[1] else None
                
                # AI уязвимости
                cur.execute("""
                    SELECT COUNT(*),
                           AVG(ai_confidence) as avg_confidence,
                           COUNT(CASE WHEN ai_confidence >= 0.7 THEN 1 END) as high_confidence
                    FROM vulnerabilities 
                    WHERE is_ai_related = TRUE
                """)
                ai_row = cur.fetchone()
                ai_count = ai_row[0] if ai_row else 0
                ai_avg_confidence = float(ai_row[1]) if ai_row and ai_row[1] else 0.0
                ai_high_confidence = ai_row[2] if ai_row else 0
                
                # Всего уязвимостей
                cur.execute("SELECT COUNT(*) FROM vulnerabilities")
                total_vulns = cur.fetchone()[0] if cur.rowcount > 0 else 0

        # Обновляем статусы с реальными данными
        osv_status.update({
            'total_in_db': osv_count,
            'percentage': round((osv_count / total_vulns * 100) if total_vulns > 0 else 0, 1)
        })

        # NVD Integration
        try:
            nvd_status = nvd_integration.get_sync_status()
            nvd_connection = nvd_integration.validate_connection()
            nvd_status.update({
                'total_in_db': nvd_count,
                'last_sync': nvd_last_sync,
                'recent_week': nvd_recent_week,
                'percentage': round((nvd_count / total_vulns * 100) if total_vulns > 0 else 0, 1)
            })
        except Exception as e:
            nvd_status = {
                'status': 'error', 
                'error': str(e),
                'total_in_db': nvd_count,
                'last_sync': nvd_last_sync,
                'recent_week': nvd_recent_week
            }
            nvd_connection = {'status': 'error', 'message': str(e)}

        # Red Hat Importer
        redhat_status = {
            'available': True,
            'total_in_db': redhat_count,
            'last_import': redhat_last_import,
            'high_severity_count': redhat_high_severity,
            'percentage': round((redhat_count / total_vulns * 100) if total_vulns > 0 else 0, 1),
            'notes': f'В БД: {redhat_count} CVE ({redhat_high_severity} critical/important)'
        }
        
        # Ubuntu Security
        ubuntu_status = {
            'available': True,
            'type': 'API',
            'total_in_db': ubuntu_count,
            'last_import': ubuntu_last_import,
            'percentage': round((ubuntu_count / total_vulns * 100) if total_vulns > 0 else 0, 1),
            'notes': f'В БД: {ubuntu_count} уязвимостей'
        }
        
        # Debian Security Tracker
        debian_status = {
            'available': True,
            'type': 'API',
            'total_in_db': debian_count,
            'last_import': debian_last_import,
            'percentage': round((debian_count / total_vulns * 100) if total_vulns > 0 else 0, 1),
            'notes': f'В БД: {debian_count} уязвимостей'
        }
        
        # AI Tagger Service
        ai_tagger_status = {
            'available': True,
            'type': 'Service',
            'ai_vulnerabilities': ai_count,
            'avg_confidence': round(ai_avg_confidence * 100, 1),
            'high_confidence_count': ai_high_confidence,
            'percentage': round((ai_count / total_vulns * 100) if total_vulns > 0 else 0, 1),
            'notes': f'Найдено {ai_count} AI-уязвимостей (средняя уверенность: {round(ai_avg_confidence * 100, 1)}%)'
        }
        
        # Universal Vendor Parser
        try:
            from services.universal_vendor_parser import universal_vendor_parser
            vendor_sources_count = len(universal_vendor_parser.sources)
            vendor_total = ubuntu_count + debian_count
            vendor_status = {
                'available': True,
                'type': 'Multi-source',
                'sources_count': vendor_sources_count,
                'total_parsed': vendor_total,
                'breakdown': {
                    'ubuntu': ubuntu_count,
                    'debian': debian_count
                },
                'notes': f'{vendor_sources_count} источников, спарсено {vendor_total} уязвимостей'
            }
        except Exception as e:
            vendor_status = {
                'available': False,
                'type': 'Multi-source',
                'notes': f'Ошибка: {str(e)}'
            }

        # Scheduler
        scheduler_status = {
            'is_running': scheduler.is_running,
            'status': 'active' if scheduler.is_running else 'stopped'
        }
        
        # Общая статистика
        stats_summary = {
            'total_vulnerabilities': total_vulns,
            'by_source': {
                'osv': osv_count,
                'nvd': nvd_count,
                'redhat': redhat_count,
                'ubuntu': ubuntu_count,
                'debian': debian_count
            },
            'ai_related': ai_count,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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
                'ubuntu': ubuntu_status,
                'debian': debian_status,
                'ai_tagger': ai_tagger_status,
                'vendor_parser': vendor_status,
                'scheduler': scheduler_status
            },
            'summary': stats_summary
        })
    except Exception as e:
        logger.error(f"Parsers status error: {e}")
        import traceback
        traceback.print_exc()
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

# === EXCEL ИМПОРТ/ЭКСПОРТ ===

@app.route('/api/excel/import/preview', methods=['POST'])
def preview_excel_import():
    """Предварительный просмотр Excel файла для импорта"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'Файл не найден'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'Файл не выбран'})
        
        # Сохраняем файл временно
        temp_dir = tempfile.mkdtemp()
        filename = file.filename or 'import.xlsx'
        filepath = os.path.join(temp_dir, secure_filename(filename))
        file.save(filepath)
        
        # Читаем Excel файл
        df = pd.read_excel(filepath)
        
        # Получаем информацию о колонках
        columns = list(df.columns)
        row_count = len(df)
        sample_data = df.head(5).to_dict('records')
        
        # Удаляем временный файл
        os.remove(filepath)
        os.rmdir(temp_dir)
        
        return jsonify({
            'success': True,
            'columns': columns,
            'row_count': row_count,
            'sample_data': sample_data
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/excel/import', methods=['POST'])
def import_excel_vulnerabilities():
    """Импорт уязвимостей из Excel файла"""
    try:
        required_columns = ['title', 'description', 'severity']
        
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'Файл не найден'})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'Файл не выбран'})
        
        # Сохраняем файл временно
        temp_dir = tempfile.mkdtemp()
        filename = file.filename or 'import.xlsx'
        filepath = os.path.join(temp_dir, secure_filename(filename))
        file.save(filepath)
        
        # Читаем Excel файл
        df = pd.read_excel(filepath)
        
        # Проверяем обязательные колонки
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            os.remove(filepath)
            os.rmdir(temp_dir)
            return jsonify({
                'success': False, 
                'error': f'Отсутствуют обязательные колонки: {", ".join(missing_columns)}',
                'missing_columns': missing_columns,
                'available_columns': list(df.columns)
            })
        
        # Импортируем данные
        imported_count = 0
        errors = []
        
        for index, row in df.iterrows():
            try:
                # Обрабатываем cvss_score безопасно
                cvss_score_val = row.get('cvss_score')
                if cvss_score_val is not None:
                    try:
                        cvss_score = float(str(cvss_score_val))
                    except (ValueError, TypeError):
                        cvss_score = 0.0
                else:
                    cvss_score = 0.0
                
                # Создаем уязвимость
                vulnerability = Vulnerability(
                    id=0,  # Будет присвоен при сохранении
                    title=str(row['title']),
                    description=str(row['description']) if 'description' in row else '',
                    severity=str(row['severity']) if 'severity' in row else 'medium',
                    status=str(row.get('status', 'new')),
                    cvss_score=cvss_score,
                    risk_level=str(row.get('risk_level', 'medium')),
                    category=str(row.get('category', 'web'))
                )
                
                # Добавляем уязвимость
                if vuln_service.add_vulnerability(vulnerability):
                    imported_count += 1
                else:
                    errors.append(f"Строка {int(index) + 1}: Ошибка добавления уязвимости")
                    
            except Exception as e:
                errors.append(f"Строка {int(index) + 1}: {str(e)}")
        
        # Удаляем временный файл
        os.remove(filepath)
        os.rmdir(temp_dir)
        
        return jsonify({
            'success': True,
            'imported_count': imported_count,
            'errors': errors,
            'total_rows': len(df)
        })
        
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

@app.route('/get-operator/<string:operator_name>')
def get_operator_by_name_api(operator_name):
    """API для получения данных оператора по имени"""
    # Получаем всех операторов и ищем по имени
    operators = operator_service.get_all_operators()
    operator = next((op for op in operators if op.name == operator_name), None)
    
    if operator:
        return jsonify({
            'success': True,
            'operator': {
                'id': operator.id,
                'name': operator.name,
                'email': operator.email,
                'current_metric': operator.current_metric,
                'experience_level': operator.experience_level
            }
        })
    return jsonify({'success': False, 'message': f'Оператор {operator_name} не найден'})

@app.route('/get-vulnerability/<int:vuln_id>', methods=['GET'])
def get_vulnerability(vuln_id):
    """Получить данные уязвимости для редактирования"""
    vulnerability = vuln_service.get_vulnerability_by_id(vuln_id)
    if vulnerability:
        # Получаем информацию об операторе, если назначен
        operator_name = None
        operator_id = None
        if vulnerability.assigned_operator:
            operator = operator_service.get_operator_by_id(vulnerability.assigned_operator)
            if operator:
                operator_name = operator.name
                operator_id = operator.id
        
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
                'approved': vulnerability.approved,
                'assigned_operator': operator_name,
                'assigned_operator_id': operator_id
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


@app.route('/api/ai-tagger/analyze', methods=['POST'])
def ai_tagger_analyze():
    """Анализ уязвимости на AI-тематику"""
    try:
        from services.ai_tagger_service import ai_tagger
        
        data = request.get_json()
        
        result = ai_tagger.analyze_vulnerability(
            title=data.get('title', ''),
            description=data.get('description', ''),
            cve_id=data.get('cve_id', ''),
            affected_software=data.get('affected_software', []),
            references=data.get('references', [])
        )
        
        return jsonify({
            'success': True,
            'result': {
                'is_ai_related': result.is_ai_related,
                'confidence': result.confidence,
                'matched_keywords': result.matched_keywords,
                'matched_categories': result.matched_categories,
                'suggested_tags': result.suggested_tags,
                'risk_multiplier': result.risk_multiplier
            }
        })
    except Exception as e:
        logger.error(f"AI tagger error: {e}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/ai-tagger/scan-all', methods=['POST'])
def ai_tagger_scan_all():
    """Сканирование всех уязвимостей на AI-тематику"""
    try:
        from services.ai_tagger_service import ai_tagger
        import psycopg
        from config import Config
        
        logger.info("🔍 Запуск сканирования AI-уязвимостей...")
        
        db_config = Config.DATABASE_CONFIG
        conn = psycopg.connect(
            host=db_config.host,
            port=db_config.port,
            dbname=db_config.database,
            user=db_config.username,
            password=db_config.password
        )
        
        # Получаем все уязвимости
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, title, description, cve_id
                FROM vulnerabilities
                WHERE is_ai_related IS NULL OR is_ai_related = FALSE
                LIMIT 100
            """)
            rows = cur.fetchall()
        
        updated_count = 0
        ai_found_count = 0
        
        for row in rows:
            vuln_id, title, description, cve_id = row
            
            result = ai_tagger.analyze_vulnerability(
                title=title or '',
                description=description or '',
                cve_id=cve_id or ''
            )
            
            if result.is_ai_related:
                # Обновляем запись
                with conn.cursor() as cur:
                    cur.execute("""
                        UPDATE vulnerabilities
                        SET is_ai_related = %s,
                            ai_confidence = %s
                        WHERE id = %s
                    """, (True, result.confidence, vuln_id))
                    conn.commit()
                
                updated_count += 1
                ai_found_count += 1
                logger.info(f"✅ AI-уязвимость: {cve_id} (confidence: {result.confidence:.2f})")
        
        conn.close()
        
        return jsonify({
            'success': True,
            'scanned': len(rows),
            'ai_found': ai_found_count,
            'updated': updated_count
        })
        
    except Exception as e:
        logger.error(f"AI scan error: {e}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/vendors/parse', methods=['POST'])
def vendors_parse():
    """Парсинг уязвимостей от вендоров"""
    try:
        from services.universal_vendor_parser import universal_vendor_parser
        
        data = request.get_json()
        sources = data.get('sources', ['ubuntu', 'debian'])  # По умолчанию только API-источники
        limit = data.get('limit', 50)
        
        logger.info(f"🌐 Парсинг вендоров: {sources}")
        
        results = universal_vendor_parser.parse_all_sources(sources, limit_per_source=limit)
        
        # Сохраняем спарсенные уязвимости в БД
        saved_count = universal_vendor_parser.save_parsed_vulnerabilities(results)
        results['total_saved'] = saved_count
        
        return jsonify({
            'success': True,
            'total_parsed': results['total_parsed'],
            'total_saved': saved_count,
            'by_source': {k: v['parsed'] for k, v in results['by_source'].items()},
            'errors': results['errors']
        })
        
    except Exception as e:
        logger.error(f"Vendors parse error: {e}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/html-parser/parse', methods=['POST'])
def html_parser_parse():
    """Парсинг уязвимостей с использованием HTML-ориентированного парсера"""
    try:
        from services.html_vulnerability_parser import html_vulnerability_parser
        
        data = request.get_json()
        sources = data.get('sources', ['ubuntu', 'debian'])  # По умолчанию только основные источники
        limit = data.get('limit', 50)
        cve_list = data.get('cve_list', None)  # Опциональный список конкретных CVE
        
        logger.info(f"🔍 HTML-парсинг уязвимостей: {sources}")
        
        all_vulnerabilities = []
        errors = []
        
        # Парсим каждый источник
        for source_name in sources:
            try:
                vulnerabilities = html_vulnerability_parser.parse_source(
                    source_name, 
                    cve_list=cve_list, 
                    limit=limit
                )
                all_vulnerabilities.extend(vulnerabilities)
                logger.info(f"✅ {source_name}: обработано {len(vulnerabilities)} уязвимостей")
            except Exception as e:
                error_msg = f"Ошибка при парсинге {source_name}: {str(e)}"
                errors.append(error_msg)
                logger.error(error_msg)
        
        # Сохраняем спарсенные уязвимости в БД
        saved_count = html_vulnerability_parser.save_vulnerabilities(all_vulnerabilities)
        
        # Группируем по источникам для отчета
        by_source = {}
        for vuln in all_vulnerabilities:
            source = vuln.get('source', 'unknown')
            if source not in by_source:
                by_source[source] = 0
            by_source[source] += 1
        
        return jsonify({
            'success': True,
            'total_parsed': len(all_vulnerabilities),
            'total_saved': saved_count,
            'by_source': by_source,
            'errors': errors
        })
        
    except Exception as e:
        logger.error(f"HTML parser error: {e}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/vendors/sources', methods=['GET'])
def vendors_sources():
    """Список доступных источников"""
    try:
        from services.universal_vendor_parser import universal_vendor_parser
        
        sources = []
        for name, config in universal_vendor_parser.sources.items():
            sources.append({
                'name': name,
                'type': config['type'],
                'url': config['url']
            })
        
        return jsonify({
            'success': True,
            'sources': sources,
            'total': len(sources)
        })
        
    except Exception as e:
        logger.error(f"Vendors sources error: {e}")
        return jsonify({'success': False, 'message': str(e)})


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
        # Получаем информацию об операторе, если назначен
        operator_name = None
        operator_id = None
        if vulnerability.assigned_operator:
            operator = operator_service.get_operator_by_id(vulnerability.assigned_operator)
            if operator:
                operator_name = operator.name
                operator_id = operator.id
        
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
                'approved': vulnerability.approved,
                'assigned_operator': operator_name,
                'assigned_operator_id': operator_id
            }
        })
    return jsonify({'success': False, 'message': 'Уязвимость не найдена'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5002)