"""
Сервис для выполнения тестов безопасности
Управление проектами, тестами и результатами
"""
import logging
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from models.database import DatabaseManager
from config import Config

logger = logging.getLogger(__name__)


class SecurityTestingService:
    """Сервис управления тестированием безопасности"""
    
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.logger = logging.getLogger(__name__)
    
    def create_project(self, project_data: Dict[str, Any], created_by: int) -> Optional[int]:
        """Создать проект тестирования"""
        try:
            cursor = self.db_manager.connection.cursor()
            cursor.execute("""
                INSERT INTO security_test_projects 
                (project_name, methodology_id, target_type, target_description, 
                 target_urls, scope, out_of_scope, start_date, end_date, 
                 status, assigned_to, created_by, notes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                project_data.get('project_name'),
                project_data.get('methodology_id'),
                project_data.get('target_type'),
                project_data.get('target_description'),
                project_data.get('target_urls', []),
                project_data.get('scope'),
                project_data.get('out_of_scope'),
                project_data.get('start_date'),
                project_data.get('end_date'),
                project_data.get('status', 'planned'),
                project_data.get('assigned_to'),
                created_by,
                project_data.get('notes')
            ))
            
            project_id = cursor.fetchone()[0]
            self.db_manager.connection.commit()
            cursor.close()
            
            self.logger.info(f"✅ Создан проект тестирования: {project_data.get('project_name')} (ID: {project_id})")
            return project_id
        except Exception as e:
            self.logger.error(f"Ошибка создания проекта: {e}", exc_info=True)
            if self.db_manager.connection:
                self.db_manager.connection.rollback()
            return None
    
    def get_project(self, project_id: int) -> Optional[Dict[str, Any]]:
        """Получить проект по ID"""
        try:
            cursor = self.db_manager.connection.cursor()
            cursor.execute("""
                SELECT id, project_name, methodology_id, target_type, target_description,
                       target_urls, scope, out_of_scope, start_date, end_date, status,
                       assigned_to, created_by, notes, created_at, updated_at
                FROM security_test_projects
                WHERE id = %s
            """, (project_id,))
            
            row = cursor.fetchone()
            cursor.close()
            
            if row:
                return {
                    'id': row[0],
                    'project_name': row[1],
                    'methodology_id': row[2],
                    'target_type': row[3],
                    'target_description': row[4],
                    'target_urls': row[5] if row[5] else [],
                    'scope': row[6],
                    'out_of_scope': row[7],
                    'start_date': row[8].isoformat() if row[8] else None,
                    'end_date': row[9].isoformat() if row[9] else None,
                    'status': row[10],
                    'assigned_to': row[11],
                    'created_by': row[12],
                    'notes': row[13],
                    'created_at': row[14].isoformat() if row[14] else None,
                    'updated_at': row[15].isoformat() if row[15] else None
                }
            return None
        except Exception as e:
            self.logger.error(f"Ошибка получения проекта {project_id}: {e}", exc_info=True)
            return None
    
    def get_all_projects(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Получить все проекты"""
        try:
            cursor = self.db_manager.connection.cursor()
            
            if status:
                cursor.execute("""
                    SELECT id, project_name, methodology_id, target_type, status,
                           start_date, end_date, assigned_to, created_by, created_at
                    FROM security_test_projects
                    WHERE status = %s
                    ORDER BY created_at DESC
                """, (status,))
            else:
                cursor.execute("""
                    SELECT id, project_name, methodology_id, target_type, status,
                           start_date, end_date, assigned_to, created_by, created_at
                    FROM security_test_projects
                    ORDER BY created_at DESC
                """)
            
            projects = []
            for row in cursor.fetchall():
                projects.append({
                    'id': row[0],
                    'project_name': row[1],
                    'methodology_id': row[2],
                    'target_type': row[3],
                    'status': row[4],
                    'start_date': row[5].isoformat() if row[5] else None,
                    'end_date': row[6].isoformat() if row[6] else None,
                    'assigned_to': row[7],
                    'created_by': row[8],
                    'created_at': row[9].isoformat() if row[9] else None
                })
            
            cursor.close()
            return projects
        except Exception as e:
            self.logger.error(f"Ошибка получения проектов: {e}", exc_info=True)
            return []
    
    def save_test_result(self, result_data: Dict[str, Any], tested_by: int) -> Optional[int]:
        """Сохранить результат теста"""
        try:
            cursor = self.db_manager.connection.cursor()
            cursor.execute("""
                INSERT INTO security_test_results 
                (project_id, test_id, status, severity, findings, evidence,
                 risk_score, cvss_score, remediation_status, remediation_notes,
                 remediation_priority, tested_by, tested_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                result_data.get('project_id'),
                result_data.get('test_id'),
                result_data.get('status', 'not_tested'),
                result_data.get('severity'),
                result_data.get('findings'),
                json.dumps(result_data.get('evidence', [])) if result_data.get('evidence') else None,
                result_data.get('risk_score'),
                result_data.get('cvss_score'),
                result_data.get('remediation_status', 'not_started'),
                result_data.get('remediation_notes'),
                result_data.get('remediation_priority'),
                tested_by,
                result_data.get('tested_at') or datetime.now()
            ))
            
            result_id = cursor.fetchone()[0]
            
            # Если тест выявил уязвимость, создаем связь
            if result_data.get('vulnerability_id'):
                cursor.execute("""
                    INSERT INTO test_result_vulnerabilities 
                    (test_result_id, vulnerability_id, relationship_type)
                    VALUES (%s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (result_id, result_data.get('vulnerability_id'), 'found_by'))
            
            self.db_manager.connection.commit()
            cursor.close()
            
            self.logger.info(f"✅ Сохранен результат теста (ID: {result_id})")
            return result_id
        except Exception as e:
            self.logger.error(f"Ошибка сохранения результата теста: {e}", exc_info=True)
            if self.db_manager.connection:
                self.db_manager.connection.rollback()
            return None
    
    def get_project_results(self, project_id: int) -> List[Dict[str, Any]]:
        """Получить результаты проекта"""
        try:
            cursor = self.db_manager.connection.cursor()
            cursor.execute("""
                SELECT str.id, str.test_id, st.test_code, st.test_name, str.status,
                       str.severity, str.findings, str.risk_score, str.cvss_score,
                       str.remediation_status, str.tested_by, str.tested_at
                FROM security_test_results str
                JOIN security_tests st ON str.test_id = st.id
                WHERE str.project_id = %s
                ORDER BY str.tested_at DESC
            """, (project_id,))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'id': row[0],
                    'test_id': row[1],
                    'test_code': row[2],
                    'test_name': row[3],
                    'status': row[4],
                    'severity': row[5],
                    'findings': row[6],
                    'risk_score': float(row[7]) if row[7] else None,
                    'cvss_score': float(row[8]) if row[8] else None,
                    'remediation_status': row[9],
                    'tested_by': row[10],
                    'tested_at': row[11].isoformat() if row[11] else None
                })
            
            cursor.close()
            return results
        except Exception as e:
            self.logger.error(f"Ошибка получения результатов проекта {project_id}: {e}", exc_info=True)
            return []
    
    def calculate_project_metrics(self, project_id: int) -> Dict[str, Any]:
        """Рассчитать метрики проекта"""
        try:
            cursor = self.db_manager.connection.cursor()
            
            # Получаем проект
            project = self.get_project(project_id)
            if not project:
                return {}
            
            methodology_id = project.get('methodology_id')
            
            # Подсчет результатов
            cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE status = 'passed') as passed,
                    COUNT(*) FILTER (WHERE status = 'failed') as failed,
                    COUNT(*) FILTER (WHERE status = 'skipped') as skipped,
                    COUNT(*) FILTER (WHERE status = 'na') as na,
                    COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                    COUNT(*) FILTER (WHERE severity = 'high') as high,
                    COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                    COUNT(*) FILTER (WHERE severity = 'low') as low,
                    COUNT(*) FILTER (WHERE severity = 'info') as info,
                    AVG(risk_score) as avg_risk,
                    AVG(cvss_score) as avg_cvss
                FROM security_test_results
                WHERE project_id = %s
            """, (project_id,))
            
            row = cursor.fetchone()
            
            total = row[0] or 0
            passed = row[1] or 0
            failed = row[2] or 0
            skipped = row[3] or 0
            na = row[4] or 0
            critical = row[5] or 0
            high = row[6] or 0
            medium = row[7] or 0
            low = row[8] or 0
            info = row[9] or 0
            avg_risk = float(row[10]) if row[10] else 0.0
            avg_cvss = float(row[11]) if row[11] else 0.0
            
            # Расчет compliance score
            tested = total - skipped - na
            compliance_score = (passed / tested * 100) if tested > 0 else 0.0
            
            # Сохранение метрик
            cursor.execute("""
                INSERT INTO security_test_metrics 
                (project_id, methodology_id, total_tests, tests_passed, tests_failed,
                 tests_skipped, tests_na, critical_findings, high_findings, medium_findings,
                 low_findings, info_findings, compliance_score, risk_score, average_cvss)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (project_id) DO UPDATE SET
                    total_tests = EXCLUDED.total_tests,
                    tests_passed = EXCLUDED.tests_passed,
                    tests_failed = EXCLUDED.tests_failed,
                    tests_skipped = EXCLUDED.tests_skipped,
                    tests_na = EXCLUDED.tests_na,
                    critical_findings = EXCLUDED.critical_findings,
                    high_findings = EXCLUDED.high_findings,
                    medium_findings = EXCLUDED.medium_findings,
                    low_findings = EXCLUDED.low_findings,
                    info_findings = EXCLUDED.info_findings,
                    compliance_score = EXCLUDED.compliance_score,
                    risk_score = EXCLUDED.risk_score,
                    average_cvss = EXCLUDED.average_cvss,
                    calculated_at = CURRENT_TIMESTAMP
            """, (
                project_id, methodology_id, total, passed, failed, skipped, na,
                critical, high, medium, low, info, compliance_score, avg_risk, avg_cvss
            ))
            
            self.db_manager.connection.commit()
            cursor.close()
            
            return {
                'project_id': project_id,
                'total_tests': total,
                'tests_passed': passed,
                'tests_failed': failed,
                'tests_skipped': skipped,
                'tests_na': na,
                'critical_findings': critical,
                'high_findings': high,
                'medium_findings': medium,
                'low_findings': low,
                'info_findings': info,
                'compliance_score': round(compliance_score, 2),
                'risk_score': round(avg_risk, 1),
                'average_cvss': round(avg_cvss, 1)
            }
        except Exception as e:
            self.logger.error(f"Ошибка расчета метрик проекта {project_id}: {e}", exc_info=True)
            if self.db_manager.connection:
                self.db_manager.connection.rollback()
            return {}
    
    def link_result_to_vulnerability(self, result_id: int, vulnerability_id: int, relationship_type: str = 'found_by') -> bool:
        """Связать результат теста с уязвимостью"""
        try:
            cursor = self.db_manager.connection.cursor()
            cursor.execute("""
                INSERT INTO test_result_vulnerabilities 
                (test_result_id, vulnerability_id, relationship_type)
                VALUES (%s, %s, %s)
                ON CONFLICT DO NOTHING
            """, (result_id, vulnerability_id, relationship_type))
            
            self.db_manager.connection.commit()
            cursor.close()
            
            self.logger.info(f"✅ Связан результат теста {result_id} с уязвимостью {vulnerability_id}")
            return True
        except Exception as e:
            self.logger.error(f"Ошибка связи результата с уязвимостью: {e}", exc_info=True)
            if self.db_manager.connection:
                self.db_manager.connection.rollback()
            return False


# Глобальный экземпляр
_security_testing_service_instance = None

def get_security_testing_service():
    """Получить экземпляр SecurityTestingService"""
    global _security_testing_service_instance
    if _security_testing_service_instance is None:
        _security_testing_service_instance = SecurityTestingService()
    return _security_testing_service_instance

security_testing_service = get_security_testing_service()

