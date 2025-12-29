"""
Сервис для работы с методологиями безопасности
Поддерживает OSSTMM, NIST SP 800-115, OWASP WSTG, OWASP MASTG, PCI DSS
"""
import logging
import json
from typing import Dict, List, Optional, Any
from datetime import datetime
from models.database import DatabaseManager
from config import Config

logger = logging.getLogger(__name__)


class SecurityMethodologyService:
    """Сервис управления методологиями безопасности"""
    
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.logger = logging.getLogger(__name__)
    
    def get_all_methodologies(self) -> List[Dict[str, Any]]:
        """Получить все методологии"""
        try:
            cursor = self.db_manager.connection.cursor()
            cursor.execute("""
                SELECT id, name, version, description, focus_area, 
                       documentation_url, is_active, created_at
                FROM security_methodologies
                WHERE is_active = TRUE
                ORDER BY name
            """)
            
            methodologies = []
            for row in cursor.fetchall():
                methodologies.append({
                    'id': row[0],
                    'name': row[1],
                    'version': row[2],
                    'description': row[3],
                    'focus_area': row[4],
                    'documentation_url': row[5],
                    'is_active': row[6],
                    'created_at': row[7].isoformat() if row[7] else None
                })
            
            cursor.close()
            return methodologies
        except Exception as e:
            self.logger.error(f"Ошибка получения методологий: {e}", exc_info=True)
            return []
    
    def get_methodology_by_id(self, methodology_id: int) -> Optional[Dict[str, Any]]:
        """Получить методологию по ID"""
        try:
            cursor = self.db_manager.connection.cursor()
            cursor.execute("""
                SELECT id, name, version, description, focus_area, 
                       documentation_url, is_active, created_at
                FROM security_methodologies
                WHERE id = %s
            """, (methodology_id,))
            
            row = cursor.fetchone()
            cursor.close()
            
            if row:
                return {
                    'id': row[0],
                    'name': row[1],
                    'version': row[2],
                    'description': row[3],
                    'focus_area': row[4],
                    'documentation_url': row[5],
                    'is_active': row[6],
                    'created_at': row[7].isoformat() if row[7] else None
                }
            return None
        except Exception as e:
            self.logger.error(f"Ошибка получения методологии {methodology_id}: {e}", exc_info=True)
            return None
    
    def get_categories(self, methodology_id: int) -> List[Dict[str, Any]]:
        """Получить категории методологии"""
        try:
            cursor = self.db_manager.connection.cursor()
            cursor.execute("""
                SELECT id, category_code, category_name, description, 
                       parent_category_id, order_index
                FROM methodology_categories
                WHERE methodology_id = %s
                ORDER BY order_index, category_code
            """, (methodology_id,))
            
            categories = []
            for row in cursor.fetchall():
                categories.append({
                    'id': row[0],
                    'category_code': row[1],
                    'category_name': row[2],
                    'description': row[3],
                    'parent_category_id': row[4],
                    'order_index': row[5]
                })
            
            cursor.close()
            return categories
        except Exception as e:
            self.logger.error(f"Ошибка получения категорий методологии {methodology_id}: {e}", exc_info=True)
            return []
    
    def get_tests(self, category_id: Optional[int] = None, methodology_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Получить тесты"""
        try:
            cursor = self.db_manager.connection.cursor()
            
            if category_id:
                cursor.execute("""
                    SELECT id, test_code, test_name, description, test_type, 
                           severity, prerequisites, test_steps, expected_results,
                           remediation_guidance, references, cwe_ids, owasp_category
                    FROM security_tests
                    WHERE category_id = %s AND is_active = TRUE
                    ORDER BY test_code
                """, (category_id,))
            elif methodology_id:
                cursor.execute("""
                    SELECT st.id, st.test_code, st.test_name, st.description, st.test_type, 
                           st.severity, st.prerequisites, st.test_steps, st.expected_results,
                           st.remediation_guidance, st.references, st.cwe_ids, st.owasp_category
                    FROM security_tests st
                    JOIN methodology_categories mc ON st.category_id = mc.id
                    WHERE mc.methodology_id = %s AND st.is_active = TRUE
                    ORDER BY st.test_code
                """, (methodology_id,))
            else:
                cursor.execute("""
                    SELECT id, test_code, test_name, description, test_type, 
                           severity, prerequisites, test_steps, expected_results,
                           remediation_guidance, references, cwe_ids, owasp_category
                    FROM security_tests
                    WHERE is_active = TRUE
                    ORDER BY test_code
                """)
            
            tests = []
            for row in cursor.fetchall():
                tests.append({
                    'id': row[0],
                    'test_code': row[1],
                    'test_name': row[2],
                    'description': row[3],
                    'test_type': row[4],
                    'severity': row[5],
                    'prerequisites': row[6],
                    'test_steps': row[7] if isinstance(row[7], list) else json.loads(row[7]) if row[7] else [],
                    'expected_results': row[8],
                    'remediation_guidance': row[9],
                    'references': row[10] if row[10] else [],
                    'cwe_ids': row[11] if row[11] else [],
                    'owasp_category': row[12]
                })
            
            cursor.close()
            return tests
        except Exception as e:
            self.logger.error(f"Ошибка получения тестов: {e}", exc_info=True)
            return []
    
    def create_methodology(self, methodology_data: Dict[str, Any]) -> Optional[int]:
        """Создать новую методологию"""
        try:
            cursor = self.db_manager.connection.cursor()
            cursor.execute("""
                INSERT INTO security_methodologies 
                (name, version, description, focus_area, documentation_url, is_active)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                methodology_data.get('name'),
                methodology_data.get('version'),
                methodology_data.get('description'),
                methodology_data.get('focus_area'),
                methodology_data.get('documentation_url'),
                methodology_data.get('is_active', True)
            ))
            
            methodology_id = cursor.fetchone()[0]
            self.db_manager.connection.commit()
            cursor.close()
            
            self.logger.info(f"✅ Создана методология: {methodology_data.get('name')} (ID: {methodology_id})")
            return methodology_id
        except Exception as e:
            self.logger.error(f"Ошибка создания методологии: {e}", exc_info=True)
            if self.db_manager.connection:
                self.db_manager.connection.rollback()
            return None
    
    def load_owasp_wstg(self) -> bool:
        """Загрузить OWASP WSTG методологию"""
        try:
            # Проверяем, существует ли уже
            cursor = self.db_manager.connection.cursor()
            cursor.execute("SELECT id FROM security_methodologies WHERE name = 'OWASP WSTG'")
            if cursor.fetchone():
                self.logger.info("OWASP WSTG уже загружена")
                cursor.close()
                return True
            
            # Создаем методологию
            methodology_id = self.create_methodology({
                'name': 'OWASP WSTG',
                'version': '4.2',
                'description': 'OWASP Web Security Testing Guide - стандарт для тестирования безопасности веб-приложений',
                'focus_area': 'web',
                'documentation_url': 'https://owasp.org/www-project-web-security-testing-guide/',
                'is_active': True
            })
            
            if not methodology_id:
                return False
            
            # Загружаем категории WSTG
            wstg_categories = [
                {'code': 'WSTG-INFO', 'name': 'Information Gathering', 'order': 1},
                {'code': 'WSTG-CONF', 'name': 'Configuration and Deployment Management Testing', 'order': 2},
                {'code': 'WSTG-IDNT', 'name': 'Identity Management Testing', 'order': 3},
                {'code': 'WSTG-AUTHN', 'name': 'Authentication Testing', 'order': 4},
                {'code': 'WSTG-AUTHZ', 'name': 'Authorization Testing', 'order': 5},
                {'code': 'WSTG-SESS', 'name': 'Session Management Testing', 'order': 6},
                {'code': 'WSTG-INPV', 'name': 'Input Validation Testing', 'order': 7},
                {'code': 'WSTG-ERR', 'name': 'Error Handling', 'order': 8},
                {'code': 'WSTG-CRYPST', 'name': 'Cryptography', 'order': 9},
                {'code': 'WSTG-BUSLOGIC', 'name': 'Business Logic Testing', 'order': 10},
                {'code': 'WSTG-CLIENT', 'name': 'Client Side Testing', 'order': 11},
            ]
            
            for cat_data in wstg_categories:
                cursor.execute("""
                    INSERT INTO methodology_categories 
                    (methodology_id, category_code, category_name, order_index)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                """, (methodology_id, cat_data['code'], cat_data['name'], cat_data['order']))
                category_id = cursor.fetchone()[0]
                
                # Добавляем базовые тесты для категории (пример)
                # В реальной реализации здесь будет загрузка полного списка тестов из файла
                self.logger.info(f"✅ Загружена категория {cat_data['code']} (ID: {category_id})")
            
            self.db_manager.connection.commit()
            cursor.close()
            
            self.logger.info(f"✅ OWASP WSTG успешно загружена")
            return True
        except Exception as e:
            self.logger.error(f"Ошибка загрузки OWASP WSTG: {e}", exc_info=True)
            if self.db_manager.connection:
                self.db_manager.connection.rollback()
            return False
    
    def get_methodology_statistics(self, methodology_id: int) -> Dict[str, Any]:
        """Получить статистику по методологии"""
        try:
            cursor = self.db_manager.connection.cursor()
            
            # Количество категорий
            cursor.execute("""
                SELECT COUNT(*) FROM methodology_categories 
                WHERE methodology_id = %s
            """, (methodology_id,))
            categories_count = cursor.fetchone()[0]
            
            # Количество тестов
            cursor.execute("""
                SELECT COUNT(*) FROM security_tests st
                JOIN methodology_categories mc ON st.category_id = mc.id
                WHERE mc.methodology_id = %s AND st.is_active = TRUE
            """, (methodology_id,))
            tests_count = cursor.fetchone()[0]
            
            # Количество проектов
            cursor.execute("""
                SELECT COUNT(*) FROM security_test_projects
                WHERE methodology_id = %s
            """, (methodology_id,))
            projects_count = cursor.fetchone()[0]
            
            cursor.close()
            
            return {
                'methodology_id': methodology_id,
                'categories_count': categories_count,
                'tests_count': tests_count,
                'projects_count': projects_count
            }
        except Exception as e:
            self.logger.error(f"Ошибка получения статистики методологии {methodology_id}: {e}", exc_info=True)
            return {}


# Глобальный экземпляр
_security_methodology_service_instance = None

def get_security_methodology_service():
    """Получить экземпляр SecurityMethodologyService"""
    global _security_methodology_service_instance
    if _security_methodology_service_instance is None:
        _security_methodology_service_instance = SecurityMethodologyService()
    return _security_methodology_service_instance

security_methodology_service = get_security_methodology_service()

