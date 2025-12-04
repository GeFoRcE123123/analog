import logging
from typing import List, Optional, Tuple
from models.entities import Vulnerability
from models.optimized_database import optimized_db_manager

logger = logging.getLogger(__name__)

class OptimizedPostgresVulnerabilityRepository:
    """Оптимизированный PostgreSQL репозиторий для уязвимостей с кэшированием и connection pooling"""
    
    def __init__(self):
        self.db_manager = optimized_db_manager
    
    def get_by_id(self, vuln_id: int) -> Optional[Vulnerability]:
        # Проверяем кэш сначала
        cache_key = f"vuln:id:{vuln_id}"
        cached_result = self.db_manager.get_cached(cache_key)
        if cached_result:
            return Vulnerability.from_db_row(tuple(cached_result))
        
        query = """
        SELECT id, title, description, severity, status, assigned_operator, 
               created_date, completed_date, approved, modifications, 
               cvss_score, risk_level, category
        FROM vulnerabilities 
        WHERE id = %s
        """
        try:
            result = self.db_manager.execute_query(query, (vuln_id,))
            if result:
                vulnerability = Vulnerability.from_db_row(result[0])
                # Сохраняем в кэш на 5 минут
                self.db_manager.set_cached(cache_key, result[0], 300)
                return vulnerability
            return None
        except Exception as e:
            logger.error(f"Error getting vulnerability by ID {vuln_id}: {e}")
            return None
    
    def get_all(self) -> List[Vulnerability]:
        """Получить все уязвимости (ограничено для предотвращения перогрузки)"""
        cache_key = "vuln:all"
        cached_result = self.db_manager.get_cached(cache_key)
        if cached_result:
            return [Vulnerability.from_db_row(tuple(row)) for row in cached_result]
        
        query = """
            SELECT id, title, description, severity, status, assigned_operator, 
                   created_date, completed_date, approved, modifications, 
                   cvss_score, risk_level, category
            FROM vulnerabilities 
            ORDER BY created_date DESC
            LIMIT 1000
            """
        try:
            rows = self.db_manager.execute_query(query)
            vulnerabilities = [Vulnerability.from_db_row(row) for row in rows]
            # Сохраняем в кэш на 2 минуты
            self.db_manager.set_cached(cache_key, [list(row) for row in rows], 120)
            return vulnerabilities
        except Exception as e:
            logger.error(f"Error getting all vulnerabilities: {e}")
            return []

    def get_all_unlimited(self) -> List[Vulnerability]:
        """Получить все уязвимости без ограничений (для аналитики)"""
        cache_key = "vuln:all:unlimited"
        cached_result = self.db_manager.get_cached(cache_key)
        if cached_result:
            return [Vulnerability.from_db_row(tuple(row)) for row in cached_result]
        
        query = """
            SELECT id, title, description, severity, status, assigned_operator, 
                   created_date, completed_date, approved, modifications, 
                   cvss_score, risk_level, category
            FROM vulnerabilities 
            ORDER BY created_date DESC
            """
        try:
            rows = self.db_manager.execute_query(query)
            vulnerabilities = [Vulnerability.from_db_row(row) for row in rows]
            # Сохраняем в кэш на 2 минуты
            self.db_manager.set_cached(cache_key, [list(row) for row in rows], 120)
            return vulnerabilities
        except Exception as e:
            logger.error(f"Error getting all vulnerabilities (unlimited): {e}")
            return []
    
    def get_paginated(self, page: int = 1, per_page: int = 50, 
                     status: Optional[str] = None, severity: Optional[str] = None, 
                     search: Optional[str] = None) -> Tuple[List[Vulnerability], int]:
        """Получить уязвимости с пагинацией и фильтрацией с кэшированием"""
        # Создаем ключ кэша на основе параметров
        cache_key = f"vuln:list:page:{page}:per_page:{per_page}"
        if status:
            cache_key += f":status:{status}"
        if severity:
            cache_key += f":severity:{severity}"
        if search:
            cache_key += f":search:{search}"
        
        # Проверяем кэш
        cached_result = self.db_manager.get_cached(cache_key)
        if cached_result and isinstance(cached_result, list) and len(cached_result) == 2:
            vulnerabilities_data, total_count = cached_result
            vulnerabilities = [Vulnerability.from_db_row(tuple(row)) for row in vulnerabilities_data]
            return vulnerabilities, total_count
        
        try:
            offset = (page - 1) * per_page
            
            # Базовый запрос
            base_query = """
                SELECT id, title, description, severity, status, assigned_operator, 
                       created_date, completed_date, approved, modifications, 
                       cvss_score, risk_level, category
                FROM vulnerabilities 
            """
            
            # Условия фильтрации
            conditions = []
            params = []
            
            if status and status != 'all':
                conditions.append("status = %s")
                params.append(status)
                
            if severity and severity != 'all':
                conditions.append("severity = %s")
                params.append(severity)
                
            if search:
                conditions.append("(title ILIKE %s OR description ILIKE %s)")
                params.extend([f'%{search}%', f'%{search}%'])
            
            # Добавляем WHERE если есть условия
            if conditions:
                base_query += " WHERE " + " AND ".join(conditions)
            
            # Добавляем ORDER BY и LIMIT/OFFSET
            base_query += " ORDER BY created_date DESC LIMIT %s OFFSET %s"
            params.extend([per_page, offset])
            
            # Запрос для данных
            rows = self.db_manager.execute_query(base_query, tuple(params))
            vulnerabilities = [Vulnerability.from_db_row(row) for row in rows]
            
            # Запрос для подсчета общего количества
            count_query = "SELECT COUNT(*) FROM vulnerabilities"
            count_params = []
            
            if conditions:
                count_query += " WHERE " + " AND ".join(conditions)
                count_params = params[:-2]  # Исключаем LIMIT и OFFSET
                
            count_result = self.db_manager.execute_query(count_query, tuple(count_params))
            total_count = count_result[0][0] if count_result else 0
            
            # Сохраняем в кэш на 2 минуты
            cache_data = ([list(row) for row in rows], total_count)
            self.db_manager.set_cached(cache_key, cache_data, 120)
            
            return vulnerabilities, total_count
                
        except Exception as e:
            logger.error(f"Error getting paginated vulnerabilities: {e}")
            return [], 0
    
    def get_statistics(self) -> dict:
        """Получить статистику по уязвимостям с кэшированием"""
        cache_key = "stats:vulnerabilities"
        cached_result = self.db_manager.get_cached(cache_key)
        if cached_result:
            return cached_result
        
        try:
            stats = {}
            
            # Общее количество
            result = self.db_manager.execute_query("SELECT COUNT(*) FROM vulnerabilities")
            stats['total'] = result[0][0] if result else 0
            
            # По статусам
            result = self.db_manager.execute_query("""
                SELECT status, COUNT(*) 
                FROM vulnerabilities 
                GROUP BY status
            """)
            stats['by_status'] = {row[0]: row[1] for row in result}
            
            # По уровням серьезности
            result = self.db_manager.execute_query("""
                SELECT severity, COUNT(*) 
                FROM vulnerabilities 
                GROUP BY severity
            """)
            stats['by_severity'] = {row[0]: row[1] for row in result}
            
            # Сохраняем в кэш на 5 минут
            self.db_manager.set_cached(cache_key, stats, 300)
            
            return stats
        except Exception as e:
            logger.error(f"Error getting vulnerability statistics: {e}")
            return {}
    
    def get_by_title(self, title: str) -> Optional[Vulnerability]:
        query = """
        SELECT id, title, description, severity, status, assigned_operator, 
               created_date, completed_date, approved, modifications, 
               cvss_score, risk_level, category
        FROM vulnerabilities 
        WHERE title = %s
        """
        try:
            result = self.db_manager.execute_query(query, (title,))
            if result:
                return Vulnerability.from_db_row(result[0])
            return None
        except Exception as e:
            logger.error(f"Error getting vulnerability by title '{title}': {e}")
            return None
    
    def get_by_status(self, status: str) -> List[Vulnerability]:
        query = """
        SELECT id, title, description, severity, status, assigned_operator, 
               created_date, completed_date, approved, modifications, 
               cvss_score, risk_level, category
        FROM vulnerabilities 
        WHERE status = %s
        ORDER BY created_date DESC
        """
        try:
            rows = self.db_manager.execute_query(query, (status,))
            return [Vulnerability.from_db_row(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting vulnerabilities by status '{status}': {e}")
            return []
    
    def get_by_severity(self, severity: str) -> List[Vulnerability]:
        query = """
        SELECT id, title, description, severity, status, assigned_operator, 
               created_date, completed_date, approved, modifications, 
               cvss_score, risk_level, category
        FROM vulnerabilities 
        WHERE severity = %s
        ORDER BY cvss_score DESC
        """
        try:
            rows = self.db_manager.execute_query(query, (severity,))
            return [Vulnerability.from_db_row(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting vulnerabilities by severity '{severity}': {e}")
            return []
    
    def assign_operator(self, vuln_id: int, operator_id: int) -> bool:
        query = "UPDATE vulnerabilities SET assigned_operator = %s WHERE id = %s"
        try:
            result = self.db_manager.execute_update(query, (operator_id, vuln_id))
            return result > 0
        except Exception as e:
            logger.error(f"Error assigning operator {operator_id} to vulnerability {vuln_id}: {e}")
            return False
    
    def unassign_operator(self, vuln_id: int) -> bool:
        query = "UPDATE vulnerabilities SET assigned_operator = NULL WHERE id = %s"
        try:
            result = self.db_manager.execute_update(query, (vuln_id,))
            return result > 0
        except Exception as e:
            logger.error(f"Error unassigning operator from vulnerability {vuln_id}: {e}")
            return False
    
    def update(self, vulnerability: Vulnerability) -> bool:
        query = """
        UPDATE vulnerabilities 
        SET title = %s, description = %s, severity = %s, status = %s, 
            assigned_operator = %s, created_date = %s, completed_date = %s, 
            approved = %s, modifications = %s, cvss_score = %s, 
            risk_level = %s, category = %s
        WHERE id = %s
        """
        try:
            params = (
                vulnerability.title,
                vulnerability.description,
                vulnerability.severity,
                vulnerability.status,
                vulnerability.assigned_operator,
                vulnerability.created_date,
                vulnerability.completed_date,
                vulnerability.approved,
                vulnerability.modifications,
                vulnerability.cvss_score,
                vulnerability.risk_level,
                vulnerability.category,
                vulnerability.id
            )
            result = self.db_manager.execute_update(query, params)
            return result > 0
        except Exception as e:
            logger.error(f"Error updating vulnerability {vulnerability.id}: {e}")
            return False
    
    def add(self, vulnerability: Vulnerability) -> bool:
        """Добавить уязвимость с инвалидацией кэша"""
        query = """
        INSERT INTO vulnerabilities 
        (title, description, severity, status, assigned_operator, created_date, 
         completed_date, approved, modifications, cvss_score, risk_level, category)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """
        try:
            params = (
                vulnerability.title,
                vulnerability.description,
                vulnerability.severity,
                vulnerability.status,
                vulnerability.assigned_operator,
                vulnerability.created_date,
                vulnerability.completed_date,
                vulnerability.approved,
                vulnerability.modifications,
                vulnerability.cvss_score,
                vulnerability.risk_level,
                vulnerability.category
            )
            
            result = self.db_manager.execute_query(query, params)
            if result:
                vulnerability.id = result[0][0]
                return True
            return False
        except Exception as e:
            logger.error(f"Error adding vulnerability: {e}")
            return False