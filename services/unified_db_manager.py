"""
Оптимизированный менеджер БД для работы с новой схемой
Поддерживает пакетные операции, кеширование и автоматическую оптимизацию
"""

import logging
import psycopg
from typing import List, Dict, Optional, Any
from datetime import datetime
from services.universal_adapter import UnifiedVulnerability
from config import Config

logger = logging.getLogger(__name__)


class UnifiedDBManager:
    """Менеджер для работы с унифицированной схемой БД"""
    
    def __init__(self):
        self.db_config = Config.DATABASE_CONFIG
        self.connection: Optional[psycopg.Connection] = None
        self._cache = {}
        self._connect()
    
    def _connect(self):
        """Установка соединения с БД"""
        try:
            self.connection = psycopg.connect(
                host=self.db_config.host,
                port=self.db_config.port,
                dbname=self.db_config.database,
                user=self.db_config.username,
                password=self.db_config.password
            )
            logger.info("Соединение с БД установлено")
        except Exception as e:
            logger.error(f"Ошибка подключения к БД: {e}")
            raise
    
    # ============================================
    # ВСТАВКА ДАННЫХ (BATCH OPERATIONS)
    # ============================================
    
    def insert_vulnerability_batch(self, vulnerabilities: List[UnifiedVulnerability]) -> int:
        """Пакетная вставка уязвимостей в таблицу turn"""
        if not vulnerabilities:
            return 0
        
        inserted_count = 0
        
        try:
            with self.connection.cursor() as cursor:
                # Подготавливаем данные для пакетной вставки
                insert_query = """
                    INSERT INTO turn (
                        source, link, cve, joining_date, name, cvss, 
                        price_one, priority, start_date, end_date, etc, status
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (cve) DO UPDATE SET
                        cvss = EXCLUDED.cvss,
                        price_one = EXCLUDED.price_one,
                        priority = EXCLUDED.priority,
                        etc = EXCLUDED.etc
                """
                
                # Собираем данные для вставки
                values = [
                    (
                        v.source, v.link, v.cve, v.joining_date, v.name,
                        v.cvss, v.price_one, v.priority, v.start_date,
                        v.end_date, v.etc, v.status
                    )
                    for v in vulnerabilities
                ]
                
                # Выполняем пакетную вставку
                cursor.executemany(insert_query, values)
                inserted_count = cursor.rowcount
                
                self.connection.commit()
                logger.info(f"✅ Вставлено/обновлено {inserted_count} уязвимостей в таблицу turn")
                
                # Дополнительно сохраняем связанные данные
                for vuln in vulnerabilities:
                    self._save_vulnerability_metadata(vuln)
                
                self.connection.commit()
            
            return inserted_count
            
        except Exception as e:
            self.connection.rollback()
            logger.error(f"❌ Ошибка пакетной вставки: {e}")
            return 0
    
    def _save_vulnerability_metadata(self, vuln: UnifiedVulnerability):
        """Сохранение метаданных уязвимости (CWE, теги, ПО)"""
        try:
            with self.connection.cursor() as cursor:
                # Сохраняем CWE
                if vuln.cwe_list:
                    for cwe in vuln.cwe_list:
                        cursor.execute("""
                            INSERT INTO map_table (cve, cwe)
                            VALUES (%s, %s)
                            ON CONFLICT (cve) DO UPDATE SET cwe = EXCLUDED.cwe
                        """, (vuln.cve, cwe))
                
                # Сохраняем теги
                if vuln.tags:
                    for tag in vuln.tags:
                        # Вставляем тег в таблицу tags
                        cursor.execute("""
                            INSERT INTO tags (tag, tagprice)
                            VALUES (%s, %s)
                            ON CONFLICT (tag) DO NOTHING
                        """, (tag, 10.0))  # Базовая цена тега
                        
                        # Связываем тег с CVE
                        cursor.execute("""
                            INSERT INTO tagcve (tag, cve)
                            VALUES (%s, %s)
                            ON CONFLICT (tag, cve) DO NOTHING
                        """, (tag, vuln.cve))
                
                # Сохраняем затронутое ПО
                if vuln.affected_software:
                    for software in vuln.affected_software[:10]:  # Ограничиваем 10
                        cursor.execute("""
                            INSERT INTO map_table_cve (cve, name_po)
                            VALUES (%s, %s)
                            ON CONFLICT (cve, name_po) DO NOTHING
                        """, (vuln.cve, software[:100]))
        
        except Exception as e:
            logger.error(f"Ошибка сохранения метаданных для {vuln.cve}: {e}")
    
    # ============================================
    # ЧТЕНИЕ ДАННЫХ
    # ============================================
    
    def get_all_vulnerabilities(self, limit: int = 100) -> List[Dict]:
        """Получение всех уязвимостей из таблицы turn"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT id, source, link, cve, joining_date, name, cvss, 
                           price_one, priority, start_date, end_date, etc, status
                    FROM turn
                    ORDER BY joining_date DESC
                    LIMIT %s
                """, (limit,))
                
                rows = cursor.fetchall()
                
                vulnerabilities = []
                for row in rows:
                    vulnerabilities.append({
                        'id': row[0],
                        'source': row[1],
                        'link': row[2],
                        'cve': row[3],
                        'joining_date': row[4],
                        'name': row[5],
                        'cvss': row[6],
                        'price_one': row[7],
                        'priority': row[8],
                        'start_date': row[9],
                        'end_date': row[10],
                        'etc': row[11],
                        'status': row[12]
                    })
                
                return vulnerabilities
                
        except Exception as e:
            logger.error(f"Ошибка получения уязвимостей: {e}")
            return []
    
    def get_vulnerability_by_cve(self, cve_id: str) -> Optional[Dict]:
        """Получение уязвимости по CVE ID"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT id, source, link, cve, joining_date, name, cvss, 
                           price_one, priority, start_date, end_date, etc, status
                    FROM turn
                    WHERE cve = %s
                """, (cve_id,))
                
                row = cursor.fetchone()
                if row:
                    return {
                        'id': row[0],
                        'source': row[1],
                        'link': row[2],
                        'cve': row[3],
                        'joining_date': row[4],
                        'name': row[5],
                        'cvss': row[6],
                        'price_one': row[7],
                        'priority': row[8],
                        'start_date': row[9],
                        'end_date': row[10],
                        'etc': row[11],
                        'status': row[12]
                    }
                return None
                
        except Exception as e:
            logger.error(f"Ошибка получения уязвимости {cve_id}: {e}")
            return None
    
    def get_vulnerabilities_by_source(self, source: str) -> List[Dict]:
        """Получение уязвимостей по источнику (NVD, OSV, RedHat)"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT id, source, link, cve, joining_date, name, cvss, 
                           price_one, priority, start_date, end_date, etc, status
                    FROM turn
                    WHERE source = %s
                    ORDER BY joining_date DESC
                """, (source,))
                
                rows = cursor.fetchall()
                
                vulnerabilities = []
                for row in rows:
                    vulnerabilities.append({
                        'id': row[0],
                        'source': row[1],
                        'link': row[2],
                        'cve': row[3],
                        'joining_date': row[4],
                        'name': row[5],
                        'cvss': row[6],
                        'price_one': row[7],
                        'priority': row[8],
                        'start_date': row[9],
                        'end_date': row[10],
                        'etc': row[11],
                        'status': row[12]
                    })
                
                return vulnerabilities
                
        except Exception as e:
            logger.error(f"Ошибка получения уязвимостей по источнику {source}: {e}")
            return []
    
    def get_ai_vulnerabilities(self) -> List[Dict]:
        """Получение AI-уязвимостей"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT DISTINCT t.id, t.source, t.link, t.cve, t.joining_date, 
                           t.name, t.cvss, t.price_one, t.priority, t.start_date, 
                           t.end_date, t.etc, t.status
                    FROM turn t
                    INNER JOIN tagcve tc ON t.cve = tc.cve
                    WHERE tc.tag IN ('ai', 'neural_network')
                    ORDER BY t.joining_date DESC
                """)
                
                rows = cursor.fetchall()
                
                vulnerabilities = []
                for row in rows:
                    vulnerabilities.append({
                        'id': row[0],
                        'source': row[1],
                        'link': row[2],
                        'cve': row[3],
                        'joining_date': row[4],
                        'name': row[5],
                        'cvss': row[6],
                        'price_one': row[7],
                        'priority': row[8],
                        'start_date': row[9],
                        'end_date': row[10],
                        'etc': row[11],
                        'status': row[12]
                    })
                
                return vulnerabilities
                
        except Exception as e:
            logger.error(f"Ошибка получения AI уязвимостей: {e}")
            return []
    
    # ============================================
    # УПРАВЛЕНИЕ ОПЕРАТОРАМИ
    # ============================================
    
    def insert_operator(self, operator_name: str, level: float = 50.0) -> bool:
        """Добавление оператора"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO operators (operator, level)
                    VALUES (%s, %s)
                    ON CONFLICT (operator) DO UPDATE SET level = EXCLUDED.level
                """, (operator_name, level))
                
                self.connection.commit()
                logger.info(f"✅ Оператор {operator_name} добавлен/обновлен")
                return True
                
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Ошибка добавления оператора: {e}")
            return False
    
    def assign_vulnerability_to_operator(self, cve_id: str, operator_name: str) -> bool:
        """Назначение уязвимости оператору"""
        try:
            with self.connection.cursor() as cursor:
                # Проверяем существование оператора
                cursor.execute("SELECT operator FROM operators WHERE operator = %s", (operator_name,))
                if not cursor.fetchone():
                    logger.warning(f"Оператор {operator_name} не найден")
                    return False
                
                # Назначаем уязвимость
                cursor.execute("""
                    INSERT INTO actids (cve, active, oper)
                    VALUES (%s, TRUE, %s)
                    ON CONFLICT (cve) DO UPDATE SET 
                        active = TRUE,
                        oper = EXCLUDED.oper
                """, (cve_id, operator_name))
                
                self.connection.commit()
                logger.info(f"✅ Уязвимость {cve_id} назначена оператору {operator_name}")
                return True
                
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Ошибка назначения уязвимости: {e}")
            return False
    
    def get_operator_assignments(self, operator_name: str) -> List[str]:
        """Получение списка CVE назначенных оператору"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT cve FROM actids 
                    WHERE oper = %s AND active = TRUE
                """, (operator_name,))
                
                return [row[0] for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Ошибка получения назначений: {e}")
            return []
    
    # ============================================
    # СТАТИСТИКА
    # ============================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """Получение общей статистики"""
        try:
            with self.connection.cursor() as cursor:
                stats = {}
                
                # Общее количество уязвимостей
                cursor.execute("SELECT COUNT(*) FROM turn")
                stats['total_vulnerabilities'] = cursor.fetchone()[0]
                
                # По источникам
                cursor.execute("SELECT source, COUNT(*) FROM turn GROUP BY source")
                stats['by_source'] = dict(cursor.fetchall())
                
                # По статусу
                cursor.execute("SELECT status, COUNT(*) FROM turn GROUP BY status")
                stats['by_status'] = dict(cursor.fetchall())
                
                # AI уязвимости
                cursor.execute("""
                    SELECT COUNT(DISTINCT t.cve) 
                    FROM turn t
                    INNER JOIN tagcve tc ON t.cve = tc.cve
                    WHERE tc.tag IN ('ai', 'neural_network')
                """)
                stats['ai_vulnerabilities'] = cursor.fetchone()[0]
                
                # Средний CVSS
                cursor.execute("SELECT AVG(cvss) FROM turn WHERE cvss > 0")
                avg_cvss = cursor.fetchone()[0]
                stats['avg_cvss'] = float(avg_cvss) if avg_cvss else 0.0
                
                # Количество операторов
                cursor.execute("SELECT COUNT(*) FROM operators")
                stats['total_operators'] = cursor.fetchone()[0]
                
                return stats
                
        except Exception as e:
            logger.error(f"Ошибка получения статистики: {e}")
            return {}
    
    # ============================================
    # ОЧИСТКА И ОПТИМИЗАЦИЯ
    # ============================================
    
    def cleanup_old_data(self, days: int = 365):
        """Очистка старых данных"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    DELETE FROM turn 
                    WHERE joining_date < NOW() - INTERVAL '%s days'
                    AND status = TRUE
                """, (days,))
                
                deleted_count = cursor.rowcount
                self.connection.commit()
                
                logger.info(f"🧹 Удалено {deleted_count} старых записей")
                return deleted_count
                
        except Exception as e:
            self.connection.rollback()
            logger.error(f"Ошибка очистки данных: {e}")
            return 0
    
    def optimize_database(self):
        """Оптимизация БД (VACUUM ANALYZE)"""
        try:
            # VACUUM нельзя выполнить в транзакции
            self.connection.autocommit = True
            
            with self.connection.cursor() as cursor:
                cursor.execute("VACUUM ANALYZE")
                logger.info("🚀 База данных оптимизирована")
            
            self.connection.autocommit = False
            
        except Exception as e:
            logger.error(f"Ошибка оптимизации БД: {e}")
    
    def close(self):
        """Закрытие соединения"""
        if self.connection:
            self.connection.close()
            logger.info("Соединение с БД закрыто")


# Глобальный экземпляр
unified_db_manager = UnifiedDBManager()
