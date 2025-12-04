"""
Скрипт миграции данных из старой схемы БД в новую унифицированную схему
"""

import logging
import psycopg
from typing import Dict, Any
from config import Config
from services.universal_adapter import universal_adapter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DatabaseMigrator:
    """Миграция данных между схемами БД"""
    
    def __init__(self):
        self.db_config = Config.DATABASE_CONFIG
        self.connection = None
        self._connect()
    
    def _connect(self):
        """Подключение к БД"""
        try:
            self.connection = psycopg.connect(
                host=self.db_config.host,
                port=self.db_config.port,
                dbname=self.db_config.database,
                user=self.db_config.username,
                password=self.db_config.password
            )
            logger.info("✅ Подключение к БД установлено")
        except Exception as e:
            logger.error(f"❌ Ошибка подключения: {e}")
            raise
    
    def migrate_legacy_data(self) -> Dict[str, int]:
        """
        Миграция данных из старых таблиц (vulnerabilities, operators)
        в новые таблицы (turn, operators, actids, и т.д.)
        """
        stats = {
            'vulnerabilities_migrated': 0,
            'operators_migrated': 0,
            'errors': 0
        }
        
        logger.info("🚀 Начало миграции данных...")
        
        try:
            # Шаг 1: Проверяем наличие старых таблиц
            if not self._check_legacy_tables_exist():
                logger.warning("⚠️ Старые таблицы не найдены. Создаем их для копирования существующих данных...")
                self._backup_current_data()
            
            # Шаг 2: Мигрируем операторов
            logger.info("👤 Миграция операторов...")
            stats['operators_migrated'] = self._migrate_operators()
            
            # Шаг 3: Мигрируем уязвимости
            logger.info("🔒 Миграция уязвимостей...")
            stats['vulnerabilities_migrated'] = self._migrate_vulnerabilities()
            
            logger.info(f"""
            ═══════════════════════════════════════════════
            РЕЗУЛЬТАТЫ МИГРАЦИИ
            ═══════════════════════════════════════════════
            Операторы: {stats['operators_migrated']}
            Уязвимости: {stats['vulnerabilities_migrated']}
            Ошибки: {stats['errors']}
            ═══════════════════════════════════════════════
            """)
            
            return stats
            
        except Exception as e:
            logger.error(f"❌ Критическая ошибка миграции: {e}")
            stats['errors'] += 1
            return stats
    
    def _check_legacy_tables_exist(self) -> bool:
        """Проверка существования старых таблиц"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT 1 FROM information_schema.tables 
                        WHERE table_name = 'vulnerabilities'
                    )
                """)
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Ошибка проверки таблиц: {e}")
            return False
    
    def _backup_current_data(self):
        """Резервное копирование текущих данных в legacy таблицы"""
        try:
            with self.connection.cursor() as cursor:
                # Копируем существующие vulnerabilities в legacy
                logger.info("💾 Копирование vulnerabilities -> legacy_vulnerabilities...")
                cursor.execute("""
                    INSERT INTO legacy_vulnerabilities 
                    SELECT * FROM vulnerabilities
                    ON CONFLICT DO NOTHING
                """)
                
                # Копируем operators
                logger.info("💾 Копирование operators -> legacy_operators...")
                cursor.execute("""
                    INSERT INTO legacy_operators 
                    SELECT * FROM operators
                    ON CONFLICT DO NOTHING
                """)
                
                self.connection.commit()
                logger.info("✅ Данные скопированы в legacy таблицы")
                
        except Exception as e:
            self.connection.rollback()
            logger.error(f"❌ Ошибка резервного копирования: {e}")
    
    def _migrate_operators(self) -> int:
        """Миграция операторов из legacy_operators в operators"""
        try:
            with self.connection.cursor() as cursor:
                # Читаем старых операторов
                cursor.execute("""
                    SELECT name, current_metric FROM legacy_operators
                """)
                
                old_operators = cursor.fetchall()
                migrated = 0
                
                for name, level in old_operators:
                    try:
                        # Вставляем в новую таблицу operators
                        cursor.execute("""
                            INSERT INTO operators (operator, level)
                            VALUES (%s, %s)
                            ON CONFLICT (operator) DO UPDATE SET level = EXCLUDED.level
                        """, (name, level or 50.0))
                        
                        migrated += 1
                        
                    except Exception as e:
                        logger.error(f"Ошибка миграции оператора {name}: {e}")
                
                self.connection.commit()
                logger.info(f"✅ Мигрировано {migrated} операторов")
                return migrated
                
        except Exception as e:
            self.connection.rollback()
            logger.error(f"❌ Ошибка миграции операторов: {e}")
            return 0
    
    def _migrate_vulnerabilities(self) -> int:
        """Миграция уязвимостей из legacy_vulnerabilities в turn"""
        try:
            with self.connection.cursor() as cursor:
                # Читаем старые уязвимости
                cursor.execute("""
                    SELECT 
                        cve_id, title, description, cvss_score, created_date,
                        source_identifier, published, status
                    FROM legacy_vulnerabilities
                    WHERE cve_id IS NOT NULL
                """)
                
                old_vulns = cursor.fetchall()
                migrated = 0
                
                for row in old_vulns:
                    try:
                        cve_id, title, description, cvss, created, source, published, status = row
                        
                        # Определяем источник
                        if source and 'nvd' in source.lower():
                            source_name = 'NVD'
                        elif source and 'redhat' in source.lower():
                            source_name = 'RedHat'
                        else:
                            source_name = 'Legacy'
                        
                        # Рассчитываем цену и приоритет
                        cvss_float = float(cvss) if cvss else 5.0
                        price_one = cvss_float * 10
                        priority = min(cvss_float * 10, 100)
                        
                        # Вставляем в новую таблицу turn
                        cursor.execute("""
                            INSERT INTO turn (
                                source, link, cve, joining_date, name, cvss, 
                                price_one, priority, start_date, status
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON CONFLICT (cve) DO UPDATE SET
                                cvss = EXCLUDED.cvss,
                                price_one = EXCLUDED.price_one,
                                priority = EXCLUDED.priority
                        """, (
                            source_name,
                            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            cve_id,
                            created,
                            title or cve_id,
                            cvss_float,
                            price_one,
                            priority,
                            published,
                            status == 'completed' if status else False
                        ))
                        
                        migrated += 1
                        
                    except Exception as e:
                        logger.error(f"Ошибка миграции уязвимости: {e}")
                
                self.connection.commit()
                logger.info(f"✅ Мигрировано {migrated} уязвимостей")
                return migrated
                
        except Exception as e:
            self.connection.rollback()
            logger.error(f"❌ Ошибка миграции уязвимостей: {e}")
            return 0
    
    def cleanup_legacy_tables(self):
        """Очистка старых таблиц после успешной миграции"""
        try:
            with self.connection.cursor() as cursor:
                logger.warning("⚠️ Удаление данных из legacy таблиц...")
                cursor.execute("TRUNCATE TABLE legacy_vulnerabilities CASCADE")
                cursor.execute("TRUNCATE TABLE legacy_operators CASCADE")
                
                self.connection.commit()
                logger.info("✅ Legacy таблицы очищены")
                
        except Exception as e:
            self.connection.rollback()
            logger.error(f"❌ Ошибка очистки legacy таблиц: {e}")
    
    def close(self):
        """Закрытие соединения"""
        if self.connection:
            self.connection.close()


def main():
    """Основная функция миграции"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║     МИГРАЦИЯ БД VULNERABILITY MANAGER                     ║
    ║     Старая схема -> Новая унифицированная схема           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    migrator = DatabaseMigrator()
    
    try:
        # Выполняем миграцию
        stats = migrator.migrate_legacy_data()
        
        print(f"""
        ═══════════════════════════════════════════════
        ✅ МИГРАЦИЯ ЗАВЕРШЕНА
        ═══════════════════════════════════════════════
        Операторы: {stats['operators_migrated']}
        Уязвимости: {stats['vulnerabilities_migrated']}
        Ошибки: {stats['errors']}
        ═══════════════════════════════════════════════
        """)
        
        # Спрашиваем об очистке legacy таблиц
        response = input("\nОчистить legacy таблицы? (y/n): ")
        if response.lower() == 'y':
            migrator.cleanup_legacy_tables()
        
    except Exception as e:
        logger.error(f"Критическая ошибка: {e}")
        return 1
    finally:
        migrator.close()
    
    return 0


if __name__ == "__main__":
    exit(main())
