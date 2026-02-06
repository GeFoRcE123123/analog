"""
Простой тест подключения к базе данных
"""

import psycopg
from config import Config


def test_connection():
    """Тестирование подключения к базе данных"""
    try:
        print("🔌 Тестирование подключения к PostgreSQL...")

        # Используем конфигурацию из config.py
        db_config = Config.DATABASE_CONFIG

        connection = psycopg.connect(
            host=db_config.host,
            port=db_config.port,
            dbname=db_config.database,
            user=db_config.username,
            password=db_config.password
        )

        print("✅ Подключение к PostgreSQL успешно!")

        # Проверяем таблицы
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
                ORDER BY table_name
            """)
            tables = cursor.fetchall()

            print(f"📋 Найдено таблиц: {len(tables)}")
            for table in tables:
                print(f"   - {table[0]}")

        # Проверяем данные
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM operators")
            operator_count = cursor.fetchone()[0]
            print(f"👥 Операторов в базе: {operator_count}")

            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            vuln_count = cursor.fetchone()[0]
            print(f"🐛 Уязвимостей в базе: {vuln_count}")

        connection.close()
        print("🎉 Все тесты пройдены успешно!")

    except Exception as e:
        print(f"❌ Ошибка: {e}")
        return False

    return True


if __name__ == "__main__":
    test_connection()