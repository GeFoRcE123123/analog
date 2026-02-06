#!/usr/bin/env python3
"""
Скрипт для инициализации базы данных Vulnerability Management System
"""

import sys
import os
import psycopg
from datetime import datetime

# Добавляем путь к проекту для импорта конфигурации
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config import Config


def create_tables(connection):
    """Создать таблицы в базе данных"""
    try:
        with connection.cursor() as cursor:
            print("📊 Создание таблиц...")

            # Таблица операторов
            operators_table = """
            CREATE TABLE IF NOT EXISTS operators (
                id SERIAL PRIMARY KEY,
                name VARCHAR(200) NOT NULL,
                email VARCHAR(200) UNIQUE NOT NULL,
                experience_level DECIMAL(5,2) DEFAULT 50.0,
                current_metric DECIMAL(5,2) DEFAULT 50.0,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
            cursor.execute(operators_table)
            print("✅ Таблица 'operators' создана")

            # Таблица уязвимостей с NVD полями - сначала БЕЗ внешнего ключа
            vulnerabilities_table = """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id SERIAL PRIMARY KEY,
                title VARCHAR(500) NOT NULL,
                description TEXT,
                severity VARCHAR(50),
                status VARCHAR(50) DEFAULT 'new',
                assigned_operator INTEGER,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_date TIMESTAMP,
                approved BOOLEAN DEFAULT FALSE,
                modifications INTEGER DEFAULT 0,
                cvss_score DECIMAL(3,1) DEFAULT 0.0,
                risk_level VARCHAR(50) DEFAULT 'medium',
                category VARCHAR(100) DEFAULT 'web',

                -- NVD поля --
                cve_id VARCHAR(50) UNIQUE,
                source_identifier VARCHAR(100),
                published TIMESTAMP,
                last_modified TIMESTAMP,
                vuln_status VARCHAR(50),
                descriptions JSONB,
                metrics JSONB,
                weaknesses JSONB,
                configurations JSONB,
                "references" JSONB,
                vendor_comments JSONB,
                is_ai_related BOOLEAN DEFAULT FALSE,
                ai_confidence DECIMAL(3,2) DEFAULT 0.0,
                has_kev BOOLEAN DEFAULT FALSE,
                has_cert_alerts BOOLEAN DEFAULT FALSE
            )
            """
            cursor.execute(vulnerabilities_table)
            print("✅ Таблица 'vulnerabilities' создана с NVD полями")

            # Теперь добавляем внешний ключ для assigned_operator
            fk_operator = """
            ALTER TABLE vulnerabilities 
            ADD CONSTRAINT fk_vulnerabilities_operator 
            FOREIGN KEY (assigned_operator) REFERENCES operators(id) ON DELETE SET NULL
            """
            cursor.execute(fk_operator)
            print("✅ Внешний ключ для операторов добавлен")

            # Таблица AI уязвимостей - БЕЗ внешнего ключа сначала
            ai_vulnerabilities_table = """
            CREATE TABLE IF NOT EXISTS ai_vulnerabilities (
                id SERIAL PRIMARY KEY,
                cve_id VARCHAR(50),
                ai_confidence DECIMAL(3,2) DEFAULT 0.0,
                ai_keywords_found JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
            cursor.execute(ai_vulnerabilities_table)
            print("✅ Таблица 'ai_vulnerabilities' создана")

            connection.commit()

            # Теперь добавляем внешний ключ для AI уязвимостей
            print("🔗 Добавление внешних ключей...")

            # Сначала проверяем, существует ли колонка cve_id в таблице vulnerabilities
            cursor.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'vulnerabilities' AND column_name = 'cve_id'
            """)
            cve_id_exists = cursor.fetchone()

            if cve_id_exists:
                print("✅ Колонка cve_id найдена в таблице vulnerabilities")

                # Добавляем внешний ключ
                add_foreign_key = """
                ALTER TABLE ai_vulnerabilities 
                ADD CONSTRAINT fk_ai_vulnerabilities_cve 
                FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id)
                """
                cursor.execute(add_foreign_key)
                print("✅ Внешний ключ для ai_vulnerabilities добавлен")
            else:
                print("❌ Колонка cve_id не найдена в таблице vulnerabilities")
                # Создаем колонку если она не существует
                add_cve_id_column = """
                ALTER TABLE vulnerabilities 
                ADD COLUMN cve_id VARCHAR(50) UNIQUE
                """
                cursor.execute(add_cve_id_column)
                print("✅ Колонка cve_id добавлена в таблицу vulnerabilities")

                # Теперь добавляем внешний ключ
                add_foreign_key = """
                ALTER TABLE ai_vulnerabilities 
                ADD CONSTRAINT fk_ai_vulnerabilities_cve 
                FOREIGN KEY (cve_id) REFERENCES vulnerabilities(cve_id)
                """
                cursor.execute(add_foreign_key)
                print("✅ Внешний ключ для ai_vulnerabilities добавлен")

            connection.commit()

    except Exception as e:
        connection.rollback()
        raise e


def seed_initial_data(connection):
    """Заполнить базу начальными данными"""
    try:
        with connection.cursor() as cursor:
            print("📝 Заполнение начальными данными...")

            # Проверяем, есть ли уже операторы
            cursor.execute("SELECT COUNT(*) FROM operators")
            operator_count = cursor.fetchone()[0]

            if operator_count == 0:
                # Добавляем тестовых операторов
                operators = [
                    ("Иван Петров", "ivan@company.com", 50.0, 65.0),
                    ("Мария Сидорова", "maria@company.com", 50.0, 45.0),
                    ("Алексей Козлов", "alexey@company.com", 50.0, 50.0),
                    ("Елена Новикова", "elena@company.com", 50.0, 70.0)
                ]

                insert_operator = """
                INSERT INTO operators (name, email, experience_level, current_metric)
                VALUES (%s, %s, %s, %s)
                """

                for operator in operators:
                    cursor.execute(insert_operator, operator)

                print("✅ Тестовые операторы добавлены")

            # Проверяем, есть ли уже уязвимости
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            vuln_count = cursor.fetchone()[0]

            if vuln_count == 0:
                # Добавляем тестовые уязвимости
                vulnerabilities = [
                    ("SQL Injection", "Возможность SQL инъекции в форме логина пользователя", "high", 9.8, "critical",
                     "web"),
                    ("XSS Vulnerability", "Межсайтовый скриптинг в комментариях", "medium", 6.1, "medium", "web"),
                    ("Weak Password Policy", "Слабые требования к паролям пользователей", "low", 3.7, "low",
                     "authentication"),
                    ("Information Disclosure", "Раскрытие системной информации в ошибках", "medium", 5.3, "medium",
                     "information"),
                    ("CSRF Protection Missing", "Отсутствует защита от CSRF атак", "high", 8.8, "high", "web")
                ]

                insert_vulnerability = """
                INSERT INTO vulnerabilities (title, description, severity, cvss_score, risk_level, category)
                VALUES (%s, %s, %s, %s, %s, %s)
                """

                for vuln in vulnerabilities:
                    cursor.execute(insert_vulnerability, vuln)

                print("✅ Тестовые уязвимости добавлены")

            connection.commit()

    except Exception as e:
        connection.rollback()
        raise e


def test_connection():
    """Протестировать подключение к базе данных"""
    try:
        print("🔌 Тестирование подключения к базе данных...")

        # Используем конфигурацию из config.py
        db_config = Config.DATABASE_CONFIG

        connection = psycopg.connect(
            host=db_config.host,
            port=db_config.port,
            dbname=db_config.database,
            user=db_config.username,
            password=db_config.password
        )

        print("✅ Подключение к базе данных успешно")

        # Проверяем существование таблиц
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
            """)
            tables = cursor.fetchall()
            print(f"📋 Найдено таблиц: {len(tables)}")

        connection.close()
        return True

    except Exception as e:
        print(f"❌ Ошибка подключения к базе данных: {e}")
        return False


def main():
    """Основная функция инициализации"""
    print("🔧 Инициализация базы данных Vulnerability Management System...")
    print("=" * 60)

    try:
        # Тестируем подключение
        if not test_connection():
            sys.exit(1)

        # Подключаемся к базе данных
        db_config = Config.DATABASE_CONFIG
        connection = psycopg.connect(
            host=db_config.host,
            port=db_config.port,
            dbname=db_config.database,
            user=db_config.username,
            password=db_config.password
        )
        connection.autocommit = False

        # Создаем таблицы
        create_tables(connection)

        # Заполняем начальными данными
        seed_initial_data(connection)

        # Закрываем соединение
        connection.close()

        print("=" * 60)
        print("🎉 Инициализация базы данных завершена успешно!")
        print("📊 База данных готова к использованию")

    except Exception as e:
        print(f"❌ Ошибка при инициализации базы данных: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()