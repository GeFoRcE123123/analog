import psycopg
from config import Config
from models.repository_factory import repository_factory


class DatabaseManager:
    """Менеджер базы данных для миграций и управления схемой"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
            cls._instance._init_db()
        return cls._instance

    def _init_db(self):
        """Инициализация соединения с БД"""
        self.db_config = Config.DATABASE_CONFIG
        self.connection = None
        self._connect()

    def _connect(self):
        """Установить соединение с БД"""
        try:
            if self.db_config.type == "postgresql":
                self.connection = psycopg.connect(
                    host=self.db_config.host,
                    port=self.db_config.port,
                    dbname=self.db_config.database,
                    user=self.db_config.username,
                    password=self.db_config.password
                )
                # ВАЖНО: Отключаем autocommit для ручного управления транзакциями
                self.connection.autocommit = False
            else:
                raise ValueError(f"Unsupported database type: {self.db_config.type}")
        except Exception as e:
            print(f"Database connection error: {e}")
            raise

    def execute_query(self, query, params=None):
        """Выполнить SQL запрос"""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(query, params)
                if query.strip().upper().startswith('SELECT'):
                    return cursor.fetchall()
                self.connection.commit()
                return cursor.rowcount
        except Exception as e:
            self.connection.rollback()
            raise e

    # models/database.py → метод create_tables()

    def create_tables(self):
        try:
            # Таблица пользователей
            users_table = """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) CHECK (role IN ('admin', 'user')) DEFAULT 'user',
                full_name VARCHAR(100),
                department VARCHAR(100),
                is_active BOOLEAN DEFAULT TRUE,
                is_locked BOOLEAN DEFAULT FALSE,
                locked_until TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0,
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """

            # Таблица назначений
            assignments_table = """
            CREATE TABLE IF NOT EXISTS user_vulnerability_assignments (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                vulnerability_id INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
                assigned_by INTEGER REFERENCES users(id),
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(20) CHECK (status IN ('pending', 'in_progress', 'completed', 'rejected')) DEFAULT 'pending',
                due_date TIMESTAMP,
                completed_at TIMESTAMP,
                notes TEXT
            );
            """

            # Таблица аудита входа
            login_attempts_table = """
            CREATE TABLE IF NOT EXISTS login_attempts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                ip_address INET,
                user_agent TEXT,
                success BOOLEAN,
                attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """

            # Сгенерированные пароли (для админа при добавлении/редактировании пользователя)
            user_generated_passwords_table = """
            CREATE TABLE IF NOT EXISTS user_generated_passwords (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                plain_password VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """

            # И уже существующие таблицы
            operators = """
            CREATE TABLE IF NOT EXISTS operators (
                id SERIAL PRIMARY KEY,
                name VARCHAR(200) NOT NULL,
                email VARCHAR(200) UNIQUE NOT NULL,
                experience_level DECIMAL(5,2) DEFAULT 50.0,
                current_metric DECIMAL(5,2) DEFAULT 50.0,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """

            vulnerabilities = """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id SERIAL PRIMARY KEY,
                title VARCHAR(500) NOT NULL,
                description TEXT,
                severity VARCHAR(50),
                status VARCHAR(50) DEFAULT 'new',
                assigned_operator INTEGER REFERENCES operators(id) ON DELETE SET NULL,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_date TIMESTAMP,
                approved BOOLEAN DEFAULT FALSE,
                modifications INTEGER DEFAULT 0,
                cvss_score DECIMAL(3,1) DEFAULT 0.0,
                risk_level VARCHAR(50) DEFAULT 'medium',
                category VARCHAR(100) DEFAULT 'web'
            );
            """

            # Выполняем в правильном порядке
            self.execute_query(users_table)
            self.execute_query(operators)
            self.execute_query(vulnerabilities)
            self.execute_query(assignments_table)
            self.execute_query(login_attempts_table)
            self.execute_query(user_generated_passwords_table)

            # Индексы
            self.execute_query("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            self.execute_query("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)")
            self.execute_query(
                "CREATE INDEX IF NOT EXISTS idx_assignments_user ON user_vulnerability_assignments(user_id)")
            self.execute_query(
                "CREATE INDEX IF NOT EXISTS idx_assignments_vuln ON user_vulnerability_assignments(vulnerability_id)")
            self.execute_query("CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(user_id)")
            self.execute_query("CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON login_attempts(attempted_at)")
            self.execute_query("CREATE UNIQUE INDEX IF NOT EXISTS idx_user_generated_passwords_user_id ON user_generated_passwords(user_id)")

            print("✅ Все таблицы авторизации успешно созданы")
        except Exception as e:
            print(f"❌ Ошибка создания таблиц: {e}")
            raise

    def seed_initial_data(self):
        """Заполнить начальными данными"""
        try:
            # Проверяем, есть ли уже операторы
            check_operators = "SELECT COUNT(*) FROM operators"
            result = self.execute_query(check_operators)

            if result[0][0] == 0:
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
                    self.execute_query(insert_operator, operator)

                print("Initial operators data seeded")

            # Проверяем, есть ли уже уязвимости
            check_vulnerabilities = "SELECT COUNT(*) FROM vulnerabilities"
            result = self.execute_query(check_vulnerabilities)

            if result[0][0] == 0:
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
                    self.execute_query(insert_vulnerability, vuln)

                print("Initial vulnerabilities data seeded")

        except Exception as e:
            print(f"Error seeding initial data: {e}")
            raise

    def close(self):
        """Закрыть соединение с БД"""
        if self.connection:
            self.connection.close()

    def __del__(self):
        """Деструктор для автоматического закрытия соединения"""
        self.close()

    def get_db_connection():
        """Получить подключение к БД (для обратной совместимости)"""
        db_manager = DatabaseManager()
        return db_manager.connection

    def get_db_connection_new():
        """Создать новое подключение к БД"""
        db_config = Config.DATABASE_CONFIG
        try:
            if db_config.type == "postgresql":
                connection = psycopg.connect(
                    host=db_config.host,
                    port=db_config.port,
                    dbname=db_config.database,
                    user=db_config.username,
                    password=db_config.password
                )
                return connection
            else:
                raise ValueError(f"Unsupported database type: {db_config.type}")
        except Exception as e:
            print(f"Database connection error: {e}")
            raise


# Для обратной совместимости
class Database(DatabaseManager):
    """Класс-обертка для обратной совместимости со старым кодом"""
    pass