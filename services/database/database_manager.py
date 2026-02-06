import logging
import psycopg
from typing import Optional, Any, List, Dict
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Централизованный менеджер для работы с базой данных"""

    _instance = None
    _connection = None
    _config = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, '_initialized'):
            self._initialized = True
            self._connection = None
            self._config = None

    def configure(self, host: str, port: int, database: str, username: str, password: str):
        """Конфигурация подключения к БД"""
        self._config = {
            'host': host,
            'port': port,
            'dbname': database,
            'user': username,
            'password': password
        }
        logger.info(f"Database configured for {host}:{port}/{database}")

    def connect(self) -> bool:
        """Установка подключения к БД"""
        if self._config is None:
            logger.error("Database configuration not set")
            return False

        try:
            self._connection = psycopg.connect(**self._config)
            self._connection.autocommit = False
            logger.info("Database connection established successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            self._connection = None
            return False

    def disconnect(self):
        """Закрытие подключения к БД"""
        if self._connection and not self._connection.closed:
            self._connection.close()
            self._connection = None
            logger.info("Database connection closed")

    def is_connected(self) -> bool:
        """Проверка активности подключения"""
        return self._connection is not None and not self._connection.closed

    def reconnect(self) -> bool:
        """Переподключение к БД"""
        self.disconnect()
        return self.connect()

    @contextmanager
    def get_cursor(self):
        """Контекстный менеджер для получения курсора"""
        if not self.is_connected():
            if not self.reconnect():
                raise ConnectionError("No active database connection")

        cursor = None
        try:
            cursor = self._connection.cursor()
            yield cursor
            self._connection.commit()
        except Exception as e:
            if self._connection:
                self._connection.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if cursor:
                cursor.close()

    def execute_query(self, query: str, params: tuple = None) -> List[tuple]:
        """Выполнение SELECT запроса"""
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            return cursor.fetchall()

    def execute_command(self, command: str, params: tuple = None) -> int:
        """Выполнение INSERT/UPDATE/DELETE команды"""
        with self.get_cursor() as cursor:
            cursor.execute(command, params)
            return cursor.rowcount

    def execute_scalar(self, query: str, params: tuple = None) -> Any:
        """Выполнение запроса и возврат скалярного значения"""
        with self.get_cursor() as cursor:
            cursor.execute(query, params)
            result = cursor.fetchone()
            return result[0] if result else None

    def test_connection(self) -> bool:
        """Тестирование подключения к БД"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute("SELECT 1")
                return True
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False

    def get_connection_info(self) -> Dict[str, Any]:
        """Получение информации о подключении"""
        if not self._config:
            return {}

        return {
            'host': self._config['host'],
            'port': self._config['port'],
            'database': self._config.get('dbname'),
            'user': self._config['user'],
            'connected': self.is_connected()
        }


# Глобальный экземпляр менеджера БД
db_manager = DatabaseManager()