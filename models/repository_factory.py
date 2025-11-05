import psycopg
import logging
from config import Config
from models.postgres_repositories import PostgresVulnerabilityRepository, PostgresOperatorRepository

logger = logging.getLogger(__name__)


class RepositoryFactory:
    """Фабрика для создания репозиториев PostgreSQL"""

    def __init__(self):
        self.db_config = Config.DATABASE_CONFIG
        self._connection = None
        logger.info("RepositoryFactory initialized with PostgreSQL")

    def _get_connection(self):
        """Получить соединение с БД"""
        if self._connection is None or self._connection.closed:
            try:
                self._connection = psycopg.connect(
                    host=self.db_config.host,
                    port=self.db_config.port,
                    dbname=self.db_config.database,
                    user=self.db_config.username,
                    password=self.db_config.password
                )
                logger.info("Database connection established")
            except Exception as e:
                logger.error(f"Failed to connect to database: {e}")
                raise

        return self._connection

    def create_vulnerability_repository(self):
        """Создать репозиторий уязвимостей"""
        return PostgresVulnerabilityRepository(self._get_connection())

    def create_operator_repository(self):
        """Создать репозиторий операторов"""
        return PostgresOperatorRepository(self._get_connection())

    def close_connection(self):
        """Закрыть соединение с БД"""
        if self._connection and not self._connection.closed:
            self._connection.close()
            self._connection = None
            logger.info("Database connection closed")


# Глобальный экземпляр фабрики
repository_factory = RepositoryFactory()