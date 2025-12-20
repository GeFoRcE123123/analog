"""
Конфигурация для Backend сервиса (10.0.88.20)
"""
from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class DatabaseConfig:
    """Конфигурация базы данных"""
    type: str = "postgresql"
    host: str = "10.0.88.11"  # Database VM
    port: int = 5432
    database: str = "vuln_db"
    username: str = "admin"
    password: str = "123"

    @property
    def connection_string(self) -> str:
        """Генерация строки подключения"""
        if self.type == "postgresql":
            return f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
        else:
            raise ValueError(f"Unsupported database type: {self.type}")


class Config:
    # Database configuration
    DATABASE_CONFIG = DatabaseConfig()
    DATABASE_URI = DATABASE_CONFIG.connection_string

    # Backend API settings
    BACKEND_HOST = "0.0.0.0"  # Слушать на всех интерфейсах
    BACKEND_PORT = 5000
    BACKEND_URL = f"http://10.0.88.20:{BACKEND_PORT}"

    # Frontend URL (для CORS)
    FRONTEND_URL = "http://10.0.88.10"

    # Logging
    LOG_LEVEL = "INFO"

    # Application
    SECRET_KEY = "dev-secret-key-change-in-production"

    # Database schema mode
    USE_LEGACY_SCHEMA = True

