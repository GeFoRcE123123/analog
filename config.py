import os
from dataclasses import dataclass
from typing import Dict, Any


@dataclass
class DatabaseConfig:
    """Конфигурация базы данных"""
    type: str = "postgresql"
    host: str = "localhost"
    port: int = 5432
    database: str = "vulnerability_db"
    username: str = "vuln_user"
    password: str = "password123"

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

    # Для обратной совместимости
    DATABASE_URI = DATABASE_CONFIG.connection_string

    # Parser settings
    BASE_URL = "https://osv.dev/list"
    MAX_PAGES = 5
    REQUEST_TIMEOUT = 30

    # Logging
    LOG_LEVEL = "INFO"

    # Application
    SECRET_KEY = "dev-secret-key"

    # Keywords for filtering
    KEYWORDS = {
        "7-Zip": 99, "Adobe": 80, "Debian": 99, "Docker": 99, "Drupal": 76,
        "MySQL": 52, "Nginx": 99, "NodeJS": 99, "Oracle": 59, "Linux": 51,
        "Microsoft": 99, "PHP": 68, "PostgreSQL": 99, "Redis": 99, "Ubuntu": 99,
        "Windows": 99, "Apache": 99, "Cisco": 99, "VMware": 99
    }