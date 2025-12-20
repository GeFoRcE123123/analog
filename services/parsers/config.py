"""
Конфигурация для Parsers сервиса (10.0.88.23)
"""
from dataclasses import dataclass


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

    # Backend API URL (для отправки статусов)
    BACKEND_URL = "http://10.0.88.20:5000"

    # Parser settings
    BASE_URL = "https://osv.dev/list"
    MAX_PAGES = 5
    REQUEST_TIMEOUT = 30

    # Logging
    LOG_LEVEL = "INFO"

    # Database schema mode
    USE_LEGACY_SCHEMA = True

    # Keywords for filtering
    KEYWORDS = {
        "7-Zip": 99, "Adobe": 80, "Debian": 99, "Docker": 99, "Drupal": 76,
        "MySQL": 52, "Nginx": 99, "NodeJS": 99, "Oracle": 59, "Linux": 51,
        "Microsoft": 99, "PHP": 68, "PostgreSQL": 99, "Redis": 99, "Ubuntu": 99,
        "Windows": 99, "Apache": 99, "Cisco": 99, "VMware": 99
    }

