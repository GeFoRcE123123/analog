import os
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

    # Для обратной совместимости
    DATABASE_URI = DATABASE_CONFIG.connection_string

    # Backend API settings
    BACKEND_HOST = "0.0.0.0"  # Слушать на всех интерфейсах
    BACKEND_PORT = 5000
    BACKEND_URL = f"http://10.0.88.20:{BACKEND_PORT}"

    # Frontend URL (для CORS)
    FRONTEND_URL = "http://10.0.88.10"

    # Parser settings
    BASE_URL = "https://osv.dev/list"
    MAX_PAGES = 5
    REQUEST_TIMEOUT = 30

    # Logging
    LOG_LEVEL = "INFO"

    # Application
    SECRET_KEY = "dev-secret-key-change-in-production"

    # Keywords for filtering
    KEYWORDS = {
        "7-Zip": 99, "Adobe": 80, "Debian": 99, "Docker": 99, "Drupal": 76,
        "MySQL": 52, "Nginx": 99, "NodeJS": 99, "Oracle": 59, "Linux": 51,
        "Microsoft": 99, "PHP": 68, "PostgreSQL": 99, "Redis": 99, "Ubuntu": 99,
        "Windows": 99, "Apache": 99, "Cisco": 99, "VMware": 99
    }

    # Database schema mode: 'legacy' (turn, cvelist, etc) or 'modern' (vulnerabilities, operators)
    USE_LEGACY_SCHEMA = True
    
    # NVD API Configuration
    # Получить API ключ: https://nvd.nist.gov/developers/request-an-api-key
    # Активировать: https://nvd.nist.gov/developers/confirm-api-key
    # Активированный ключ: 6e96c1b9-a283-4ce3-b83e-bb162d9b4323
    NVD_API_KEY = os.getenv("NVD_API_KEY", "6e96c1b9-a283-4ce3-b83e-bb162d9b4323")
    
    # Настройки для полной синхронизации (максимальная скорость)
    NVD_FULL_SYNC_REQUESTS_PER_SECOND = 50 if NVD_API_KEY else 5  # Максимум с API ключом
    NVD_FULL_SYNC_MAX_WORKERS = 20  # Больше потоков для полной синхронизации
    
    # Настройки для инкрементальной синхронизации (экономный режим)
    NVD_INCREMENTAL_REQUESTS_PER_SECOND = 50 if NVD_API_KEY else 5
    NVD_INCREMENTAL_MAX_WORKERS = 10  # Меньше потоков для инкрементальной
    
    # По умолчанию (для обратной совместимости)
    NVD_REQUESTS_PER_SECOND = NVD_FULL_SYNC_REQUESTS_PER_SECOND
    NVD_MAX_WORKERS = NVD_FULL_SYNC_MAX_WORKERS