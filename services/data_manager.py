import logging
from models.entities import Operator, Vulnerability
from typing import List, Optional
from services.vulnerability_service import VulnerabilityService
from services.operator_service import OperatorService

logger = logging.getLogger(__name__)


class DataManager:
    """
    Менеджер данных для работы с PostgreSQL.
    Теперь это фасад над сервисами, а не in-memory хранилище.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DataManager, cls).__new__(cls)
            cls._instance._init_services()
        return cls._instance

    def _init_services(self):
        """Инициализация сервисов"""
        self.vulnerability_service = VulnerabilityService()
        self.operator_service = OperatorService()
        logger.info("DataManager initialized with PostgreSQL services")

    def get_operators(self) -> List[Operator]:
        """Получить всех операторов"""
        return self.operator_service.get_all_operators()

    def get_vulnerabilities(self) -> List[Vulnerability]:
        """Получить все уязвимости"""
        return self.vulnerability_service.get_all_vulnerabilities()

    def get_operator_by_id(self, operator_id: int) -> Optional[Operator]:
        """Получить оператора по ID"""
        return self.operator_service.get_operator_by_id(operator_id)

    def get_vulnerability_by_id(self, vuln_id: int) -> Optional[Vulnerability]:
        """Получить уязвимость по ID"""
        return self.vulnerability_service.get_vulnerability_by_id(vuln_id)

    def update_operator(self, operator: Operator):
        """Обновить оператора в БД"""
        self.operator_service.operator_repo.update(operator)

    def update_vulnerability(self, vulnerability: Vulnerability):
        """Обновить уязвимость в БД"""
        self.vulnerability_service.vulnerability_repo.update(vulnerability)

    def add_vulnerability(self, vulnerability: Vulnerability) -> bool:
        """Добавить новую уязвимость в БД"""
        return self.vulnerability_service.add_vulnerability(vulnerability)

    def get_vulnerability_by_title(self, title: str) -> Optional[Vulnerability]:
        """Найти уязвимость по заголовку"""
        return self.vulnerability_service.get_vulnerability_by_title(title)

    def assign_vulnerabilities_to_operator(self, operator_id: int, vulnerability_ids: List[int]) -> bool:
        """Назначить уязвимости оператору"""
        return self.operator_service.assign_vulnerabilities(operator_id, vulnerability_ids)

    def get_vulnerabilities_count(self) -> int:
        """Получить общее количество уязвимостей"""
        return self.vulnerability_service.get_vulnerabilities_count()