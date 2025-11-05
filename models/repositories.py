from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime
from models.entities import Vulnerability, Operator


class BaseRepository(ABC):
    """Абстрактный базовый класс для всех репозиториев"""

    @abstractmethod
    def get_by_id(self, id: int):
        pass

    @abstractmethod
    def get_all(self) -> List:
        pass

    @abstractmethod
    def add(self, entity) -> bool:
        pass

    @abstractmethod
    def update(self, entity) -> bool:
        pass

    @abstractmethod
    def delete(self, id: int) -> bool:
        pass


class VulnerabilityRepository(BaseRepository):
    """Абстрактный репозиторий для уязвимостей"""

    @abstractmethod
    def get_by_title(self, title: str) -> Optional[Vulnerability]:
        pass

    @abstractmethod
    def get_by_status(self, status: str) -> List[Vulnerability]:
        pass

    @abstractmethod
    def get_by_severity(self, severity: str) -> List[Vulnerability]:
        pass

    @abstractmethod
    def assign_operator(self, vuln_id: int, operator_id: int) -> bool:
        pass

    @abstractmethod
    def unassign_operator(self, vuln_id: int) -> bool:
        pass


class OperatorRepository(BaseRepository):
    """Абстрактный репозиторий для операторов"""

    @abstractmethod
    def get_by_email(self, email: str) -> Optional[Operator]:
        pass

    @abstractmethod
    def update_metric(self, operator_id: int, new_metric: float) -> bool:
        pass

    @abstractmethod
    def get_assigned_vulnerabilities(self, operator_id: int) -> List[Vulnerability]:
        pass