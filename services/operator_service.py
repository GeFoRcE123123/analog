import logging
from typing import List, Optional, Dict
from datetime import datetime
from models.entities import Operator
from models.repository_factory import repository_factory

logger = logging.getLogger(__name__)


class OperatorService:
    """Сервис для работы с операторами через PostgreSQL"""

    def __init__(self):
        self.repo_factory = repository_factory
        self.operator_repo = self.repo_factory.create_operator_repository()
        logger.info("OperatorService initialized with PostgreSQL")

    def get_all_operators(self) -> List[Operator]:
        """Получить всех операторов"""
        try:
            return self.operator_repo.get_all()
        except Exception as e:
            logger.error(f"Error getting all operators: {e}")
            return []

    def get_operator_by_id(self, operator_id: int) -> Optional[Operator]:
        """Получить оператора по ID"""
        try:
            return self.operator_repo.get_by_id(operator_id)
        except Exception as e:
            logger.error(f"Error getting operator {operator_id}: {e}")
            return None

    def get_operator_by_email(self, email: str) -> Optional[Operator]:
        """Получить оператора по email"""
        try:
            return self.operator_repo.get_by_email(email)
        except Exception as e:
            logger.error(f"Error getting operator by email '{email}': {e}")
            return None

    def create_operator(self, name: str, email: str, experience_level: float = 50.0) -> Operator:
        """Создать нового оператора"""
        try:
            # Проверяем, нет ли оператора с таким email
            existing = self.get_operator_by_email(email)
            if existing:
                raise ValueError(f"Operator with email {email} already exists")

            new_operator = Operator(
                id=0,  # Будет установлен при сохранении
                name=name,
                email=email,
                experience_level=experience_level,
                current_metric=experience_level,
                assigned_vulnerabilities=[],
                last_activity=datetime.now()
            )

            if self.operator_repo.add(new_operator):
                return new_operator
            else:
                raise Exception("Failed to create operator in database")

        except Exception as e:
            logger.error(f"Error creating operator '{name}': {e}")
            raise

    def remove_vulnerability_from_operator(self, operator_id: int, vuln_id: int) -> bool:
        """Удалить уязвимость у оператора"""
        try:
            # Используем VulnerabilityService для снятия назначения
            from .vulnerability_service import VulnerabilityService
            vuln_service = VulnerabilityService()
            return vuln_service.unassign_vulnerability(vuln_id)
        except Exception as e:
            logger.error(f"Error removing vulnerability {vuln_id} from operator {operator_id}: {e}")
            return False

    def update_operator_metric(self, operator_id: int, action: str) -> bool:
        """Обновить метрику оператора на основе действия"""
        try:
            operator = self.get_operator_by_id(operator_id)
            if not operator:
                return False

            metric_changes = {
                'approve': 10,  # +10% за одобрение
                'modify': -5,  # -5% за модификацию
                'inactive': -2,  # -2% за неактивность
                'complete': 5  # +5% за выполнение
            }

            if action in metric_changes:
                new_metric = operator.current_metric + metric_changes[action]
                new_metric = max(0, min(100, new_metric))
                return self.operator_repo.update_metric(operator_id, new_metric)

            return False
        except Exception as e:
            logger.error(f"Error updating operator metric {operator_id} for action '{action}': {e}")
            return False

    def assign_vulnerabilities(self, operator_id: int, vulnerability_ids: List[int]) -> bool:
        """Назначить уязвимости оператору"""
        try:
            from .vulnerability_service import VulnerabilityService
            vuln_service = VulnerabilityService()

            success = True
            for vuln_id in vulnerability_ids:
                if not vuln_service.assign_vulnerability(vuln_id, operator_id):
                    success = False

            return success
        except Exception as e:
            logger.error(f"Error assigning vulnerabilities to operator {operator_id}: {e}")
            return False

    def get_operator_performance_report(self) -> Dict:
        """Получить отчет по производительности операторов"""
        try:
            operators = self.get_all_operators()
            report = {}

            for op in operators:
                completed = len([v for v in op.assigned_vulnerabilities if v.status == 'completed'])
                pending = len([v for v in op.assigned_vulnerabilities if v.status != 'completed'])

                report[op.id] = {
                    'name': op.name,
                    'metric': op.current_metric,
                    'completed': completed,
                    'pending': pending,
                    'workload': op.calculate_workload()
                }

            return report
        except Exception as e:
            logger.error(f"Error generating operator performance report: {e}")
            return {}