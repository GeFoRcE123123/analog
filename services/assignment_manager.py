from typing import List, Dict, Optional
from models.entities import Vulnerability, Operator
import logging


class AssignmentManager:
    """Менеджер для назначения операторов на уязвимости"""

    def __init__(self, data_manager):
        self.data_manager = data_manager
        self.logger = logging.getLogger(__name__)

    def assign_operator_to_vulnerability(self, vulnerability_id: int, operator_id: int) -> Dict[str, any]:
        """Назначить оператора на конкретную уязвимость"""
        try:
            vulnerability = self.data_manager.get_vulnerability_by_id(vulnerability_id)
            operator = self.data_manager.get_operator_by_id(operator_id)

            if not vulnerability:
                return {'success': False, 'message': 'Уязвимость не найдена'}

            if not operator:
                return {'success': False, 'message': 'Оператор не найден'}

            # Убираем уязвимость у предыдущего оператора (если был)
            if vulnerability.assigned_operator:
                previous_operator = self.data_manager.get_operator_by_id(vulnerability.assigned_operator)
                if previous_operator:
                    previous_operator.remove_vulnerability(vulnerability_id)
                    self.data_manager.update_operator(previous_operator)

            # Назначаем новому оператору
            vulnerability.assigned_operator = operator_id
            vulnerability.status = 'in_progress'

            # Добавляем уязвимость оператору, если её еще нет
            if vulnerability not in operator.assigned_vulnerabilities:
                operator.assigned_vulnerabilities.append(vulnerability)

            # Сохраняем изменения
            self.data_manager.update_vulnerability(vulnerability)
            self.data_manager.update_operator(operator)

            self.logger.info(f"Уязвимость {vulnerability_id} назначена оператору {operator.name}")

            return {
                'success': True,
                'message': f'Уязвимость назначена оператору {operator.name}',
                'vulnerability': {
                    'id': vulnerability.id,
                    'title': vulnerability.title,
                    'status': vulnerability.status
                },
                'operator': {
                    'id': operator.id,
                    'name': operator.name,
                    'assigned_count': len(operator.assigned_vulnerabilities)
                }
            }

        except Exception as e:
            self.logger.error(f"Ошибка назначения оператора: {e}")
            return {'success': False, 'message': f'Ошибка назначения: {str(e)}'}

    def assign_multiple_vulnerabilities(self, operator_id: int, vulnerability_ids: List[int]) -> Dict[str, any]:
        """Назначить несколько уязвимостей оператору"""
        try:
            operator = self.data_manager.get_operator_by_id(operator_id)
            if not operator:
                return {'success': False, 'message': 'Оператор не найден'}

            assigned_count = 0
            failed_assignments = []

            for vuln_id in vulnerability_ids:
                result = self.assign_operator_to_vulnerability(vuln_id, operator_id)
                if result['success']:
                    assigned_count += 1
                else:
                    failed_assignments.append({'vuln_id': vuln_id, 'error': result['message']})

            return {
                'success': True,
                'message': f'Назначено {assigned_count} из {len(vulnerability_ids)} уязвимостей',
                'assigned_count': assigned_count,
                'failed_assignments': failed_assignments,
                'operator': {
                    'id': operator.id,
                    'name': operator.name,
                    'total_assigned': len(operator.assigned_vulnerabilities)
                }
            }

        except Exception as e:
            self.logger.error(f"Ошибка массового назначения: {e}")
            return {'success': False, 'message': f'Ошибка массового назначения: {str(e)}'}

    def get_operator_workload(self, operator_id: int) -> Dict[str, any]:
        """Получить нагрузку оператора"""
        operator = self.data_manager.get_operator_by_id(operator_id)
        if not operator:
            return {'success': False, 'message': 'Оператор не найден'}

        active_vulnerabilities = [v for v in operator.assigned_vulnerabilities if v.status != 'completed']
        completed_vulnerabilities = [v for v in operator.assigned_vulnerabilities if v.status == 'completed']

        return {
            'success': True,
            'operator': {
                'id': operator.id,
                'name': operator.name,
                'total_assigned': len(operator.assigned_vulnerabilities),
                'active_count': len(active_vulnerabilities),
                'completed_count': len(completed_vulnerabilities),
                'workload_percentage': operator.calculate_workload()
            },
            'active_vulnerabilities': [
                {
                    'id': v.id,
                    'title': v.title,
                    'severity': v.severity,
                    'status': v.status
                } for v in active_vulnerabilities
            ]
        }

    def reassign_vulnerability(self, vulnerability_id: int, new_operator_id: int) -> Dict[str, any]:
        """Переназначить уязвимость другому оператору"""
        return self.assign_operator_to_vulnerability(vulnerability_id, new_operator_id)

    def unassign_vulnerability(self, vulnerability_id: int) -> Dict[str, any]:
        """Снять назначение с уязвимости"""
        try:
            vulnerability = self.data_manager.get_vulnerability_by_id(vulnerability_id)
            if not vulnerability or not vulnerability.assigned_operator:
                return {'success': False, 'message': 'Уязвимость не назначена'}

            operator = self.data_manager.get_operator_by_id(vulnerability.assigned_operator)
            if operator:
                operator.remove_vulnerability(vulnerability_id)
                self.data_manager.update_operator(operator)

            vulnerability.assigned_operator = None
            vulnerability.status = 'new'
            self.data_manager.update_vulnerability(vulnerability)

            return {'success': True, 'message': 'Назначение снято'}

        except Exception as e:
            self.logger.error(f"Ошибка снятия назначения: {e}")
            return {'success': False, 'message': f'Ошибка снятия назначения: {str(e)}'}