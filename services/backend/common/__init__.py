"""
Общие модули для Frontend и Backend приложений
"""
from .helpers import (
    get_vulnerabilities_with_operators,
    get_vulnerabilities_with_operators_old,
    get_dashboard_stats,
    get_analytics_data,
    serialize_vulnerability,
    save_parsing_history
)

__all__ = [
    'get_vulnerabilities_with_operators',
    'get_vulnerabilities_with_operators_old',
    'get_dashboard_stats',
    'get_analytics_data',
    'serialize_vulnerability',
    'save_parsing_history'
]

