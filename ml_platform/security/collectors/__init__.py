"""
Сборщики данных об уязвимостях
"""

from .nvd_collector import NVDCollector
from .osv_collector import OSVCollector
from .github_security_collector import GitHubSecurityCollector
from .redhat_collector import RedHatCollector

__all__ = [
    'NVDCollector',
    'OSVCollector',
    'GitHubSecurityCollector',
    'RedHatCollector'
]
