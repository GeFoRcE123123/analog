"""
Legacy парсеры из папки pars/
Адаптированы под структуру проекта
"""
from .base_legacy_parser import BaseLegacyParser
from .redhat_parser import RedHatParser
from .debian_parser import DebianParser
from .cisco_parser import CiscoParser
from .cert_parser import CertParser
from .fortiguard_parser import FortiGuardParser
from .ibm_parser import IBMParser
from .postgresql_parser import PostgreSQLParser
from .suse_parser import SUSEParser
from .palo_alto_parser import PaloAltoParser
from .juniper_parser import JuniperParser
from .cybersecurity_parser import CyberSecurityParser
from .cxsecurity_parser import CXSecurityParser
from .kaspersky_parser import KasperskyParser, KasperskyStatParser
from .nvd_keywords_parser import NVDKeywordsParser
from .zerodayinitiative_parser import ZeroDayInitiativeParser
from .cvedetails_parser import CVEDetailsParser

__all__ = [
    'BaseLegacyParser',
    'RedHatParser',
    'DebianParser',
    'CiscoParser',
    'CertParser',
    'FortiGuardParser',
    'IBMParser',
    'PostgreSQLParser',
    'SUSEParser',
    'PaloAltoParser',
    'JuniperParser',
    'CyberSecurityParser',
    'CXSecurityParser',
    'KasperskyParser',
    'KasperskyStatParser',
    'NVDKeywordsParser',
    'ZeroDayInitiativeParser',
    'CVEDetailsParser',
]
