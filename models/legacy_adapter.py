"""
Адаптер для конвертации между современными моделями и legacy схемой БД
"""
from typing import Dict, Optional
from datetime import datetime
from models.entities import Vulnerability, NVDVulnerability


def nvd_to_vulnerability(nvd_vuln: NVDVulnerability) -> Vulnerability:
    """Конвертация NVDVulnerability в Vulnerability для legacy схемы"""
    
    # Получаем основное описание
    description = ""
    if nvd_vuln.descriptions:
        for desc in nvd_vuln.descriptions:
            if isinstance(desc, dict):
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            elif isinstance(desc, str):
                description = desc
                break
        
        if not description and nvd_vuln.descriptions:
            first_desc = nvd_vuln.descriptions[0]
            if isinstance(first_desc, dict):
                description = first_desc.get('value', '')
            else:
                description = str(first_desc)

    # Определяем severity из CVSS
    severity = 'medium'
    cvss_score = 0.0
    
    if nvd_vuln.metrics:
        if nvd_vuln.metrics.cvss_v4:
            cvss_data = nvd_vuln.metrics.cvss_v4
            cvss_score = float(cvss_data.get('baseScore', 0.0)) if isinstance(cvss_data, dict) else 0.0
            severity_str = cvss_data.get('baseSeverity', 'medium').lower() if isinstance(cvss_data, dict) else 'medium'
        elif nvd_vuln.metrics.cvss_v3:
            cvss_data = nvd_vuln.metrics.cvss_v3
            cvss_score = float(cvss_data.get('baseScore', 0.0)) if isinstance(cvss_data, dict) else 0.0
            severity_str = cvss_data.get('baseSeverity', 'medium').lower() if isinstance(cvss_data, dict) else 'medium'
        elif nvd_vuln.metrics.cvss_v2:
            cvss_data = nvd_vuln.metrics.cvss_v2
            cvss_score = float(cvss_data.get('baseScore', 0.0)) if isinstance(cvss_data, dict) else 0.0
            severity_str = 'medium'
        else:
            severity_str = 'medium'

        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low'
        }
        severity = severity_map.get(severity_str, 'medium')

    # Создаем объект Vulnerability
    vulnerability = Vulnerability(
        id=0,  # БД назначит ID
        title=nvd_vuln.cve_id or 'Unknown CVE',
        description=description[:1000],
        severity=severity,
        status='new',
        assigned_operator=None,
        created_date=datetime.now(),
        completed_date=None,
        approved=False,
        modifications=0,
        cvss_score=cvss_score,
        risk_level=severity,
        category='security'
    )

    # Добавляем NVD поля как атрибуты
    vulnerability.cve_id = nvd_vuln.cve_id
    vulnerability.source_identifier = nvd_vuln.source_identifier
    vulnerability.published = nvd_vuln.published
    vulnerability.last_modified = nvd_vuln.last_modified
    vulnerability.vuln_status = nvd_vuln.vuln_status
    
    # Конвертируем descriptions
    if nvd_vuln.descriptions:
        vulnerability.descriptions = []
        for desc in nvd_vuln.descriptions:
            if isinstance(desc, dict):
                vulnerability.descriptions.append(desc)
            else:
                vulnerability.descriptions.append({'lang': 'en', 'value': str(desc)})
    
    # Конвертируем metrics
    if nvd_vuln.metrics:
        vulnerability.metrics = {}
        if nvd_vuln.metrics.cvss_v2:
            vulnerability.metrics['cvss_v2'] = nvd_vuln.metrics.cvss_v2 if isinstance(nvd_vuln.metrics.cvss_v2, dict) else {}
        if nvd_vuln.metrics.cvss_v3:
            vulnerability.metrics['cvss_v3'] = nvd_vuln.metrics.cvss_v3 if isinstance(nvd_vuln.metrics.cvss_v3, dict) else {}
        if nvd_vuln.metrics.cvss_v4:
            vulnerability.metrics['cvss_v4'] = nvd_vuln.metrics.cvss_v4 if isinstance(nvd_vuln.metrics.cvss_v4, dict) else {}
    
    # Конвертируем weaknesses
    vulnerability.weaknesses = []
    if nvd_vuln.weaknesses:
        for weak in nvd_vuln.weaknesses:
            if isinstance(weak, dict):
                vulnerability.weaknesses.append(weak)
            else:
                vulnerability.weaknesses.append({
                    'source': getattr(weak, 'source', ''),
                    'type': getattr(weak, 'type', ''),
                    'description': getattr(weak, 'description', ''),
                    'cwe_id': getattr(weak, 'cwe_id', '')
                })
    
    # Конвертируем configurations
    vulnerability.configurations = []
    if nvd_vuln.configurations:
        for config in nvd_vuln.configurations:
            if isinstance(config, dict):
                vulnerability.configurations.append(config)
            else:
                vulnerability.configurations.append({
                    'nodes': getattr(config, 'nodes', []),
                    'operator': getattr(config, 'operator', '')
                })
    
    # Конвертируем references
    vulnerability.references = []
    if nvd_vuln.references:
        for ref in nvd_vuln.references:
            if isinstance(ref, dict):
                vulnerability.references.append(ref)
            else:
                vulnerability.references.append({
                    'url': getattr(ref, 'url', ''),
                    'source': getattr(ref, 'source', ''),
                    'tags': getattr(ref, 'tags', [])
                })
    
    vulnerability.vendor_comments = nvd_vuln.vendor_comments or []
    vulnerability.is_ai_related = nvd_vuln.is_ai_related
    vulnerability.ai_confidence = nvd_vuln.ai_confidence
    vulnerability.has_kev = nvd_vuln.has_kev
    vulnerability.has_cert_alerts = nvd_vuln.has_cert_alerts

    return vulnerability


def dict_to_vulnerability(vuln_dict: Dict) -> Vulnerability:
    """Конвертация словаря в Vulnerability"""
    from models.entities import Vulnerability
    
    return Vulnerability(
        id=vuln_dict.get('id', 0),
        title=vuln_dict.get('title', vuln_dict.get('cve_id', 'Unknown')),
        description=vuln_dict.get('description', ''),
        severity=vuln_dict.get('severity', 'medium'),
        status=vuln_dict.get('status', 'new'),
        assigned_operator=vuln_dict.get('assigned_operator'),
        created_date=vuln_dict.get('created_date'),
        completed_date=vuln_dict.get('completed_date'),
        approved=vuln_dict.get('approved', False),
        modifications=vuln_dict.get('modifications', 0),
        cvss_score=float(vuln_dict.get('cvss_score', 0.0)),
        risk_level=vuln_dict.get('risk_level', 'medium'),
        category=vuln_dict.get('category', 'security'),
        cve_id=vuln_dict.get('cve_id')
    )

