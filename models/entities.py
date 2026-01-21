from dataclasses import dataclass, field
import json
from datetime import datetime, date
from typing import List, Dict, Optional, Any
from decimal import Decimal


@dataclass
class Vulnerability:
    """
    Модель уязвимости с поддержкой NVD и БДУ ФСТЭК
    """
    # ========================================
    # БАЗОВЫЕ ПОЛЯ (Основная информация)
    # ========================================
    id: int
    title: str
    description: str
    severity: str
    status: str = 'new'
    assigned_operator: Optional[int] = None
    created_date: Optional[datetime] = None
    completed_date: Optional[datetime] = None
    approved: bool = False
    modifications: int = 0
    cvss_score: float = 0.0
    risk_level: str = 'medium'
    category: str = 'web'

    # ========================================
    # NVD ПОЛЯ (National Vulnerability Database)
    # ========================================
    cve_id: Optional[str] = None
    source_identifier: Optional[str] = None
    published: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    vuln_status: Optional[str] = None
    descriptions: Optional[List[Dict]] = None
    metrics: Optional[Dict] = None
    weaknesses: Optional[List[Dict]] = None
    configurations: Optional[List[Dict]] = None
    references: Optional[List[Dict]] = None
    vendor_comments: Optional[List[Dict]] = None
    is_ai_related: bool = False
    ai_confidence: float = 0.0
    has_kev: bool = False
    has_cert_alerts: bool = False

    # ИИ-анализ результатов
    ai_keywords_found: Optional[List[str]] = None
    ai_categories: Optional[List[str]] = None
    ai_reasoning: Optional[str] = None

    # ========================================
    # БДУ ФСТЭК ПОЛЯ (Банк Данных Угроз)
    # ========================================
    
    # 1. Идентификация
    bdu_id: Optional[str] = None  # BDU:YYYY-XXXXX
    bdu_name: Optional[str] = None  # Название из БДУ
    
    # 2. Информация о ПО
    vendor: Optional[str] = None  # Вендор ПО
    product_name: Optional[str] = None  # Название продукта
    affected_versions: Optional[str] = None  # Уязвимые версии
    platform: Optional[str] = None  # Платформа (32/64-bit)
    software_types: Optional[List[Dict]] = None  # JSONB типы ПО
    registry_number: Optional[str] = None  # Регистрационный номер
    vulnerable_software: Optional[List[Dict]] = None  # JSONB полная структура
    
    # 3. Окружение
    environment: Optional[List[Dict]] = None  # JSONB информация об ОС
    
    # 4. Технические детали
    cwes: Optional[List[Dict]] = None  # JSONB массив CWE
    vul_class: Optional[str] = None  # Класс уязвимости
    sl_oper_procs: Optional[List[Dict]] = None  # Служебные операционные процессы
    
    # 5. Даты
    identify_date: Optional[date] = None  # Дата обнаружения
    publication_date: Optional[date] = None  # Дата публикации в БДУ
    last_upd_date: Optional[date] = None  # Дата последнего обновления
    
    # 6. Оценка рисков
    cvss2_vector: Optional[str] = None  # CVSS 2.0 вектор
    cvss2_score: Optional[Decimal] = None  # CVSS 2.0 оценка
    cvss3_vector: Optional[str] = None  # CVSS 3.0 вектор
    cvss3_score: Optional[Decimal] = None  # CVSS 3.0 оценка
    bdu_severity: Optional[str] = None  # Уровень опасности (текст из БДУ)
    
    # 7. Статусы и устранение
    vul_status: Optional[str] = None  # Статус уязвимости (Подтверждена производителем и т.д.)
    exploit_status: Optional[str] = None  # Наличие эксплоита
    fix_status: Optional[str] = None  # Статус устранения
    solution: Optional[str] = None  # Способ устранения
    
    # 8. Дополнительная информация
    sources: Optional[str] = None  # Источники (текст)
    other_identifiers: Optional[List[Dict]] = None  # JSONB других идентификаторов
    vul_incident: Optional[str] = None  # Информация об инциденте
    vul_state: Optional[str] = None  # Состояние уязвимости
    vul_elimination: Optional[str] = None  # Способ устранения (категория)

    def __post_init__(self):
        """Инициализация списков после создания объекта"""
        if self.descriptions is None:
            self.descriptions = []
        if self.weaknesses is None:
            self.weaknesses = []
        if self.configurations is None:
            self.configurations = []
        if self.references is None:
            self.references = []
        if self.vendor_comments is None:
            self.vendor_comments = []
        if self.metrics is None:
            self.metrics = {}
        if self.ai_keywords_found is None:
            self.ai_keywords_found = []
        if self.ai_categories is None:
            self.ai_categories = []
        if self.software_types is None:
            self.software_types = []
        if self.vulnerable_software is None:
            self.vulnerable_software = []
        if self.environment is None:
            self.environment = []
        if self.cwes is None:
            self.cwes = []
        if self.sl_oper_procs is None:
            self.sl_oper_procs = []
        if self.other_identifiers is None:
            self.other_identifiers = []

    # ========================================
    # МЕТОДЫ УПРАВЛЕНИЯ СТАТУСОМ
    # ========================================
    
    def mark_completed(self):
        """Отметить уязвимость как выполненную"""
        self.status = 'completed'
        self.completed_date = datetime.now()

    def mark_approved(self):
        """Утвердить уязвимость"""
        self.approved = True
        self.status = 'approved'

    def request_modification(self):
        """Запросить модификацию"""
        self.modifications += 1
        self.status = 'needs_modification'

    # ========================================
    # ПРОВЕРКИ ТИПА ИСТОЧНИКА
    # ========================================
    
    def is_nvd_vulnerability(self) -> bool:
        """Проверка, является ли уязвимость из NVD"""
        return self.cve_id is not None
    
    def is_bdu_vulnerability(self) -> bool:
        """Проверка, является ли уязвимость из БДУ ФСТЭК"""
        return self.bdu_id is not None
    
    def is_hybrid_vulnerability(self) -> bool:
        """Проверка, есть ли данные и из NVD и из БДУ"""
        return self.cve_id is not None and self.bdu_id is not None
    
    def get_source_type(self) -> str:
        """Получить тип источника данных"""
        if self.is_hybrid_vulnerability():
            return 'hybrid'
        elif self.is_bdu_vulnerability():
            return 'bdu'
        elif self.is_nvd_vulnerability():
            return 'nvd'
        else:
            return 'manual'

    # ========================================
    # ПОЛУЧЕНИЕ ОПИСАНИЙ
    # ========================================
    
    def get_primary_description(self) -> str:
        """Получить основное описание на английском (из NVD)"""
        if self.descriptions:
            for desc in self.descriptions:
                if desc.get('lang') == 'en':
                    return desc.get('value', '')
            # Если английского нет, вернуть первое доступное
            if self.descriptions:
                return self.descriptions[0].get('value', '')
        return self.description or ''
    
    def get_bdu_description(self) -> str:
        """Получить описание из БДУ (русский)"""
        # Описание БДУ хранится в основном поле description если это БДУ уязвимость
        if self.is_bdu_vulnerability():
            return self.description or ''
        return ''

    # ========================================
    # ПОЛУЧЕНИЕ CVSS
    # ========================================
    
    def get_highest_cvss_score(self) -> float:
        """Получить максимальную CVSS оценку из всех источников"""
        scores = []
        
        # CVSS из базового поля
        if self.cvss_score:
            scores.append(float(self.cvss_score))
        
        # CVSS 2.0 из БДУ
        if self.cvss2_score:
            scores.append(float(self.cvss2_score))
        
        # CVSS 3.0 из БДУ
        if self.cvss3_score:
            scores.append(float(self.cvss3_score))
        
        # CVSS из NVD metrics
        if self.metrics:
            if 'cvssMetricV31' in self.metrics:
                for metric in self.metrics['cvssMetricV31']:
                    if 'cvssData' in metric and 'baseScore' in metric['cvssData']:
                        scores.append(float(metric['cvssData']['baseScore']))
            if 'cvssMetricV30' in self.metrics:
                for metric in self.metrics['cvssMetricV30']:
                    if 'cvssData' in metric and 'baseScore' in metric['cvssData']:
                        scores.append(float(metric['cvssData']['baseScore']))
        
        return max(scores) if scores else 0.0
    
    def get_cvss_vector_string(self) -> Optional[str]:
        """Получить строку CVSS вектора (приоритет CVSS 3.0)"""
        # Приоритет БДУ CVSS 3.0
        if self.cvss3_vector:
            return self.cvss3_vector
        
        # Затем БДУ CVSS 2.0
        if self.cvss2_vector:
            return self.cvss2_vector
        
        # Затем из NVD metrics
        if self.metrics:
            if 'cvssMetricV31' in self.metrics:
                for metric in self.metrics['cvssMetricV31']:
                    if 'cvssData' in metric and 'vectorString' in metric['cvssData']:
                        return metric['cvssData']['vectorString']
        
        return None

    # ========================================
    # ПОЛУЧЕНИЕ CWE
    # ========================================
    
    def get_cwe_ids(self) -> List[str]:
        """Получить список CWE ID из всех источников"""
        cwe_ids = set()
        
        # CWE из БДУ
        if self.cwes:
            for cwe in self.cwes:
                if 'identifier' in cwe:
                    cwe_ids.add(cwe['identifier'])
        
        # CWE из NVD weaknesses
        if self.weaknesses:
            for weakness in self.weaknesses:
                if 'description' in weakness:
                    for desc in weakness['description']:
                        if desc.get('value', '').startswith('CWE-'):
                            cwe_ids.add(desc['value'])
        
        return list(cwe_ids)

    # ========================================
    # МЕТОДЫ ДЛЯ ЭКСПОРТА
    # ========================================
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь для JSON/API"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'assigned_operator': self.assigned_operator,
            'created_date': self.created_date.isoformat() if self.created_date else None,
            'completed_date': self.completed_date.isoformat() if self.completed_date else None,
            'approved': self.approved,
            'modifications': self.modifications,
            'cvss_score': float(self.cvss_score),
            'risk_level': self.risk_level,
            'category': self.category,
            
            # NVD
            'cve_id': self.cve_id,
            'source_identifier': self.source_identifier,
            'published': self.published.isoformat() if self.published else None,
            'last_modified': self.last_modified.isoformat() if self.last_modified else None,
            'vuln_status': self.vuln_status,
            'is_ai_related': self.is_ai_related,
            'ai_confidence': float(self.ai_confidence),
            'has_kev': self.has_kev,
            'has_cert_alerts': self.has_cert_alerts,
            
            # БДУ
            'bdu_id': self.bdu_id,
            'bdu_name': self.bdu_name,
            'vendor': self.vendor,
            'product_name': self.product_name,
            'affected_versions': self.affected_versions,
            'platform': self.platform,
            'registry_number': self.registry_number,
            'vul_class': self.vul_class,
            'identify_date': self.identify_date.isoformat() if self.identify_date else None,
            'publication_date': self.publication_date.isoformat() if self.publication_date else None,
            'last_upd_date': self.last_upd_date.isoformat() if self.last_upd_date else None,
            'cvss2_vector': self.cvss2_vector,
            'cvss2_score': float(self.cvss2_score) if self.cvss2_score else None,
            'cvss3_vector': self.cvss3_vector,
            'cvss3_score': float(self.cvss3_score) if self.cvss3_score else None,
            'bdu_severity': self.bdu_severity,
            'vul_status': self.vul_status,
            'exploit_status': self.exploit_status,
            'fix_status': self.fix_status,
            'solution': self.solution,
            'sources': self.sources,
            'vul_incident': self.vul_incident,
            'vul_state': self.vul_state,
            'vul_elimination': self.vul_elimination,
            
            # Computed
            'source_type': self.get_source_type(),
            'highest_cvss_score': self.get_highest_cvss_score(),
            'cwe_ids': self.get_cwe_ids(),
        }
    
    def to_bdu_dict(self) -> Dict[str, Any]:
        """Конвертация только БДУ полей в словарь"""
        return {
            'bdu_id': self.bdu_id,
            'bdu_name': self.bdu_name,
            'vendor': self.vendor,
            'product_name': self.product_name,
            'affected_versions': self.affected_versions,
            'platform': self.platform,
            'software_types': self.software_types,
            'registry_number': self.registry_number,
            'vulnerable_software': self.vulnerable_software,
            'environment': self.environment,
            'cwes': self.cwes,
            'vul_class': self.vul_class,
            'sl_oper_procs': self.sl_oper_procs,
            'identify_date': self.identify_date.isoformat() if self.identify_date else None,
            'publication_date': self.publication_date.isoformat() if self.publication_date else None,
            'last_upd_date': self.last_upd_date.isoformat() if self.last_upd_date else None,
            'cvss2_vector': self.cvss2_vector,
            'cvss2_score': float(self.cvss2_score) if self.cvss2_score else None,
            'cvss3_vector': self.cvss3_vector,
            'cvss3_score': float(self.cvss3_score) if self.cvss3_score else None,
            'bdu_severity': self.bdu_severity,
            'vul_status': self.vul_status,
            'exploit_status': self.exploit_status,
            'fix_status': self.fix_status,
            'solution': self.solution,
            'sources': self.sources,
            'other_identifiers': self.other_identifiers,
            'vul_incident': self.vul_incident,
            'vul_state': self.vul_state,
            'vul_elimination': self.vul_elimination,
        }

    @classmethod
    def from_db_row(cls, row):
        """
        Создать объект Vulnerability из строки БД
        Поддерживает как старый формат (13 колонок) так и новый (с NVD и БДУ полями)
        """
        # Базовые поля (всегда присутствуют)
        vuln = cls(
            id=row[0],
            title=row[1],
            description=row[2],
            severity=row[3],
            status=row[4],
            assigned_operator=row[5],
            created_date=row[6],
            completed_date=row[7],
            approved=row[8],
            modifications=row[9],
            cvss_score=float(row[10]) if row[10] else 0.0,
            risk_level=row[11],
            category=row[12]
        )

        # Если есть дополнительные поля, парсим их
        # Это требует точного знания порядка колонок в SELECT запросе
        # TODO: Реализовать полный парсинг всех полей из row
        # Рекомендуется использовать именованные параметры или ORM

        return vuln


@dataclass
class Operator:
    """Модель оператора"""
    id: int
    name: str
    email: str
    experience_level: float = 50.0
    current_metric: float = 50.0
    assigned_vulnerabilities: Optional[List[Vulnerability]] = None
    last_activity: Optional[datetime] = None

    def __post_init__(self):
        if self.assigned_vulnerabilities is None:
            self.assigned_vulnerabilities = []

    def calculate_workload(self) -> float:
        """Рассчитать текущую нагрузку оператора"""
        active_vulns = [v for v in self.assigned_vulnerabilities if v.status != 'completed']
        return len(active_vulns) * 10

    def remove_vulnerability(self, vuln_id: int):
        """Удалить уязвимость из списка назначенных"""
        self.assigned_vulnerabilities = [v for v in self.assigned_vulnerabilities if v.id != vuln_id]

    def get_assigned_vulnerabilities_info(self) -> List[dict]:
        """Получить информацию о назначенных уязвимостях"""
        return [
            {
                'id': vuln.id,
                'title': vuln.title,
                'severity': vuln.severity,
                'status': vuln.status,
                'cvss_score': vuln.cvss_score
            }
            for vuln in self.assigned_vulnerabilities
        ]

    @classmethod
    def from_db_row(cls, row):
        """Создать объект Operator из строки БД"""
        return cls(
            id=row[0],
            name=row[1],
            email=row[2],
            experience_level=float(row[3]),
            current_metric=float(row[4]),
            last_activity=row[5]
        )
