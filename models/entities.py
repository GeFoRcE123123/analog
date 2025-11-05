from dataclasses import dataclass
import json
from datetime import datetime
from typing import List, Dict, Optional, Any




@dataclass
class Vulnerability:
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

    def mark_completed(self):
        self.status = 'completed'
        self.completed_date = datetime.now()

    def mark_approved(self):
        self.approved = True
        self.status = 'approved'

    def request_modification(self):
        self.modifications += 1
        self.status = 'needs_modification'

    @classmethod
    def from_db_row(cls, row):
        """Создать объект Vulnerability из строки БД"""
        return cls(
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

    @dataclass
    class Vulnerability:
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

        # Новые поля для NVD данных
        cve_id: Optional[str] = None
        source_identifier: Optional[str] = None
        published: Optional[datetime] = None
        last_modified: Optional[datetime] = None
        vuln_status: Optional[str] = None
        descriptions: List[Dict] = None
        metrics: Dict = None
        weaknesses: List[Dict] = None
        configurations: List[Dict] = None
        references: List[Dict] = None
        vendor_comments: List[Dict] = None
        is_ai_related: bool = False
        ai_confidence: float = 0.0
        has_kev: bool = False
        has_cert_alerts: bool = False

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

        def mark_completed(self):
            self.status = 'completed'
            self.completed_date = datetime.now()

        def mark_approved(self):
            self.approved = True
            self.status = 'approved'

        def request_modification(self):
            self.modifications += 1
            self.status = 'needs_modification'

        @classmethod
        def from_db_row(cls, row):
            """Создать объект Vulnerability из строки БД"""
            # Используем обновленный конструктор с NVD полями
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

            # Добавляем NVD поля если они есть
            if len(row) > 13:
                vuln.cve_id = row[13]
                vuln.source_identifier = row[14]
                vuln.published = row[15]
                vuln.last_modified = row[16]
                vuln.vuln_status = row[17]

                # JSON поля
                if row[18]:  # descriptions
                    try:
                        vuln.descriptions = json.loads(row[18])
                    except:
                        vuln.descriptions = []

                if row[19]:  # metrics
                    try:
                        vuln.metrics = json.loads(row[19])
                    except:
                        vuln.metrics = {}

                if row[20]:  # weaknesses
                    try:
                        vuln.weaknesses = json.loads(row[20])
                    except:
                        vuln.weaknesses = []

                if row[21]:  # configurations
                    try:
                        vuln.configurations = json.loads(row[21])
                    except:
                        vuln.configurations = []

                if row[22]:  # references
                    try:
                        vuln.references = json.loads(row[22])
                    except:
                        vuln.references = []

                if row[23]:  # vendor_comments
                    try:
                        vuln.vendor_comments = json.loads(row[23])
                    except:
                        vuln.vendor_comments = []

                # Флаги
                vuln.is_ai_related = bool(row[24]) if row[24] is not None else False
                vuln.ai_confidence = float(row[25]) if row[25] else 0.0
                vuln.has_kev = bool(row[26]) if row[26] is not None else False
                vuln.has_cert_alerts = bool(row[27]) if row[27] is not None else False

            return vuln

        def is_nvd_vulnerability(self) -> bool:
            """Проверка, является ли уязвимость из NVD"""
            return self.cve_id is not None

        def get_primary_description(self) -> str:
            """Получить основное описание на английском"""
            for desc in self.descriptions:
                if desc.get('lang') == 'en':
                    return desc.get('value', '')
            return self.descriptions[0].get('value', '') if self.descriptions else self.description


from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Optional, Any


# Существующие классы остаются без изменений
# Добавляем новые классы для NVD уязвимостей

@dataclass
class NVDMetrics:
    """Метрики CVSS из NVD"""
    cvss_v2: Optional[Dict] = None
    cvss_v3: Optional[Dict] = None
    cvss_v4: Optional[Dict] = None


@dataclass
class NVDWeakness:
    """Слабость CWE из NVD"""
    source: str
    type: str
    description: str
    cwe_id: str


@dataclass
class NVDReference:
    """Ссылка на внешние ресурсы"""
    url: str
    source: str
    tags: List[str]


@dataclass
class NVDConfiguration:
    """Конфигурация CPE"""
    nodes: List[Dict]
    operator: str


@dataclass
class NVDVulnerability:
    """Уязвимость из NVD"""
    cve_id: str
    source_identifier: str
    published: datetime
    last_modified: datetime
    vuln_status: str
    descriptions: List[Dict]
    metrics: NVDMetrics
    weaknesses: List[NVDWeakness]
    configurations: List[NVDConfiguration]
    references: List[NVDReference]
    vendor_comments: List[Dict]

    # Флаги для классификации
    is_ai_related: bool = False
    ai_confidence: float = 0.0
    has_kev: bool = False
    has_cert_alerts: bool = False

    # Для интеграции с существующей системой
    assigned_operator_id: Optional[int] = None
    status: str = "new"

    def to_dict(self) -> Dict[str, Any]:
        """Конвертация в словарь для сохранения в БД"""
        return {
            'cve_id': self.cve_id,
            'source_identifier': self.source_identifier,
            'published': self.published.isoformat(),
            'last_modified': self.last_modified.isoformat(),
            'vuln_status': self.vuln_status,
            'descriptions': self.descriptions,
            'metrics': {
                'cvss_v2': self.metrics.cvss_v2,
                'cvss_v3': self.metrics.cvss_v3,
                'cvss_v4': self.metrics.cvss_v4
            },
            'weaknesses': [w.__dict__ for w in self.weaknesses],
            'configurations': [c.__dict__ for c in self.configurations],
            'references': [r.__dict__ for r in self.references],
            'vendor_comments': self.vendor_comments,
            'is_ai_related': self.is_ai_related,
            'ai_confidence': self.ai_confidence,
            'has_kev': self.has_kev,
            'has_cert_alerts': self.has_cert_alerts,
            'assigned_operator_id': self.assigned_operator_id,
            'status': self.status
        }

@dataclass
class Operator:
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

