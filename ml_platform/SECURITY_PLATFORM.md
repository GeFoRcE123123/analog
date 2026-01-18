# Распределенная платформа анализа информационной безопасности

Полная реализация системы анализа уязвимостей, расчета рисков и паспортизации CVE с использованием машинного обучения.

## Архитектура системы

```
┌─────────────────────────────────────────────────────────────┐
│                    ML Platform Core                          │
│  (Model Training, Data Loading, GPU Management)            │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Security Analysis Module                       │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │  Collectors  │  │  Passports   │  │  ML Models   │    │
│  │  (NVD/OSV/   │  │  (CVE Data   │  │  (Classify/  │    │
│  │   GitHub)    │  │   Structure) │  │   Predict)   │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ Risk Engine  │  │Visualization │  │  API Layer   │    │
│  │ (Calculate/ │  │ (Dashboards/ │  │  (REST/WS)   │    │
│  │  Aggregate)  │  │   Reports)   │  │              │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Основные компоненты

### 1. Сбор данных (Collectors)

**NVDCollector**
- Сбор данных из National Vulnerability Database
- Поддержка API v2.0
- Rate limiting и обработка ошибок
- Нормализация данных CVE

**OSVCollector**
- Сбор данных из Open Source Vulnerabilities
- Поиск по пакетам и коммитам
- Поддержка различных экосистем (npm, pypi, maven, etc.)

**GitHubSecurityCollector**
- Сбор данных из GitHub Security Advisories
- Поиск по экосистемам
- Интеграция с GHSA ID

### 2. Паспортизация CVE

**CVEPassport**
- Единая структура данных об уязвимости
- Полная информация: CVSS, CWE, CPE, эксплуатируемость
- ML предсказания
- Метрики качества данных

**CVEPassportManager**
- Создание и управление паспортами
- Объединение данных из разных источников
- Вычисление качества метаданных

### 3. ML модели

**VulnerabilityClassifier**
- Мультизадачная нейросетевая модель
- Классификация критичности
- Классификация типа атаки (CWE)
- Предсказание сложности эксплуатации
- Регрессия CVSS score

**VulnerabilityClassifierTrainer**
- Обучение моделей на исторических данных
- Извлечение признаков из паспортов
- Валидация и метрики качества

### 4. Движок расчета рисков

**RiskEngine**
- Базовый расчет риска (CVSS × Критичность × Бизнес-ценность)
- Учет сетевой экспозиции
- Расчет вероятности угрозы
- Фактор компенсирующих контролей
- ML коррекция на основе контекста
- Агрегация рисков по активам

**Asset**
- Модель актива организации
- CPE конфигурации для сопоставления
- Критичность и бизнес-ценность
- Компенсирующие контроли

### 5. Визуализация

**SecurityVisualizer**
- Тепловые карты рисков (Assets vs CVEs)
- Распределение по критичности
- Временные линии CVSS scores
- Распределение рисков по активам
- Полные отчеты безопасности

### 6. API

**Security API Endpoints**
- `GET /security/cve/{cve_id}` - Получение паспорта CVE
- `POST /security/cve/collect` - Сбор недавних CVE
- `POST /security/assets` - Создание актива
- `POST /security/risk/calculate` - Расчет риска
- `POST /security/risk/batch` - Пакетный расчет
- `GET /security/risk/aggregate/{asset_id}` - Агрегированный риск
- `GET /security/stats` - Статистика

## Алгоритм работы

### 1. Сбор данных
```
NVD API → Нормализация → Паспорт CVE
OSV API → Нормализация → Объединение с паспортом
GitHub → Нормализация → Обогащение паспорта
```

### 2. Паспортизация
```
Сырые данные → Нормализация → CVEPassport
  ↓
Обогащение метаданными
  ↓
Вычисление качества
  ↓
Сохранение в хранилище
```

### 3. ML классификация
```
Паспорт CVE → Извлечение признаков → ML модель
  ↓
Предсказания:
  - Критичность
  - Тип атаки
  - Сложность
  - CVSS score
  ↓
Обновление паспорта
```

### 4. Расчет рисков
```
CVE + Актив → Сопоставление CPE → Базовый риск
  ↓
Учет факторов:
  - Экспозиция
  - Вероятность угрозы
  - Контроли
  ↓
ML коррекция
  ↓
Финальный риск
```

### 5. Визуализация
```
Риски + Активы → Агрегация → Графики
  ↓
Отчеты безопасности
```

## Использование

### Базовый пример

```python
from ml_platform.security.collectors.nvd_collector import NVDCollector
from ml_platform.security.cve_passport import CVEPassportManager
from ml_platform.security.risk_engine import RiskEngine, Asset

# Сбор данных
nvd = NVDCollector()
cves = nvd.get_recent_cves(days=7)

# Паспортизация
manager = CVEPassportManager()
for cve_data in cves:
    normalized = nvd.normalize_cve_data(cve_data)
    passport = manager.create_passport(normalized["cve_id"], normalized)

# Расчет рисков
risk_engine = RiskEngine()
asset = Asset(
    asset_id="server-01",
    name="Web Server",
    asset_type="server",
    criticality=0.9,
    business_value=0.8,
    cpe_configurations=["cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*"]
)

for passport in manager.passports.values():
    risk = risk_engine.calculate_risk(passport, asset)
    print(f"{passport.cve_id}: {risk.risk_level} ({risk.adjusted_risk_score:.2f})")
```

### Через API

```bash
# Получение паспорта CVE
curl http://localhost:8000/security/cve/CVE-2024-0001

# Расчет риска
curl -X POST http://localhost:8000/security/risk/calculate \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2024-0001",
    "asset_id": "server-01",
    "use_ml_correction": true
  }'

# Пакетный расчет
curl -X POST http://localhost:8000/security/risk/batch \
  -H "Content-Type: application/json" \
  -d '{
    "cve_ids": ["CVE-2024-0001", "CVE-2024-0002"],
    "assets": [{
      "asset_id": "server-01",
      "name": "Web Server",
      "asset_type": "server",
      "criticality": 0.9,
      "business_value": 0.8,
      "cpe_configurations": ["cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*"]
    }]
  }'
```

## Структура паспорта CVE

```yaml
CVE_Passport:
  metadata:
    cve_id: "CVE-2024-XXXXX"
    published_date: "2024-01-15T00:00Z"
    data_sources: ["NVD", "OSV"]
  
  vulnerability:
    description: "Описание уязвимости"
    cwe_ids: ["CWE-78"]
    attack_vector: ["NETWORK"]
  
  scoring:
    cvss_v3:
      base_score: 9.8
      vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      severity: "Critical"
  
  affected_products:
    - cpe: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
      vulnerable: true
  
  exploitability:
    known_exploited: true
    exploitation_rating: "High"
  
  ml_predictions:
    risk_category: "Critical"
    propagation_likelihood: 0.92
    confidence_score: 0.94
```

## Расчет риска

Формула расчета риска:

```
Base Risk = CVSS Score × Asset Criticality × Business Value

Exposure Factor = Network Exposure × Attack Vector Factor

Threat Likelihood = Base Likelihood × Exploitability × ML Prediction

Controls Factor = 1 - Σ(Control Effectiveness)

Final Risk = Base Risk × Exposure Factor × Threat Likelihood × Controls Factor × ML Correction
```

## ML модели

### Классификация уязвимостей

**Входные признаки:**
- CVSS scores (base, exploitability, impact)
- CWE категории (one-hot encoding)
- Эксплуатируемость (boolean flags)
- Количество затронутых продуктов
- Наличие патчей
- Качество метаданных
- Длина описания
- Вектор атаки

**Выходы:**
- Критичность (5 классов)
- Тип атаки (28+ CWE категорий)
- Сложность (3 класса)
- CVSS score (регрессия)

### Обучение модели

```python
from ml_platform.security.ml_models.vulnerability_classifier import VulnerabilityClassifierTrainer

trainer = VulnerabilityClassifierTrainer()

# Подготовка данных
passports = [...]  # Список паспортов CVE

# Обучение
trainer.train(passports, epochs=100, learning_rate=0.001)

# Сохранение
trainer.save("models/vulnerability_classifier.pth")

# Использование
predictions = trainer.predict(passport)
```

## Визуализация

### Доступные графики

1. **Risk Heatmap** - Тепловая карта рисков (Assets × CVEs)
2. **Severity Distribution** - Распределение по критичности
3. **CVSS Timeline** - Временная линия CVSS scores
4. **Asset Risk Distribution** - Топ активов по риску

### Создание отчета

```python
from ml_platform.security.visualization.security_dashboard import SecurityVisualizer

visualizer = SecurityVisualizer()
report_files = visualizer.create_security_report(
    passports=passports,
    risk_calculations=risk_calculations,
    assets=assets
)
```

## Интеграция

### С основным API сервером

Security API автоматически подключается к основному серверу:

```python
from ml_platform.api.server import app

# Security endpoints доступны по /security/*
```

### С внешними системами

- **SIEM системы** - Экспорт через API
- **ITSM системы** - Создание тикетов через webhooks
- **Threat Intelligence** - Импорт/экспорт STIX формата
- **CMDB** - Синхронизация активов

## Масштабирование

- Поддержка миллионов CVE записей
- Обработка сотен тысяч активов
- Параллельный расчет рисков
- Кэширование паспортов CVE
- Асинхронная обработка запросов

## Безопасность

- Валидация всех входных данных
- Rate limiting для внешних API
- Шифрование чувствительных данных
- Аудит всех операций
- RBAC для доступа к API

## Документация

- `security/README.md` - Документация модуля безопасности
- `examples/security_analysis.py` - Полный пример использования
- API документация доступна через `/docs` endpoint

## Требования

Дополнительные зависимости в `requirements_security.txt`:
- requests, httpx - для сбора данных
- seaborn, plotly - для визуализации
- transformers - для NLP анализа
- stix2 - для threat intelligence

## Лицензия

MIT License
