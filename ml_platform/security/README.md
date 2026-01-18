# Модуль анализа информационной безопасности

Модуль для автоматизированного анализа уязвимостей, расчета рисков и паспортизации CVE с использованием машинного обучения.

## Основные возможности

- ✅ **Сбор данных об уязвимостях** из NVD, OSV, GitHub Security
- ✅ **Паспортизация CVE** с полной информацией об уязвимостях
- ✅ **ML классификация** уязвимостей по типу атаки и критичности
- ✅ **AI анализ** уязвимостей на предмет связи с ИИ/ML технологиями
- ✅ **Расчет рисков** с учетом контекста организации и ML коррекцией
- ✅ **Визуализация** рисков и уязвимостей
- ✅ **REST API** для интеграции с другими системами

## Компоненты

### Сборщики данных (collectors/)

- **NVDCollector** - сбор данных из National Vulnerability Database
- **OSVCollector** - сбор данных из Open Source Vulnerabilities
- **GitHubSecurityCollector** - сбор данных из GitHub Security Advisories

### Паспортизация CVE (cve_passport.py)

Система создания единых паспортов уязвимостей с полной информацией:

```python
from ml_platform.security.cve_passport import CVEPassport, CVEPassportManager

manager = CVEPassportManager()
passport = manager.create_passport(cve_id, normalized_data)

# Доступ к данным
print(passport.cve_id)
print(passport.get_severity())
print(passport.scoring.cvss_v3)
print(passport.affected_products)
```

### ML модели (ml_models/)

- **VulnerabilityClassifier** - нейросетевая модель для классификации:
  - Критичность (Critical/High/Medium/Low)
  - Тип атаки (CWE категории)
  - Сложность эксплуатации
  - Предсказание CVSS score

### AI анализ (ai_analysis/)

- **AIClassifier** - классификатор уязвимостей на ИИ-связанность:
  - Определение связи с ИИ/ML технологиями
  - Классификация по категориям (frameworks, models, techniques, etc.)
  - OWASP Top 10 классификация
  - Оценка zero-day потенциала
- **HybridAIClassifier** - гибридный подход:
  - Внешний API (опционально)
  - Локальный fallback
  - Автоматическое переключение

### Движок рисков (risk_engine.py)

Расчет рисков с учетом:
- CVSS базового скора
- Критичности актива
- Бизнес-ценности
- Сетевой экспозиции
- Компенсирующих контролей
- ML коррекции на основе исторических данных

```python
from ml_platform.security.risk_engine import RiskEngine, Asset

risk_engine = RiskEngine()

asset = Asset(
    asset_id="server-01",
    name="Web Server",
    asset_type="server",
    criticality=0.9,
    business_value=0.8,
    cpe_configurations=["cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*"]
)

risk = risk_engine.calculate_risk(passport, asset)
print(f"Risk Level: {risk.risk_level}")
print(f"Risk Score: {risk.adjusted_risk_score}")
```

### Визуализация (visualization/)

- Тепловые карты рисков
- Распределение уязвимостей по критичности
- Временные линии CVSS scores
- Распределение рисков по активам

## Использование

### Сбор данных об уязвимостях

```python
from ml_platform.security.collectors.nvd_collector import NVDCollector
from ml_platform.security.cve_passport import CVEPassportManager

# Сбор недавних CVE
nvd = NVDCollector()
recent_cves = nvd.get_recent_cves(days=7)

# Создание паспортов
manager = CVEPassportManager()
for cve_data in recent_cves:
    normalized = nvd.normalize_cve_data(cve_data)
    passport = manager.create_passport(normalized["cve_id"], normalized)
```

### ML классификация

```python
from ml_platform.security.ml_models.vulnerability_classifier import VulnerabilityClassifierTrainer

trainer = VulnerabilityClassifierTrainer()

# Обучение модели
trainer.train(passports, epochs=100)

# Предсказание
predictions = trainer.predict(passport)
print(f"Severity: {predictions['severity']}")
print(f"Attack Type: {predictions['attack_type']}")
```

### Расчет рисков

```python
from ml_platform.security.risk_engine import RiskEngine, Asset

risk_engine = RiskEngine()

# Создание актива
asset = Asset(
    asset_id="app-01",
    name="Web Application",
    asset_type="application",
    criticality=0.8,
    business_value=0.9,
    cpe_configurations=["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"],
    network_exposure=0.7,
    compensating_controls=["firewall", "waf"]
)

# Расчет риска
risk = risk_engine.calculate_risk(passport, asset, use_ml_correction=True)
```

### Визуализация

```python
from ml_platform.security.visualization.security_dashboard import SecurityVisualizer

visualizer = SecurityVisualizer()

# Создание отчета
report_files = visualizer.create_security_report(
    passports=passports,
    risk_calculations=risk_calculations,
    assets=assets
)
```

## API Endpoints

### Security API

#### GET /security/cve/{cve_id}
Получение паспорта CVE

#### POST /security/cve/collect
Сбор недавних CVE

#### POST /security/assets
Создание актива

#### POST /security/risk/calculate
Расчет риска для CVE и актива

#### POST /security/risk/batch
Пакетный расчет рисков

#### GET /security/risk/aggregate/{asset_id}
Получение агрегированного риска

#### GET /security/stats
Статистика безопасности

### AI Analysis API

#### POST /security/ai/analyze
Анализ уязвимости на ИИ-связанность

```json
{
  "cve_id": "CVE-2024-1234",
  "description": "Vulnerability description...",
  "cwe_ids": ["CWE-79"],
  "cvss_score": 7.5
}
```

#### POST /security/ai/classify/{cve_id}
Классификация существующего CVE

#### POST /security/ai/batch-analyze
Пакетный анализ нескольких CVE

#### GET /security/ai/stats
Статистика по AI-связанным уязвимостям

## Примеры использования

### Базовый анализ безопасности

См. `examples/security_analysis.py` для полного примера анализа безопасности.

### AI анализ уязвимостей

```python
from ml_platform.security.ai_analysis.ai_classifier import HybridAIClassifier
from ml_platform.security.cve_passport import CVEPassportManager

# Получение паспорта CVE
manager = CVEPassportManager()
passport = manager.get_passport("CVE-2024-1234")

# AI классификация
classifier = HybridAIClassifier()
classification = classifier.classify(passport)

print(f"ИИ-связана: {classification.is_ai_related}")
print(f"Уверенность: {classification.confidence:.2f}")
print(f"Категории: {classification.ai_categories}")
print(f"Обоснование: {classification.reasoning}")
```

### Использование через API

```bash
# AI анализ уязвимости
curl -X POST http://localhost:8000/security/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2024-1234",
    "description": "TensorFlow remote code execution vulnerability",
    "cwe_ids": ["CWE-79"],
    "cvss_score": 9.8
  }'

# Классификация существующего CVE
curl -X POST http://localhost:8000/security/ai/classify/CVE-2024-1234

# Пакетный анализ
curl -X POST http://localhost:8000/security/ai/batch-analyze \
  -H "Content-Type: application/json" \
  -d '["CVE-2024-1234", "CVE-2024-5678"]'
```

## Интеграция

Модуль интегрирован в основной API сервер и доступен через `/security/*` endpoints.

## Требования

- Все зависимости из `requirements.txt`
- Доступ к интернету для сбора данных из внешних источников
- Опционально: API ключи для увеличения лимитов запросов
