# 🧪 Руководство по тестированию и интеграции парсеров

> **Полное руководство по тестированию, интеграции и развёртыванию каждого парсера отдельно**

## 📋 Содержание

1. [Обзор парсеров](#обзор-парсеров)
2. [Общая архитектура](#общая-архитектура)
3. [Тестирование парсеров](#тестирование-парсеров)
4. [Интеграция парсеров](#интеграция-парсеров)
5. [Развёртывание на сервере](#развёртывание-на-сервере)
6. [Схема поэтапной интеграции](#схема-поэтапной-интеграции)
7. [Мониторинг и безопасность](#мониторинг-и-безопасность)

---

## 📊 Обзор парсеров

### Основные парсеры

| Парсер | Файл | Класс | Тип | API/HTML |
|--------|------|-------|-----|----------|
| **NVD** | `services/nvd_integration_service.py` | `NVDIntegrationService` | API | ✅ API |
| **Red Hat** | `services/redhat_cve_importer.py` | `RedHatCVEImporter` | API | ✅ API |
| **OSV** | `services/osv_api_parser.py` | `OSVAPIParser` | API | ✅ API |
| **Ubuntu** | `services/html_vulnerability_parser.py` | `HTMLVulnerabilityParser` | HTML | ✅ HTML |
| **Debian** | `services/html_vulnerability_parser.py` | `HTMLVulnerabilityParser` | HTML | ✅ HTML |
| **CVE.org** | `services/cve_org_integration_service.py` | `CVEOrgIntegrationService` | JSON | ✅ JSON |

### Legacy парсеры (17 источников)

| Парсер | Файл | Класс |
|--------|------|-------|
| RedHat | `services/legacy_parsers/redhat_parser.py` | `RedHatParser` |
| Debian | `services/legacy_parsers/debian_parser.py` | `DebianParser` |
| Cisco | `services/legacy_parsers/cisco_parser.py` | `CiscoParser` |
| Cert | `services/legacy_parsers/cert_parser.py` | `CertParser` |
| FortiGuard | `services/legacy_parsers/fortiguard_parser.py` | `FortiGuardParser` |
| IBM | `services/legacy_parsers/ibm_parser.py` | `IBMParser` |
| PostgreSQL | `services/legacy_parsers/postgresql_parser.py` | `PostgreSQLParser` |
| SUSE | `services/legacy_parsers/suse_parser.py` | `SUSEParser` |
| Palo Alto | `services/legacy_parsers/palo_alto_parser.py` | `PaloAltoParser` |
| Juniper | `services/legacy_parsers/juniper_parser.py` | `JuniperParser` |
| CyberSecurity | `services/legacy_parsers/cybersecurity_parser.py` | `CyberSecurityParser` |
| CXSecurity | `services/legacy_parsers/cxsecurity_parser.py` | `CXSecurityParser` |
| Kaspersky | `services/legacy_parsers/kaspersky_parser.py` | `KasperskyParser` |
| NVD Keywords | `services/legacy_parsers/nvd_keywords_parser.py` | `NVDKeywordsParser` |
| Zero Day Initiative | `services/legacy_parsers/zerodayinitiative_parser.py` | `ZeroDayInitiativeParser` |
| CVE Details | `services/legacy_parsers/cvedetails_parser.py` | `CVEDetailsParser` |

---

## 🏗️ Общая архитектура

### Структура проекта

```
vulnerability_manager/
├── config.py                          # Конфигурация (БД, API ключи)
├── models/
│   ├── database.py                    # DatabaseManager (singleton)
│   ├── legacy_repositories.py         # LegacyVulnerabilityRepository
│   └── postgres_repositories.py       # PostgresVulnerabilityRepository
├── services/
│   ├── nvd_integration_service.py     # NVD парсер
│   ├── redhat_cve_importer.py         # Red Hat парсер
│   ├── osv_api_parser.py              # OSV парсер
│   ├── html_vulnerability_parser.py   # Ubuntu/Debian парсер
│   ├── cve_org_integration_service.py # CVE.org парсер
│   └── legacy_parsers/                # 17 legacy парсеров
└── tests/                             # Тесты парсеров
```

### Зависимости

Все парсеры используют:
- `models.database.DatabaseManager` - подключение к БД
- `models.legacy_repositories.LegacyVulnerabilityRepository` - сохранение в БД
- `config.Config` - настройки подключения

### База данных

- **Схема**: Legacy (`turn` таблица)
- **Хост**: `10.0.88.11:5432`
- **База**: `vuln_db`
- **Пользователь**: `admin`

---

## 🧪 Тестирование парсеров

### Общий формат теста

Каждый тест должен:
1. Инициализировать парсер
2. Подключиться к БД
3. Выполнить парсинг
4. Сохранить результаты
5. Вернуть JSON с результатами

### Формат вывода результатов

```json
{
  "parser": "NVD",
  "status": "success",
  "total_found": 120,
  "total_saved": 115,
  "duplicates_skipped": 5,
  "errors": [],
  "warnings": [],
  "duration_seconds": 2.5,
  "start_time": "2026-01-05T15:00:00",
  "end_time": "2026-01-05T15:00:02",
  "details": {
    "api_calls": 10,
    "rate_limit_hits": 0,
    "retries": 0
  }
}
```

---

## 1️⃣ NVD (NIST Vulnerability Database)

### Описание

**Файл**: `services/nvd_integration_service.py`  
**Класс**: `NVDIntegrationService`  
**Тип**: API парсер  
**Источник**: https://nvd.nist.gov/

### Зависимости

```python
from services.nvd_integration_service import NVDIntegrationService
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config
```

### Тестирование

#### Минимальный тест (1-5 CVE)

**Файл**: `tests/test_nvd_minimal.py`

```python
#!/usr/bin/env python3
"""Минимальный тест NVD парсера"""
import sys
import os
import json
from datetime import datetime, timedelta

# Добавляем путь к проекту
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.nvd_integration_service import NVDIntegrationService
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config

def test_nvd_minimal():
    """Тест парсинга 1-5 CVE из NVD"""
    start_time = datetime.now()
    results = {
        "parser": "NVD",
        "status": "running",
        "total_found": 0,
        "total_saved": 0,
        "duplicates_skipped": 0,
        "errors": [],
        "warnings": [],
        "start_time": start_time.isoformat()
    }
    
    try:
        # Инициализация
        db_manager = DatabaseManager()
        vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        api_key = Config.NVD_API_KEY
        
        # Создание парсера
        nvd_service = NVDIntegrationService(vuln_repo, api_key=api_key)
        
        # Парсинг за последний день (должно быть 1-5 CVE)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=1)
        
        sync_result = nvd_service.sync_vulnerabilities(
            start_date=start_date,
            end_date=end_date,
            full_sync=False
        )
        
        results["total_found"] = sync_result.get("total_parsed", 0)
        results["total_saved"] = sync_result.get("saved_count", 0)
        results["status"] = "success"
        
    except Exception as e:
        results["status"] = "error"
        results["errors"].append(str(e))
    
    finally:
        end_time = datetime.now()
        results["end_time"] = end_time.isoformat()
        results["duration_seconds"] = (end_time - start_time).total_seconds()
    
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return results

if __name__ == "__main__":
    test_nvd_minimal()
```

**Запуск**:
```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager
python tests/test_nvd_minimal.py
```

#### Полный тест (за месяц)

**Файл**: `tests/test_nvd_full.py`

```python
#!/usr/bin/env python3
"""Полный тест NVD парсера за месяц"""
import sys
import os
import json
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.nvd_integration_service import NVDIntegrationService
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config

def test_nvd_full():
    """Тест парсинга всех CVE за последний месяц"""
    start_time = datetime.now()
    results = {
        "parser": "NVD",
        "status": "running",
        "total_found": 0,
        "total_saved": 0,
        "duplicates_skipped": 0,
        "errors": [],
        "warnings": [],
        "start_time": start_time.isoformat(),
        "details": {}
    }
    
    try:
        db_manager = DatabaseManager()
        vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        api_key = Config.NVD_API_KEY
        
        nvd_service = NVDIntegrationService(vuln_repo, api_key=api_key)
        
        # Парсинг за последний месяц
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        sync_result = nvd_service.sync_vulnerabilities(
            start_date=start_date,
            end_date=end_date,
            full_sync=False
        )
        
        results["total_found"] = sync_result.get("total_parsed", 0)
        results["total_saved"] = sync_result.get("saved_count", 0)
        results["details"] = {
            "api_calls": sync_result.get("api_calls", 0),
            "rate_limit_hits": sync_result.get("rate_limit_hits", 0),
            "retries": sync_result.get("retries", 0)
        }
        results["status"] = "success"
        
    except Exception as e:
        results["status"] = "error"
        results["errors"].append(str(e))
        import traceback
        results["traceback"] = traceback.format_exc()
    
    finally:
        end_time = datetime.now()
        results["end_time"] = end_time.isoformat()
        results["duration_seconds"] = (end_time - start_time).total_seconds()
    
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return results

if __name__ == "__main__":
    test_nvd_full()
```

### Сценарии тестирования

1. **Минимальный тест**: `python tests/test_nvd_minimal.py`
   - Парсинг за 1 день
   - Ожидается: 1-5 CVE
   - Время: < 10 секунд

2. **Полный тест**: `python tests/test_nvd_full.py`
   - Парсинг за 30 дней
   - Ожидается: 100-500 CVE
   - Время: 1-5 минут

3. **Тест ошибок**: Отключить интернет / неверный API ключ
   - Ожидается: корректная обработка ошибок

4. **Тест дубликатов**: Запустить дважды
   - Ожидается: второй запуск пропустит дубликаты

5. **Тест производительности**: Замерить время парсинга
   - Ожидается: < 5 минут для месяца

### Интеграция

#### Запуск как отдельный скрипт

**Файл**: `scripts/parsers/run_nvd.py`

```python
#!/usr/bin/env python3
"""Запуск NVD парсера как отдельный скрипт"""
import sys
import os
import json
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from services.nvd_integration_service import NVDIntegrationService
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config

def main():
    """Основная функция запуска NVD парсера"""
    # Параметры из аргументов или переменных окружения
    days = int(os.getenv("NVD_DAYS", "7"))
    api_key = os.getenv("NVD_API_KEY", Config.NVD_API_KEY)
    
    start_time = datetime.now()
    results = {
        "parser": "NVD",
        "status": "running",
        "total_found": 0,
        "total_saved": 0,
        "duplicates_skipped": 0,
        "errors": [],
        "start_time": start_time.isoformat()
    }
    
    try:
        db_manager = DatabaseManager()
        vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        
        nvd_service = NVDIntegrationService(vuln_repo, api_key=api_key)
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        sync_result = nvd_service.sync_vulnerabilities(
            start_date=start_date,
            end_date=end_date,
            full_sync=False
        )
        
        results["total_found"] = sync_result.get("total_parsed", 0)
        results["total_saved"] = sync_result.get("saved_count", 0)
        results["status"] = "success"
        
    except Exception as e:
        results["status"] = "error"
        results["errors"].append(str(e))
    
    finally:
        end_time = datetime.now()
        results["end_time"] = end_time.isoformat()
        results["duration_seconds"] = (end_time - start_time).total_seconds()
        print(json.dumps(results, indent=2, ensure_ascii=False))
    
    return 0 if results["status"] == "success" else 1

if __name__ == "__main__":
    sys.exit(main())
```

**Запуск**:
```bash
# С переменными окружения
NVD_DAYS=7 NVD_API_KEY=your-key python scripts/parsers/run_nvd.py

# Или через .env файл
source .env.nvd && python scripts/parsers/run_nvd.py
```

#### Docker контейнер

**Файл**: `services/parsers/Dockerfile.nvd`

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Установка зависимостей
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Копируем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код
COPY config.py .
COPY models/ ./models/
COPY services/nvd_integration_service.py ./services/
COPY services/nvd_scheduler.py ./services/
COPY scripts/parsers/run_nvd.py ./scripts/parsers/

# Создаем директорию для логов
RUN mkdir -p /app/logs

# Переменные окружения
ENV PYTHONUNBUFFERED=1
ENV APP_ROLE=parsers

# Запуск
CMD ["python", "scripts/parsers/run_nvd.py"]
```

**Файл**: `services/parsers/docker-compose.nvd.yml`

```yaml
version: '3.8'

services:
  nvd-parser:
    build:
      context: ../..
      dockerfile: services/parsers/Dockerfile.nvd
    container_name: nvd-parser
    environment:
      - NVD_API_KEY=${NVD_API_KEY}
      - NVD_DAYS=${NVD_DAYS:-7}
      - DB_HOST=${DB_HOST:-10.0.88.11}
      - DB_PORT=${DB_PORT:-5432}
      - DB_NAME=${DB_NAME:-vuln_db}
      - DB_USER=${DB_USER:-admin}
      - DB_PASSWORD=${DB_PASSWORD:-123}
    volumes:
      - ../../logs:/app/logs
    restart: unless-stopped
    networks:
      - vuln-network

networks:
  vuln-network:
    external: true
```

**Запуск**:
```bash
cd services/parsers
docker compose -f docker-compose.nvd.yml up -d
```

### Развёртывание на сервере

#### Systemd сервис

**Файл**: `/etc/systemd/system/nvd-parser.service`

```ini
[Unit]
Description=NVD Vulnerability Parser
After=network.target postgresql.service

[Service]
Type=oneshot
User=vuln-parser
WorkingDirectory=/opt/vulnerability_manager
Environment="NVD_API_KEY=6e96c1b9-a283-4ce3-b83e-bb162d9b4323"
Environment="NVD_DAYS=7"
Environment="DB_HOST=10.0.88.11"
Environment="DB_PORT=5432"
Environment="DB_NAME=vuln_db"
Environment="DB_USER=admin"
Environment="DB_PASSWORD=123"
ExecStart=/usr/bin/python3 /opt/vulnerability_manager/scripts/parsers/run_nvd.py
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**Установка**:
```bash
sudo cp services/parsers/nvd-parser.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable nvd-parser.service
```

#### Cron расписание

**Файл**: `/etc/cron.d/nvd-parser`

```cron
# NVD парсер - запуск каждый день в 02:00
0 2 * * * vuln-parser /usr/bin/python3 /opt/vulnerability_manager/scripts/parsers/run_nvd.py >> /var/log/nvd-parser.log 2>&1
```

**Установка**:
```bash
sudo cp services/parsers/nvd-parser.cron /etc/cron.d/nvd-parser
sudo chmod 644 /etc/cron.d/nvd-parser
```

#### Мониторинг

**Скрипт проверки**: `scripts/monitoring/check_nvd_parser.sh`

```bash
#!/bin/bash
# Проверка работы NVD парсера

LOG_FILE="/var/log/nvd-parser.log"
LAST_RUN=$(tail -1 "$LOG_FILE" | grep -o '"end_time":"[^"]*"' | cut -d'"' -f4)

if [ -z "$LAST_RUN" ]; then
    echo "ERROR: NVD parser not running"
    exit 1
fi

echo "OK: NVD parser last run: $LAST_RUN"
exit 0
```

---

## 2️⃣ Red Hat CVE

### Описание

**Файл**: `services/redhat_cve_importer.py`  
**Класс**: `RedHatCVEImporter`  
**Тип**: API парсер  
**Источник**: https://access.redhat.com/

### Тестирование

**Файл**: `tests/test_redhat.py`

```python
#!/usr/bin/env python3
"""Тест Red Hat парсера"""
import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.redhat_cve_importer import RedHatCVEImporter
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config

def test_redhat():
    """Тест парсинга Red Hat CVE"""
    start_time = datetime.now()
    results = {
        "parser": "RedHat",
        "status": "running",
        "total_found": 0,
        "total_saved": 0,
        "duplicates_skipped": 0,
        "errors": [],
        "start_time": start_time.isoformat()
    }
    
    try:
        db_manager = DatabaseManager()
        vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        
        redhat_importer = RedHatCVEImporter(vuln_repo)
        
        # Парсинг с лимитом
        limit = int(os.getenv("REDHAT_LIMIT", "10"))
        import_result = redhat_importer.import_recent_cves(limit=limit)
        
        results["total_found"] = import_result.get("parsed", 0)
        results["total_saved"] = import_result.get("saved", 0)
        results["status"] = "success"
        
    except Exception as e:
        results["status"] = "error"
        results["errors"].append(str(e))
    
    finally:
        end_time = datetime.now()
        results["end_time"] = end_time.isoformat()
        results["duration_seconds"] = (end_time - start_time).total_seconds()
        print(json.dumps(results, indent=2, ensure_ascii=False))
    
    return results

if __name__ == "__main__":
    test_redhat()
```

**Запуск**:
```bash
REDHAT_LIMIT=10 python tests/test_redhat.py
```

### Интеграция

**Файл**: `scripts/parsers/run_redhat.py`

```python
#!/usr/bin/env python3
"""Запуск Red Hat парсера"""
import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from services.redhat_cve_importer import RedHatCVEImporter
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config

def main():
    limit = int(os.getenv("REDHAT_LIMIT", "50"))
    
    start_time = datetime.now()
    results = {
        "parser": "RedHat",
        "status": "running",
        "total_found": 0,
        "total_saved": 0,
        "errors": [],
        "start_time": start_time.isoformat()
    }
    
    try:
        db_manager = DatabaseManager()
        vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        redhat_importer = RedHatCVEImporter(vuln_repo)
        
        import_result = redhat_importer.import_recent_cves(limit=limit)
        results["total_found"] = import_result.get("parsed", 0)
        results["total_saved"] = import_result.get("saved", 0)
        results["status"] = "success"
        
    except Exception as e:
        results["status"] = "error"
        results["errors"].append(str(e))
    
    finally:
        end_time = datetime.now()
        results["end_time"] = end_time.isoformat()
        results["duration_seconds"] = (end_time - start_time).total_seconds()
        print(json.dumps(results, indent=2, ensure_ascii=False))
    
    return 0 if results["status"] == "success" else 1

if __name__ == "__main__":
    sys.exit(main())
```

---

## 3️⃣ OSV (Open Source Vulnerability)

### Описание

**Файл**: `services/osv_api_parser.py`  
**Класс**: `OSVAPIParser`  
**Тип**: API парсер  
**Источник**: https://osv.dev/

### Тестирование

**Файл**: `tests/test_osv.py`

```python
#!/usr/bin/env python3
"""Тест OSV парсера"""
import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.osv_api_parser import OSVAPIParser
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config

def test_osv():
    """Тест парсинга OSV"""
    start_time = datetime.now()
    results = {
        "parser": "OSV",
        "status": "running",
        "total_found": 0,
        "total_saved": 0,
        "errors": [],
        "start_time": start_time.isoformat()
    }
    
    try:
        osv_parser = OSVAPIParser()
        limit = int(os.getenv("OSV_LIMIT", "10"))
        
        parse_result = osv_parser.parse_vulnerabilities(limit=limit)
        
        results["total_found"] = parse_result.get("parsed", 0)
        results["total_saved"] = parse_result.get("saved", 0)
        results["status"] = "success"
        
    except Exception as e:
        results["status"] = "error"
        results["errors"].append(str(e))
    
    finally:
        end_time = datetime.now()
        results["end_time"] = end_time.isoformat()
        results["duration_seconds"] = (end_time - start_time).total_seconds()
        print(json.dumps(results, indent=2, ensure_ascii=False))
    
    return results

if __name__ == "__main__":
    test_osv()
```

---

## 4️⃣ Ubuntu CVE

### Описание

**Файл**: `services/html_vulnerability_parser.py`  
**Класс**: `HTMLVulnerabilityParser`  
**Тип**: HTML/API парсер  
**Источник**: https://ubuntu.com/security/

### Тестирование

**Файл**: `tests/test_ubuntu.py`

```python
#!/usr/bin/env python3
"""Тест Ubuntu парсера"""
import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.html_vulnerability_parser import HTMLVulnerabilityParser
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config

def test_ubuntu():
    """Тест парсинга Ubuntu CVE"""
    start_time = datetime.now()
    results = {
        "parser": "Ubuntu",
        "status": "running",
        "total_found": 0,
        "total_saved": 0,
        "errors": [],
        "start_time": start_time.isoformat()
    }
    
    try:
        html_parser = HTMLVulnerabilityParser()
        limit = int(os.getenv("UBUNTU_LIMIT", "10"))
        
        vulnerabilities = html_parser.parse_source("ubuntu", limit=limit)
        
        # Сохранение в БД
        db_manager = DatabaseManager()
        vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        
        saved_count = 0
        for vuln_data in vulnerabilities:
            try:
                vulnerability = html_parser.create_vulnerability_object(vuln_data)
                if vuln_repo.save_vulnerability(vulnerability):
                    saved_count += 1
            except Exception as e:
                results["errors"].append(f"Error saving {vuln_data.get('cve_id')}: {str(e)}")
        
        results["total_found"] = len(vulnerabilities)
        results["total_saved"] = saved_count
        results["status"] = "success"
        
    except Exception as e:
        results["status"] = "error"
        results["errors"].append(str(e))
    
    finally:
        end_time = datetime.now()
        results["end_time"] = end_time.isoformat()
        results["duration_seconds"] = (end_time - start_time).total_seconds()
        print(json.dumps(results, indent=2, ensure_ascii=False))
    
    return results

if __name__ == "__main__":
    test_ubuntu()
```

---

## 5️⃣ Debian CVE

### Описание

**Файл**: `services/html_vulnerability_parser.py`  
**Класс**: `HTMLVulnerabilityParser`  
**Тип**: HTML/API парсер  
**Источник**: https://security-tracker.debian.org/

### Тестирование

Аналогично Ubuntu, но с `source_name="debian"`

---

## 6️⃣ CVE.org

### Описание

**Файл**: `services/cve_org_integration_service.py`  
**Класс**: `CVEOrgIntegrationService`  
**Тип**: JSON парсер  
**Источник**: https://www.cve.org/

### Тестирование

**Файл**: `tests/test_cve_org.py`

```python
#!/usr/bin/env python3
"""Тест CVE.org парсера"""
import sys
import os
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.cve_org_integration_service import CVEOrgIntegrationService
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config

def test_cve_org():
    """Тест парсинга CVE.org"""
    start_time = datetime.now()
    results = {
        "parser": "CVE.org",
        "status": "running",
        "total_found": 0,
        "total_saved": 0,
        "errors": [],
        "start_time": start_time.isoformat()
    }
    
    try:
        db_manager = DatabaseManager()
        vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        
        cve_org_service = CVEOrgIntegrationService(vuln_repo, storage_path="/tmp/cve_data")
        
        # Синхронизация (можно ограничить количество)
        batch_size = int(os.getenv("CVE_ORG_BATCH_SIZE", "1000"))
        sync_result = cve_org_service.sync_cves(batch_size=batch_size)
        
        results["total_found"] = sync_result.get("total_parsed", 0)
        results["total_saved"] = sync_result.get("total_saved", 0)
        results["status"] = "success"
        
    except Exception as e:
        results["status"] = "error"
        results["errors"].append(str(e))
    
    finally:
        end_time = datetime.now()
        results["end_time"] = end_time.isoformat()
        results["duration_seconds"] = (end_time - start_time).total_seconds()
        print(json.dumps(results, indent=2, ensure_ascii=False))
    
    return results

if __name__ == "__main__":
    test_cve_org()
```

---

## 📋 Схема поэтапной интеграции

### Этап 1: NVD (базовый парсер)

1. **Тестирование**:
   ```bash
   python tests/test_nvd_minimal.py
   ```

2. **Интеграция**:
   ```bash
   # Создать .env.nvd
   echo "NVD_API_KEY=6e96c1b9-a283-4ce3-b83e-bb162d9b4323" > .env.nvd
   echo "NVD_DAYS=7" >> .env.nvd
   
   # Запустить
   source .env.nvd && python scripts/parsers/run_nvd.py
   ```

3. **Проверка**:
   ```sql
   SELECT COUNT(*) FROM turn WHERE source = 'NVD';
   ```

4. **Развёртывание**:
   ```bash
   # На VM 10.0.88.23
   sudo systemctl start nvd-parser.service
   sudo systemctl status nvd-parser.service
   ```

### Этап 2: Red Hat

1. **Тестирование**: `python tests/test_redhat.py`
2. **Интеграция**: `python scripts/parsers/run_redhat.py`
3. **Проверка**: `SELECT COUNT(*) FROM turn WHERE source = 'RedHat';`

### Этап 3: OSV

1. **Тестирование**: `python tests/test_osv.py`
2. **Интеграция**: `python scripts/parsers/run_osv.py`
3. **Проверка**: `SELECT COUNT(*) FROM turn WHERE source = 'OSV';`

### Этап 4: Ubuntu/Debian

1. **Тестирование**: `python tests/test_ubuntu.py` и `python tests/test_debian.py`
2. **Интеграция**: `python scripts/parsers/run_html.py --sources ubuntu,debian`
3. **Проверка**: `SELECT COUNT(*) FROM turn WHERE source IN ('Ubuntu', 'Debian');`

### Этап 5: CVE.org

1. **Тестирование**: `python tests/test_cve_org.py`
2. **Интеграция**: `python scripts/parsers/run_cve_org.py`
3. **Проверка**: `SELECT COUNT(*) FROM turn WHERE source = 'Cve_json5';`

---

## 🔍 Мониторинг и безопасность

### Мониторинг

1. **Логи**: `/var/log/vulnerability-parsers.log`
2. **Метрики**: Количество CVE в БД по источникам
3. **Алерты**: При отсутствии новых CVE > 24 часов

### Безопасность

1. **Изоляция**: Каждый парсер в отдельном контейнере
2. **Ограничение ресурсов**: CPU, память, сеть
3. **Ротация логов**: logrotate
4. **Мониторинг ошибок**: Sentry / ELK

---

## 📝 Заключение

Это руководство описывает полный процесс тестирования, интеграции и развёртывания каждого парсера отдельно. Следуйте схеме поэтапной интеграции для безопасного развёртывания.

