#!/usr/bin/env python3
"""
Запуск NVD парсера как отдельный скрипт
Использование:
    python scripts/parsers/run_nvd.py
    NVD_DAYS=7 python scripts/parsers/run_nvd.py
"""
import sys
import os
import json
from datetime import datetime, timedelta

# Добавляем путь к проекту
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from services.nvd_integration_service import NVDIntegrationService
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config

def main():
    """Основная функция запуска NVD парсера"""
    # Параметры из переменных окружения
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
        "start_time": start_time.isoformat(),
        "config": {
            "days": days,
            "api_key_set": bool(api_key)
        }
    }
    
    try:
        print(f"🚀 Запуск NVD парсера (дней: {days})...")
        
        db_manager = DatabaseManager()
        vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        
        if not api_key:
            raise ValueError("NVD_API_KEY не установлен")
        
        nvd_service = NVDIntegrationService(vuln_repo, api_key=api_key)
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        print(f"📅 Парсинг CVE с {start_date.date()} по {end_date.date()}...")
        
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
        
        print(f"✅ Успешно: найдено {results['total_found']}, сохранено {results['total_saved']}")
        
    except Exception as e:
        results["status"] = "error"
        results["errors"].append(str(e))
        import traceback
        results["traceback"] = traceback.format_exc()
        print(f"❌ Ошибка: {e}")
    
    finally:
        end_time = datetime.now()
        results["end_time"] = end_time.isoformat()
        results["duration_seconds"] = round((end_time - start_time).total_seconds(), 2)
        print(json.dumps(results, indent=2, ensure_ascii=False))
    
    return 0 if results["status"] == "success" else 1

if __name__ == "__main__":
    sys.exit(main())

