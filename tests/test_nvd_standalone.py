#!/usr/bin/env python3
"""
Тест NVD парсера в изоляции
Минимальный тест: 1-5 CVE за последний день
"""
import sys
import os
import json
from datetime import datetime, timedelta

# Добавляем путь к проекту
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from services.nvd_integration_service import NVDIntegrationService
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config

def test_nvd_minimal():
    """Минимальный тест NVD парсера - 1-5 CVE за последний день"""
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
        print("🔍 Инициализация NVD парсера...")
        
        # Инициализация БД
        db_manager = DatabaseManager()
        vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        
        # API ключ
        api_key = Config.NVD_API_KEY
        if not api_key:
            results["status"] = "error"
            results["errors"].append("NVD_API_KEY не установлен в config.py")
            return results
        
        print(f"✅ API ключ: {api_key[:10]}...")
        
        # Создание парсера
        nvd_service = NVDIntegrationService(vuln_repo, api_key=api_key)
        
        # Парсинг за последний день
        print(f"📅 Парсинг CVE за последний день...")
        
        sync_result = nvd_service.incremental_sync(days=1)
        
        results["total_found"] = sync_result.get("total_processed", 0)
        results["total_saved"] = sync_result.get("saved_count", sync_result.get("total_processed", 0))
        results["details"] = {
            "api_calls": sync_result.get("api_calls", 0),
            "rate_limit_hits": sync_result.get("rate_limit_hits", 0),
            "retries": sync_result.get("retries", 0)
        }
        results["status"] = "success"
        
        print(f"✅ Найдено: {results['total_found']}, Сохранено: {results['total_saved']}")
        
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
    
    print("\n" + "="*50)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    print("="*50)
    
    return results

if __name__ == "__main__":
    test_nvd_minimal()

