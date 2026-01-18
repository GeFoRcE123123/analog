#!/usr/bin/env python3
"""
Тест Red Hat парсера в изоляции
Минимальный тест: 1-10 CVE
"""
import sys
import os
import json
from datetime import datetime

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from services.redhat_cve_importer import RedHatCVEImporter
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config

def test_redhat_minimal():
    """Минимальный тест Red Hat парсера - 1-10 CVE"""
    start_time = datetime.now()
    results = {
        "parser": "RedHat",
        "status": "running",
        "total_found": 0,
        "total_saved": 0,
        "duplicates_skipped": 0,
        "errors": [],
        "warnings": [],
        "start_time": start_time.isoformat()
    }
    
    try:
        print("🔍 Инициализация Red Hat парсера...")
        
        # Инициализация БД
        db_manager = DatabaseManager()
        vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        
        # Создание парсера
        redhat_importer = RedHatCVEImporter()
        
        # Парсинг за последние дни
        days = int(os.getenv("REDHAT_DAYS", "7"))
        print(f"📥 Парсинг CVE из Red Hat за последние {days} дней...")
        
        import_result = redhat_importer.import_recent_cves(days=days)
        
        results["total_found"] = import_result.get("total_fetched", 0)
        results["total_saved"] = import_result.get("successfully_saved", 0)
        results["duplicates_skipped"] = import_result.get("skipped", 0)
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
    test_redhat_minimal()

