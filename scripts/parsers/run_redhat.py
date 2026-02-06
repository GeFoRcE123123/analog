#!/usr/bin/env python3
"""
Запуск Red Hat парсера как отдельный скрипт
Использование:
    python scripts/parsers/run_redhat.py
    REDHAT_LIMIT=50 python scripts/parsers/run_redhat.py
"""
import sys
import os
import json
from datetime import datetime

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from services.redhat_cve_importer import RedHatCVEImporter
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from config import Config

def main():
    """Основная функция запуска Red Hat парсера"""
    limit = int(os.getenv("REDHAT_LIMIT", "50"))
    
    start_time = datetime.now()
    results = {
        "parser": "RedHat",
        "status": "running",
        "total_found": 0,
        "total_saved": 0,
        "duplicates_skipped": 0,
        "errors": [],
        "start_time": start_time.isoformat(),
        "config": {
            "limit": limit
        }
    }
    
    try:
        print(f"🚀 Запуск Red Hat парсера (лимит: {limit})...")
        
        db_manager = DatabaseManager()
        vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        redhat_importer = RedHatCVEImporter()
        
        print(f"📥 Парсинг {limit} последних CVE из Red Hat...")
        
        import_result = redhat_importer.import_recent_cves(limit=limit)
        
        results["total_found"] = import_result.get("parsed", 0)
        results["total_saved"] = import_result.get("saved", 0)
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

