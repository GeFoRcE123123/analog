#!/usr/bin/env python3
"""
Запуск OSV парсера как отдельный скрипт
Использование:
    python scripts/parsers/run_osv.py
    OSV_LIMIT=50 python scripts/parsers/run_osv.py
"""
import sys
import os
import json
from datetime import datetime

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

from services.osv_api_parser import OSVAPIParser
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from services.html_vulnerability_parser import HTMLVulnerabilityParser

def main():
    """Основная функция запуска OSV парсера"""
    limit = int(os.getenv("OSV_LIMIT", "50"))
    
    start_time = datetime.now()
    results = {
        "parser": "OSV",
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
        print(f"🚀 Запуск OSV парсера (лимит: {limit})...")
        
        osv_parser = OSVAPIParser()
        
        print(f"📥 Парсинг {limit} CVE из OSV.dev...")
        
        parse_result = osv_parser.parse_vulnerabilities(limit=limit)
        
        # Сохранение в БД
        db_manager = DatabaseManager()
        vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        html_parser = HTMLVulnerabilityParser()
        
        saved_count = 0
        for vuln_data in parse_result.get("vulnerabilities", []):
            try:
                vulnerability = html_parser.create_vulnerability_object(vuln_data)
                if vuln_repo.save_vulnerability(vulnerability):
                    saved_count += 1
            except Exception as e:
                results["errors"].append(f"Error saving {vuln_data.get('cve_id')}: {str(e)}")
        
        results["total_found"] = parse_result.get("parsed", 0)
        results["total_saved"] = saved_count
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

