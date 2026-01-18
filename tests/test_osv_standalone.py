#!/usr/bin/env python3
"""
Тест OSV парсера в изоляции
Минимальный тест: 1-10 CVE
"""
import sys
import os
import json
from datetime import datetime

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from services.osv_api_parser import OSVAPIParser
from models.database import DatabaseManager
from models.legacy_repositories import LegacyVulnerabilityRepository
from services.html_vulnerability_parser import HTMLVulnerabilityParser

def test_osv_minimal():
    """Минимальный тест OSV парсера - 1-10 CVE"""
    start_time = datetime.now()
    results = {
        "parser": "OSV",
        "status": "running",
        "total_found": 0,
        "total_saved": 0,
        "duplicates_skipped": 0,
        "errors": [],
        "warnings": [],
        "start_time": start_time.isoformat()
    }
    
    try:
        print("🔍 Инициализация OSV парсера...")
        
        # Создание парсера
        osv_parser = OSVAPIParser()
        
        # Парсинг с лимитом
        limit = int(os.getenv("OSV_LIMIT", "10"))
        print(f"📥 Парсинг {limit} CVE из OSV.dev...")
        
        vulnerabilities = osv_parser.query_vulnerabilities(limit=limit)
        
        # Сохранение в БД
        db_manager = DatabaseManager()
        vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)
        html_parser = HTMLVulnerabilityParser()
        
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
    test_osv_minimal()

