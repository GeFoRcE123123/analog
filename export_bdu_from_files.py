#!/usr/bin/env python3
"""
Экспорт БДУ в JSON из файловых данных (без БД)
Демонстрация работы экспорта с файловым хранилищем
"""
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# Добавляем корневую директорию в путь
sys.path.insert(0, str(Path(__file__).parent))

print("=" * 70)
print("ЭКСПОРТ БДУ В JSON - ИЗ ФАЙЛОВЫХ ДАННЫХ")
print("=" * 70)

# Импорт только ExportService (не нужна БД)
from services.export_service import ExportService

# Простой класс для имитации Vulnerability из файлов
class FileVulnerability:
    """Упрощенная модель уязвимости из файла"""
    def __init__(self, data: dict):
        self.id = data.get("id")
        self.title = data.get("title", "")
        self.description = data.get("description", "")
        self.severity = data.get("severity", "")
        self.status = data.get("status", "")
        self.risk_level = data.get("risk_level", "")
        self.category = data.get("category", "")
        self.cve_id = data.get("cve_id")
        self.bdu_id = data.get("bdu_id")
        self.bdu_name = data.get("bdu_name")
        self.vendor = data.get("vendor", "")
        self.product_name = data.get("product_name", "")
        self.affected_versions = data.get("affected_versions", "")
        self.vul_class = data.get("vul_class", "")
        self.environment = data.get("environment", [])
        self.platform = data.get("platform", "")
        self.identify_date = None
        if data.get("identify_date"):
            try:
                from datetime import datetime as dt
                self.identify_date = dt.strptime(data["identify_date"], "%Y-%m-%d")
            except:
                pass
        self.bdu_severity = data.get("bdu_severity", "")
        self.cvss2_vector = data.get("cvss2_vector", "")
        self.cvss3_vector = data.get("cvss3_vector", "")
        self.cvss_score = data.get("cvss_score")
        self.solution = data.get("solution", "")
        self.vul_status = data.get("vul_status", "")
        self.vul_state = data.get("vul_state", "")
        self.vul_elimination = data.get("vul_elimination", "")
        self.vul_incident = data.get("vul_incident", "")
        self.exploit_status = data.get("exploit_status", "")
        self.sources = data.get("sources", "")
        self.references = data.get("references", [])
        self.cwes = data.get("cwes", [])
        self.weaknesses = data.get("weaknesses", [])
    
    def get_source_type(self):
        return "BDU" if self.bdu_id else "CVE"
    
    def get_cwe_ids(self):
        ids = []
        for cwe in self.cwes:
            if isinstance(cwe, dict):
                identifier = cwe.get("identifier")
                if identifier:
                    ids.append(identifier)
        return ids
    
    def get_highest_cvss_score(self):
        return self.cvss_score
    
    def to_bdu_dict(self):
        return {
            "bdu_id": self.bdu_id,
            "bdu_name": self.bdu_name,
            "vendor": self.vendor,
            "product": self.product_name,
            "severity": self.bdu_severity,
            "status": self.vul_status
        }

try:
    # Загрузка данных из файла
    print("\n[1/4] Загрузка данных из файлов...")
    data_file = Path("osint_redi/demo_data/vulnerabilities.json")
    
    if not data_file.exists():
        print(f"   ⚠️  Файл не найден: {data_file}")
        print("   💡 Создаю демонстрационные данные...")
        
        # Запускаем скрипт создания данных
        import subprocess
        result = subprocess.run(
            [sys.executable, "create_demo_data.py"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(result.stdout)
        else:
            print(f"   ❌ Ошибка создания данных: {result.stderr}")
            sys.exit(1)
    
    with open(data_file, "r", encoding="utf-8") as f:
        vuln_data = json.load(f)
    
    # Преобразование в объекты FileVulnerability
    vulnerabilities = [FileVulnerability(v) for v in vuln_data]
    total_count = len(vulnerabilities)
    bdu_count = sum(1 for v in vulnerabilities if v.bdu_id)
    
    print(f"   ✅ Загружено уязвимостей: {total_count}")
    print(f"   📊 С BDU ID: {bdu_count}")
    print(f"   📊 Без BDU ID: {total_count - bdu_count}")
    
    # Инициализация сервиса экспорта
    print("\n[2/4] Инициализация сервиса экспорта...")
    export_service = ExportService()
    print("   ✅ Сервис готов")
    
    # Экспорт только БДУ уязвимостей
    print("\n[3/4] Экспорт БДУ уязвимостей (include_all=False)...")
    filename_bdu = export_service.export_bdu_json(
        vulnerabilities,
        output_dir="osint_redi",
        filename_prefix="bdu_export",
        include_all=False
    )
    print(f"   ✅ Файл сохранен: {filename_bdu}")
    
    # Экспорт всех уязвимостей
    print("\n[4/4] Экспорт всех уязвимостей (include_all=True)...")
    filename_all = export_service.export_bdu_json(
        vulnerabilities,
        output_dir="osint_redi",
        filename_prefix="bdu_export_all",
        include_all=True
    )
    print(f"   ✅ Файл сохранен: {filename_all}")
    
    # Анализ созданных файлов
    print("\n" + "=" * 70)
    print("АНАЛИЗ СОЗДАННЫХ ФАЙЛОВ:")
    print("=" * 70)
    
    for filepath_str in [filename_bdu, filename_all]:
        filepath = Path(filepath_str)
        if filepath.exists():
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            print(f"\n📄 {filepath.name}:")
            print(f"   Размер: {filepath.stat().st_size / 1024:.2f} KB")
            print(f"   Записей: {data.get('count', 0)}")
            print(f"   Экспортировано: {data.get('exported_at', 'N/A')}")
            print(f"   Include all: {data.get('include_all', False)}")
            
            # Показываем структуру первой записи
            if data.get('vulnerabilities'):
                first = data['vulnerabilities'][0]
                if 'bdu_excel_row' in first:
                    cols = list(first['bdu_excel_row'].keys())
                    print(f"   Колонок в bdu_excel_row: {len(cols)}")
                    print(f"   Первые 5 колонок: {', '.join(cols[:5])}")
                    
                    # Показываем пример данных
                    print(f"\n   Пример данных первой записи:")
                    example_row = {}
                    for i, (k, v) in enumerate(list(first['bdu_excel_row'].items())[:5]):
                        val_str = str(v)
                        example_row[k] = val_str[:50] + "..." if len(val_str) > 50 else val_str
                    print(json.dumps(example_row, ensure_ascii=False, indent=6))
        else:
            print(f"\n❌ Файл не найден: {filepath}")
    
    print("\n" + "=" * 70)
    print("✅ ЭКСПОРТ ЗАВЕРШЕН УСПЕШНО!")
    print("=" * 70)
    print(f"\n📁 Файлы сохранены в: {Path(filename_bdu).parent.absolute()}")
    print(f"\n📋 Созданные файлы:")
    print(f"   1. {Path(filename_bdu).name} - только БДУ уязвимости")
    print(f"   2. {Path(filename_all).name} - все уязвимости")
    
except Exception as e:
    print(f"\n❌ Ошибка: {e}")
    import traceback
    print("\nДетали ошибки:")
    traceback.print_exc()
    sys.exit(1)
