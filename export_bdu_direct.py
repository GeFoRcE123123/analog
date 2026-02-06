#!/usr/bin/env python3
"""
Прямой экспорт БДУ в JSON через Python код
Демонстрация работы экспорта без веб-интерфейса
"""
import sys
import json
from pathlib import Path
from datetime import datetime

# Добавляем корневую директорию в путь
sys.path.insert(0, str(Path(__file__).parent))

print("=" * 70)
print("ЭКСПОРТ БДУ В JSON - ПРЯМОЙ ВЫЗОВ ИЗ PYTHON")
print("=" * 70)

try:
    # Импорт сервисов
    print("\n[1/5] Импорт сервисов...")
    from services.export_service import ExportService
    from services.vulnerability_service import VulnerabilityService
    print("   ✅ Сервисы импортированы")
    
    # Инициализация сервисов
    print("\n[2/5] Инициализация сервисов...")
    try:
        vuln_service = VulnerabilityService()
        export_service = ExportService()
        print("   ✅ Сервисы инициализированы")
        db_available = True
    except Exception as db_error:
        print(f"   ⚠️  База данных недоступна: {db_error}")
        print("   💡 Продолжаю с демонстрацией структуры...")
        export_service = ExportService()
        db_available = False
    
    # Получение всех уязвимостей
    if not db_available:
        vulnerabilities = []
        total_count = 0
        bdu_count = 0
    else:
        print("\n[3/5] Загрузка уязвимостей из базы данных...")
        vulnerabilities = vuln_service.get_all_vulnerabilities_unlimited()
        total_count = len(vulnerabilities)
        bdu_count = sum(1 for v in vulnerabilities if v.bdu_id)
        
        print(f"   📊 Всего уязвимостей: {total_count}")
        print(f"   📊 С BDU ID: {bdu_count}")
        print(f"   📊 Без BDU ID: {total_count - bdu_count}")
    
    if total_count == 0 or not db_available:
        print("\n   ⚠️  База данных пуста или недоступна")
        print("   💡 Создаю демонстрационный пример структуры...")
        
        # Демонстрация структуры без реальных данных
        demo_structure = {
            "exported_at": datetime.now().isoformat(),
            "count": 0,
            "include_all": False,
            "vulnerabilities": [],
            "demo_structure": {
                "example_vulnerability": {
                    "id": 123,
                    "title": "Пример уязвимости",
                    "description": "Описание уязвимости",
                    "severity": "high",
                    "status": "open",
                    "cve_id": "CVE-2023-0437",
                    "bdu_id": "BDU:2024-02893",
                    "bdu_excel_row": {
                        "Статус": "True",
                        "Идентификатор": "True",
                        "Наименование уязвимости": "Уязвимость функции bson_utf8_validate() драйвера MongoDB C-Driver",
                        "Идентификаторы других систем описаний уязвимости": "CVE-2023-0437",
                        "Описание уязвимости": "Уязвимость связана с циклом с недостижимым условием выхода...",
                        "Вендор ПО": "MongoDB Inc.",
                        "Название ПО": "MongoDB C-Driver",
                        "Версия ПО": "1.24.0",
                        "Класс уязвимости": "Уязвимость кода",
                        "Наименование ОС и тип аппаратной платформы": "Linux, Windows",
                        "Дата выявления": "2024-01-12 00:00:00",
                        "Уровень опасности уязвимости": "Высокий",
                        "CVSS 2.0": "AV:N/AC:L/Au:N/C:N/I:N/A:C",
                        "CVSS 3.1": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                        "CVSS 4.0": "",
                        "Возможные меры по устранению": "Обновление до версии 1.24.1",
                        "Статус уязвимости": "Опубликована",
                        "Информация об устранении": "Уязвимость устранена",
                        "Дата устранения": "",
                        "Наличие эксплойта": "Подтверждена производителем",
                        "Способ устранения": "Обновление программного обеспечения",
                        "Способ эксплуатации": "",
                        "Ссылки на источники": "https://nvd.nist.gov/vuln/detail/CVE-2023-0437",
                        "cnt_arch": "",
                        "Описание ошибки CWE": "CWE-400 Uncontrolled Resource Consumption",
                        "Тип ошибки CWE": "CWE-400"
                    }
                }
            }
        }
        
        # Сохранение демо-структуры
        output_dir = Path("osint_redi")
        output_dir.mkdir(exist_ok=True)
        demo_file = output_dir / "bdu_export_demo_structure.json"
        
        with open(demo_file, "w", encoding="utf-8") as f:
            json.dump(demo_structure, f, ensure_ascii=False, indent=2)
        
        print(f"\n   ✅ Демонстрационная структура сохранена: {demo_file}")
        print("\n" + "=" * 70)
        print("СТРУКТУРА ЭКСПОРТА (26 колонок БДУ):")
        print("=" * 70)
        print(json.dumps(demo_structure["demo_structure"]["example_vulnerability"]["bdu_excel_row"], 
                        ensure_ascii=False, indent=2))
        sys.exit(0)
    
    if total_count > 0:
        # Экспорт только БДУ уязвимостей
        print("\n[4/5] Экспорт БДУ уязвимостей (include_all=False)...")
        filename_bdu = export_service.export_bdu_json(
            vulnerabilities,
            output_dir="osint_redi",
            filename_prefix="bdu_export",
            include_all=False
        )
        print(f"   ✅ Файл сохранен: {filename_bdu}")
        
        # Экспорт всех уязвимостей
        print("\n[5/5] Экспорт всех уязвимостей (include_all=True)...")
        filename_all = export_service.export_bdu_json(
            vulnerabilities,
            output_dir="osint_redi",
            filename_prefix="bdu_export_all",
            include_all=True
        )
        print(f"   ✅ Файл сохранен: {filename_all}")
        filenames_to_check = [filename_bdu, filename_all]
    else:
        filenames_to_check = [str(Path("osint_redi") / "bdu_export_demo_structure.json")]
    
    # Анализ созданных файлов
    print("\n" + "=" * 70)
    print("АНАЛИЗ СОЗДАННЫХ ФАЙЛОВ:")
    print("=" * 70)
    
    for filepath_str in filenames_to_check:
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
                    example_row = {k: str(v)[:50] + "..." if len(str(v)) > 50 else v 
                                  for k, v in list(first['bdu_excel_row'].items())[:5]}
                    print(json.dumps(example_row, ensure_ascii=False, indent=6))
        else:
            print(f"\n❌ Файл не найден: {filepath}")
    
    print("\n" + "=" * 70)
    print("✅ ЭКСПОРТ ЗАВЕРШЕН УСПЕШНО!")
    print("=" * 70)
    print(f"\n📁 Файлы сохранены в: {Path(filename_bdu).parent.absolute()}")
    
except Exception as e:
    print(f"\n❌ Ошибка: {e}")
    import traceback
    print("\nДетали ошибки:")
    traceback.print_exc()
    sys.exit(1)
