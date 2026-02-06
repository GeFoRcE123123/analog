#!/usr/bin/env python3
"""
Демонстрация работы legacy парсеров
Показывает нормализацию данных и извлечение CVSS
"""
import sys
import re
from pathlib import Path
from datetime import datetime

# Добавляем корень проекта в путь
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def normalize_cve_id(cve_id: str):
    """Нормализация CVE ID"""
    if not cve_id:
        return None
    
    # Извлекаем CVE ID из строки
    match = re.search(r'CVE-\d{4}-\d{4,}', str(cve_id).upper())
    if match:
        return match.group(0)
    
    return None


def extract_cvss_from_text(text: str):
    """Извлечение CVSS score из текста"""
    if not text:
        return 0.0
    
    # Поиск числа с плавающей точкой
    match = re.search(r'\d+\.\d+', str(text))
    if match:
        try:
            score = float(match.group(0))
            return min(10.0, max(0.0, score))  # Ограничиваем 0-10
        except:
            pass
    
    # Поиск целого числа
    match = re.search(r'\d+', str(text))
    if match:
        try:
            score = float(match.group(0))
            return min(10.0, max(0.0, score))
        except:
            pass
    
    return 0.0


def main():
    print("=" * 70)
    print("🔍 ДЕМОНСТРАЦИЯ LEGACY ПАРСЕРОВ")
    print("=" * 70)
    
    # Демонстрация нормализации CVE ID
    print("\n1️⃣  НОРМАЛИЗАЦИЯ CVE ID")
    print("-" * 70)
    
    test_cases = [
        ("CVE-2024-0001", "CVE-2024-0001"),
        ("cve-2024-0001", "CVE-2024-0001"),
        ("CVE-2024-0001 description", "CVE-2024-0001"),
        ("Some text CVE-2024-0001 more text", "CVE-2024-0001"),
        ("CVE-2024-12345", "CVE-2024-12345"),
        ("invalid", None),
        ("", None)
    ]
    
    print("   Тестовые случаи:")
    for input_cve, expected in test_cases:
        result = normalize_cve_id(input_cve)
        status = "✅" if result == expected else "❌"
        print(f"   {status} '{input_cve}' -> {result} (ожидалось: {expected})")
    
    # Демонстрация извлечения CVSS
    print("\n2️⃣  ИЗВЛЕЧЕНИЕ CVSS SCORE ИЗ ТЕКСТА")
    print("-" * 70)
    
    cvss_test_cases = [
        ("CVSS: 7.5", 7.5),
        ("Score: 9.0", 9.0),
        ("Base Score: 5.5", 5.5),
        ("CVSS v3.1 Base Score: 8.2", 8.2),
        ("The vulnerability has a score of 6.7", 6.7),
        ("Critical (10.0)", 10.0),
        ("No score", 0.0),
        ("", 0.0),
        ("Score: 15.0", 10.0),  # Ограничение до 10.0
        ("Score: -5.0", 0.0)    # Ограничение до 0.0
    ]
    
    print("   Тестовые случаи:")
    for input_text, expected in cvss_test_cases:
        result = extract_cvss_from_text(input_text)
        status = "✅" if abs(result - expected) < 0.01 else "❌"
        print(f"   {status} '{input_text}' -> {result} (ожидалось: {expected})")
    
    # Демонстрация создания объекта Vulnerability
    print("\n3️⃣  СОЗДАНИЕ ОБЪЕКТА VULNERABILITY")
    print("-" * 70)
    
    try:
        from models.entities import Vulnerability
        
        # Пример данных из парсера
        parsed_data = {
            'cve_id': 'CVE-2024-0001',
            'title': 'Test Vulnerability',
            'description': 'Test description',
            'cvss_score': 7.5,
            'source': 'RedHat',
            'link': 'https://access.redhat.com/security/cve-2024-0001'
        }
        
        # Определяем severity на основе CVSS
        cvss = parsed_data['cvss_score']
        if cvss >= 9.0:
            severity = 'critical'
        elif cvss >= 7.0:
            severity = 'high'
        elif cvss >= 4.0:
            severity = 'medium'
        else:
            severity = 'low'
        
        vulnerability = Vulnerability(
            id=0,
            cve_id=parsed_data['cve_id'],
            title=parsed_data['title'],
            description=parsed_data['description'],
            severity=severity,
            status='new',
            cvss_score=cvss,
            risk_level=severity,
            category=parsed_data['source'].lower(),
            source_identifier=parsed_data['source'],
            created_date=datetime.now()
        )
        
        print("   ✅ Объект Vulnerability создан:")
        print(f"      CVE ID: {vulnerability.cve_id}")
        print(f"      Title: {vulnerability.title}")
        print(f"      Severity: {vulnerability.severity}")
        print(f"      CVSS Score: {vulnerability.cvss_score}")
        print(f"      Source: {vulnerability.source_identifier}")
        
    except ImportError:
        print("   ⚠️  Модуль models.entities не доступен")
    
    print("\n" + "=" * 70)
    print("✅ ДЕМОНСТРАЦИЯ LEGACY ПАРСЕРОВ ЗАВЕРШЕНА!")
    print("=" * 70)


if __name__ == '__main__':
    main()

