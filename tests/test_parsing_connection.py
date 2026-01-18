#!/usr/bin/env python3
"""
Тестовый скрипт для проверки связи фронтенд-бэкенд-парсеры
"""

import requests
import json
import time

BACKEND_URL = "http://10.0.88.20:5000"

def test_parsing_api():
    """Тест API парсинга"""
    print("=" * 60)
    print("ТЕСТ СВЯЗИ ФРОНТЕНД-БЭКЕНД-ПАРСЕРЫ")
    print("=" * 60)
    
    # 1. Проверка доступности API
    print("\n1. Проверка доступности API...")
    try:
        response = requests.get(f"{BACKEND_URL}/api/parsers/stats", timeout=5)
        if response.status_code == 200:
            print("✅ API доступен")
            stats = response.json()
            print(f"   Статистика: {json.dumps(stats, indent=2, ensure_ascii=False)}")
        else:
            print(f"❌ API недоступен: HTTP {response.status_code}")
            return
    except Exception as e:
        print(f"❌ Ошибка подключения к API: {e}")
        return
    
    # 2. Запуск парсинга с минимальными параметрами
    print("\n2. Запуск парсинга (legacy парсеры: redhat)...")
    try:
        payload = {
            "sources": [],
            "limit_per_source": 5,
            "enable_legacy_parsers": True,
            "legacy_parser_sources": ["redhat"]
        }
        
        response = requests.post(
            f"{BACKEND_URL}/api/parsers/run-all",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Парсинг запущен: {json.dumps(result, indent=2, ensure_ascii=False)}")
            parsing_id = result.get('parsing_id')
            
            if parsing_id:
                print(f"   Parsing ID: {parsing_id}")
                
                # 3. Проверка статуса парсинга
                print("\n3. Проверка статуса парсинга...")
                for i in range(10):  # Проверяем 10 раз
                    time.sleep(2)
                    try:
                        status_response = requests.get(
                            f"{BACKEND_URL}/api/parsing-status",
                            timeout=5
                        )
                        if status_response.status_code == 200:
                            status_data = status_response.json()
                            if status_data.get('success'):
                                status = status_data.get('status', {})
                                print(f"   [{i+1}] Статус: {status.get('status', 'unknown')}")
                                print(f"       Спарсено: {status.get('total_parsed', 0)}")
                                print(f"       Сохранено: {status.get('total_saved', 0)}")
                                
                                if status.get('status') == 'completed':
                                    print("\n✅ Парсинг завершен!")
                                    print(f"   Итоги: {json.dumps(status, indent=2, ensure_ascii=False)}")
                                    break
                                elif status.get('status') == 'failed':
                                    print(f"\n❌ Парсинг завершился с ошибкой: {status.get('error_message', 'Unknown')}")
                                    break
                    except Exception as e:
                        print(f"   Ошибка проверки статуса: {e}")
            else:
                print("⚠️ Parsing ID не получен - возможно, ошибка создания записи в БД")
        else:
            print(f"❌ Ошибка запуска парсинга: HTTP {response.status_code}")
            print(f"   Ответ: {response.text}")
    except Exception as e:
        print(f"❌ Ошибка при запуске парсинга: {e}")
        import traceback
        traceback.print_exc()
    
    # 4. Проверка статистики после парсинга
    print("\n4. Финальная статистика...")
    try:
        response = requests.get(f"{BACKEND_URL}/api/parsers/stats", timeout=5)
        if response.status_code == 200:
            stats = response.json()
            print(f"   Статистика: {json.dumps(stats, indent=2, ensure_ascii=False)}")
    except Exception as e:
        print(f"   Ошибка получения статистики: {e}")

if __name__ == "__main__":
    test_parsing_api()
