#!/usr/bin/env python3
"""
Тестирование всех сетевых взаимодействий визуализационного сервера
"""

import requests
import json
import time
import sys
from urllib.parse import urljoin

BASE_URL = "http://127.0.0.1:8080"
TIMEOUT = 10

def test_endpoint(url, method='GET', expected_status=200, description=""):
    """Тест одного endpoint"""
    try:
        print(f"\n{'='*60}")
        print(f"🔍 Тест: {description}")
        print(f"📍 URL: {url}")
        print(f"📋 Метод: {method}")
        
        if method == 'GET':
            response = requests.get(url, timeout=TIMEOUT)
        elif method == 'POST':
            response = requests.post(url, timeout=TIMEOUT)
        else:
            print(f"❌ Неподдерживаемый метод: {method}")
            return False
        
        print(f"📊 Статус код: {response.status_code}")
        print(f"⏱️  Время ответа: {response.elapsed.total_seconds():.3f}s")
        print(f"📦 Размер ответа: {len(response.content)} bytes")
        print(f"🔗 Заголовки:")
        for key, value in response.headers.items():
            if key.lower() in ['content-type', 'content-length', 'access-control-allow-origin', 'cache-control']:
                print(f"   {key}: {value}")
        
        if response.status_code == expected_status:
            print(f"✅ Успешно: статус {response.status_code}")
            
            # Проверка содержимого для HTML
            if 'text/html' in response.headers.get('content-type', ''):
                content = response.text
                checks = {
                    'Three.js CDN': 'cdn.jsdelivr.net/npm/three' in content or 'unpkg.com/three' in content,
                    'D3.js CDN': 'cdn.jsdelivr.net/npm/d3' in content or 'unpkg.com/d3' in content,
                    'window.libsLoaded': 'window.libsLoaded' in content,
                    'three-d3-graph.js': 'three-d3-graph.js' in content,
                    'addLog function': 'function addLog' in content,
                }
                print(f"📋 Проверка содержимого HTML:")
                for check, result in checks.items():
                    status = "✅" if result else "❌"
                    print(f"   {status} {check}: {result}")
                return all(checks.values())
            
            # Проверка JSON
            elif 'application/json' in response.headers.get('content-type', ''):
                try:
                    data = response.json()
                    print(f"📋 JSON данные: {json.dumps(data, indent=2, ensure_ascii=False)}")
                    return True
                except:
                    print(f"⚠️  Не удалось распарсить JSON")
                    return False
            
            return True
        else:
            print(f"❌ Ошибка: ожидался статус {expected_status}, получен {response.status_code}")
            print(f"📄 Ответ: {response.text[:200]}")
            return False
            
    except requests.exceptions.Timeout:
        print(f"❌ Таймаут: запрос превысил {TIMEOUT} секунд")
        return False
    except requests.exceptions.ConnectionError:
        print(f"❌ Ошибка подключения: сервер не отвечает на {url}")
        return False
    except Exception as e:
        print(f"❌ Неожиданная ошибка: {type(e).__name__}: {e}")
        return False

def test_cdn_resources():
    """Тест доступности CDN ресурсов"""
    print(f"\n{'='*60}")
    print(f"🌐 Тест доступности CDN ресурсов")
    
    cdns = [
        'https://cdn.jsdelivr.net/npm/three@0.169.0/build/three.min.js',
        'https://unpkg.com/three@0.169.0/build/three.min.js',
        'https://cdn.jsdelivr.net/npm/d3@7.8.5/dist/d3.min.js',
        'https://unpkg.com/d3@7.8.5/dist/d3.min.js',
    ]
    
    results = []
    for cdn_url in cdns:
        try:
            print(f"\n🔍 Проверка: {cdn_url}")
            response = requests.get(cdn_url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
            if response.status_code == 200:
                size = len(response.content)
                print(f"   ✅ Доступен, размер: {size:,} bytes")
                results.append(True)
            else:
                print(f"   ❌ Статус: {response.status_code}")
                results.append(False)
        except Exception as e:
            print(f"   ❌ Ошибка: {type(e).__name__}: {e}")
            results.append(False)
    
    return all(results)

def test_static_files():
    """Тест статических файлов"""
    print(f"\n{'='*60}")
    print(f"📁 Тест статических файлов")
    
    static_files = [
        '/static/js/three-d3-graph.js',
    ]
    
    results = []
    for static_file in static_files:
        url = urljoin(BASE_URL, static_file)
        try:
            print(f"\n🔍 Проверка: {static_file}")
            response = requests.get(url, timeout=TIMEOUT)
            if response.status_code == 200:
                size = len(response.content)
                print(f"   ✅ Доступен, размер: {size:,} bytes")
                print(f"   📋 Content-Type: {response.headers.get('content-type', 'N/A')}")
                
                # Проверка содержимого JS файла
                if static_file.endswith('.js'):
                    content = response.text
                    checks = {
                        'THREE': 'THREE' in content or 'Three' in content,
                        'D3': 'd3' in content or 'D3' in content,
                        'init function': 'function init' in content or 'async function init' in content,
                        'Scene': 'Scene' in content or 'scene' in content,
                    }
                    print(f"   📋 Проверка содержимого:")
                    for check, result in checks.items():
                        status = "✅" if result else "❌"
                        print(f"      {status} {check}: {result}")
                
                results.append(True)
            else:
                print(f"   ❌ Статус: {response.status_code}")
                results.append(False)
        except Exception as e:
            print(f"   ❌ Ошибка: {type(e).__name__}: {e}")
            results.append(False)
    
    return all(results)

def test_cors():
    """Тест CORS заголовков"""
    print(f"\n{'='*60}")
    print(f"🌐 Тест CORS заголовков")
    
    try:
        response = requests.options(BASE_URL, timeout=TIMEOUT)
        cors_headers = {
            'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
            'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods'),
            'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers'),
        }
        
        print(f"📋 CORS заголовки:")
        for header, value in cors_headers.items():
            if value:
                print(f"   ✅ {header}: {value}")
            else:
                print(f"   ⚠️  {header}: отсутствует")
        
        return cors_headers['Access-Control-Allow-Origin'] is not None
    except Exception as e:
        print(f"❌ Ошибка: {type(e).__name__}: {e}")
        return False

def main():
    """Основная функция тестирования"""
    print("╔" + "="*58 + "╗")
    print("║" + " "*10 + "ТЕСТИРОВАНИЕ СЕТЕВЫХ ВЗАИМОДЕЙСТВИЙ" + " "*10 + "║")
    print("╚" + "="*58 + "╝")
    print(f"\n🎯 Базовый URL: {BASE_URL}")
    print(f"⏱️  Таймаут: {TIMEOUT}s")
    
    results = []
    
    # Тест 1: Health check
    results.append(("Health Check", test_endpoint(
        f"{BASE_URL}/health",
        description="Проверка здоровья сервера"
    )))
    
    # Тест 2: Главная страница
    results.append(("Главная страница", test_endpoint(
        f"{BASE_URL}/",
        description="Загрузка главной страницы HTML"
    )))
    
    # Тест 3: API данных
    results.append(("API данных", test_endpoint(
        f"{BASE_URL}/data",
        description="Получение данных графа"
    )))
    
    # Тест 4: Статические файлы
    results.append(("Статические файлы", test_static_files()))
    
    # Тест 5: CDN ресурсы
    results.append(("CDN ресурсы", test_cdn_resources()))
    
    # Тест 6: CORS
    results.append(("CORS", test_cors()))
    
    # Итоги
    print(f"\n\n{'='*60}")
    print("📊 ИТОГИ ТЕСТИРОВАНИЯ")
    print("="*60)
    
    passed = 0
    failed = 0
    
    for name, result in results:
        status = "✅ ПРОЙДЕН" if result else "❌ ПРОВАЛЕН"
        print(f"{status}: {name}")
        if result:
            passed += 1
        else:
            failed += 1
    
    print(f"\n📈 Результаты: {passed} пройдено, {failed} провалено из {len(results)}")
    
    if failed == 0:
        print("🎉 Все тесты пройдены успешно!")
        return 0
    else:
        print("⚠️  Некоторые тесты провалены")
        return 1

if __name__ == "__main__":
    sys.exit(main())

