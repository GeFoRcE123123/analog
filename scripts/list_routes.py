#!/usr/bin/env python3
"""
Скрипт для просмотра всех маршрутов Flask приложения
Показывает маршруты с методами, endpoint'ами и типами ответов
"""
import sys
import os
import re
from typing import List, Dict, Tuple

# Добавляем путь к проекту
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

def analyze_routes_file(filepath: str) -> List[Dict]:
    """Анализирует файл с маршрутами Flask"""
    routes = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.split('\n')
            
            for i, line in enumerate(lines):
                # Ищем декораторы @app.route
                route_match = re.search(r'@app\.route\([\'"]([^\'"]+)[\'"]', line)
                if route_match:
                    route_path = route_match.group(1)
                    
                    # Ищем методы
                    methods_match = re.search(r'methods=\[([^\]]+)\]', line)
                    methods = ['GET']  # По умолчанию
                    if methods_match:
                        methods_str = methods_match.group(1)
                        methods = [m.strip().strip('"\'') for m in methods_str.split(',')]
                    
                    # Ищем имя функции
                    func_name = None
                    if i + 1 < len(lines):
                        func_line = lines[i + 1].strip()
                        func_match = re.search(r'def\s+(\w+)', func_line)
                        if func_match:
                            func_name = func_match.group(1)
                    
                    # Определяем тип ответа (ищем в следующих строках)
                    response_type = 'unknown'
                    return_type = None
                    
                    # Ищем в следующих 20 строках
                    for j in range(i + 1, min(i + 20, len(lines))):
                        next_line = lines[j]
                        
                        if 'jsonify' in next_line:
                            response_type = 'JSON'
                            break
                        elif 'render_template' in next_line:
                            response_type = 'HTML'
                            break
                        elif 'redirect' in next_line:
                            response_type = 'REDIRECT'
                            break
                        elif 'send_file' in next_line or 'Response' in next_line:
                            response_type = 'FILE'
                            break
                        elif 'return' in next_line and 'json' in next_line.lower():
                            response_type = 'JSON'
                            break
                    
                    routes.append({
                        'path': route_path,
                        'methods': methods,
                        'function': func_name,
                        'response_type': response_type,
                        'file': os.path.basename(filepath),
                        'line': i + 1
                    })
    except Exception as e:
        print(f"Ошибка при анализе {filepath}: {e}", file=sys.stderr)
    
    return routes

def main():
    """Главная функция"""
    # Файлы с маршрутами
    route_files = [
        'app.py',
        'services/backend/app.py',
        'scripts/utils/app.py'
    ]
    
    all_routes = []
    
    print("=" * 80)
    print("АНАЛИЗ МАРШРУТОВ FLASK ПРИЛОЖЕНИЯ")
    print("=" * 80)
    print()
    
    for route_file in route_files:
        filepath = os.path.join(project_root, route_file)
        if os.path.exists(filepath):
            print(f"📄 Анализ файла: {route_file}")
            routes = analyze_routes_file(filepath)
            all_routes.extend(routes)
            print(f"   Найдено маршрутов: {len(routes)}")
        else:
            print(f"⚠️  Файл не найден: {route_file}")
    
    print()
    print("=" * 80)
    print("ВСЕ МАРШРУТЫ")
    print("=" * 80)
    print()
    
    # Группировка по типу ответа
    json_routes = [r for r in all_routes if r['response_type'] == 'JSON']
    html_routes = [r for r in all_routes if r['response_type'] == 'HTML']
    redirect_routes = [r for r in all_routes if r['response_type'] == 'REDIRECT']
    file_routes = [r for r in all_routes if r['response_type'] == 'FILE']
    unknown_routes = [r for r in all_routes if r['response_type'] == 'unknown']
    
    print(f"📊 Статистика:")
    print(f"   JSON API: {len(json_routes)}")
    print(f"   HTML страницы: {len(html_routes)}")
    print(f"   Редиректы: {len(redirect_routes)}")
    print(f"   Файлы: {len(file_routes)}")
    print(f"   Неопределенные: {len(unknown_routes)}")
    print(f"   Всего: {len(all_routes)}")
    print()
    
    # JSON API маршруты
    if json_routes:
        print("=" * 80)
        print("📡 JSON API МАРШРУТЫ")
        print("=" * 80)
        for route in sorted(json_routes, key=lambda x: x['path']):
            methods_str = ', '.join(route['methods'])
            print(f"  {methods_str:15} {route['path']:50} → {route['function']}")
        print()
    
    # HTML маршруты
    if html_routes:
        print("=" * 80)
        print("🌐 HTML СТРАНИЦЫ")
        print("=" * 80)
        for route in sorted(html_routes, key=lambda x: x['path']):
            methods_str = ', '.join(route['methods'])
            print(f"  {methods_str:15} {route['path']:50} → {route['function']}")
        print()
    
    # Экспорт в JSON
    import json
    output_file = os.path.join(project_root, 'docs', 'routes_analysis.json')
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            'total': len(all_routes),
            'by_type': {
                'json': len(json_routes),
                'html': len(html_routes),
                'redirect': len(redirect_routes),
                'file': len(file_routes),
                'unknown': len(unknown_routes)
            },
            'routes': all_routes
        }, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Результаты сохранены в: {output_file}")

if __name__ == '__main__':
    main()

