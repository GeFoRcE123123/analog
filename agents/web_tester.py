#!/usr/bin/env python3
"""
Агент тестирования веб-приложения
Анализирует HTML-шаблоны на наличие проблем
"""
import os
import re
from pathlib import Path
from typing import List, Dict, Set
from collections import defaultdict
import json

class WebTester:
    """Анализатор веб-приложения"""
    
    def __init__(self, templates_dir: str = "templates"):
        self.templates_dir = Path(templates_dir)
        self.issues = []
        self.links = defaultdict(list)  # link -> [files]
        self.routes = set()
        self.duplicates = []
        
    def analyze(self) -> Dict:
        """Основной метод анализа"""
        print("🔍 Анализ веб-приложения...")
        
        # Находим все HTML файлы
        html_files = list(self.templates_dir.glob("*.html"))
        print(f"📄 Найдено {len(html_files)} HTML файлов")
        
        # Анализируем каждый файл
        for html_file in html_files:
            self._analyze_file(html_file)
        
        # Проверяем дубликаты
        self._check_duplicates()
        
        # Проверяем ссылки
        self._check_links()
        
        # Проверяем структуру
        self._check_structure()
        
        # Проверяем роли
        self._check_roles()
        
        # Проверяем доступность
        self._check_accessibility()
        
        return {
            'issues': self.issues,
            'summary': self._generate_summary()
        }
    
    def _analyze_file(self, file_path: Path):
        """Анализ одного файла"""
        content = file_path.read_text(encoding='utf-8')
        filename = file_path.name
        
        # Ищем все ссылки
        links = re.findall(r'href=["\']([^"\']+)["\']', content)
        for link in links:
            if link.startswith('{{') or link.startswith('url_for'):
                # Jinja2 шаблон - извлекаем имя маршрута
                route_match = re.search(r'url_for\([\'"]([^\'"]+)[\'"]', link)
                if route_match:
                    route_name = route_match.group(1)
                    self.routes.add(route_name)
                    self.links[route_name].append(filename)
        
        # Проверяем наличие основных элементов
        if not re.search(r'<title>', content, re.IGNORECASE):
            self.issues.append({
                'type': 'missing_title',
                'file': filename,
                'severity': 'low',
                'message': 'Отсутствует тег <title>'
            })
        
        # Проверяем meta charset
        if 'base.html' not in filename and not re.search(r'<meta\s+charset', content, re.IGNORECASE):
            # Это нормально, если наследуется от base.html
            pass
        
        # Ищем дублирующиеся блоки
        self._find_duplicate_blocks(content, filename)
    
    def _find_duplicate_blocks(self, content: str, filename: str):
        """Поиск дублирующихся блоков"""
        # Ищем повторяющиеся ссылки в меню
        menu_links = re.findall(r'href=["\']{{ url_for\([\'"]([^\'"]+)[\'"]\) }}["\']', content)
        seen = set()
        for link in menu_links:
            if link in seen:
                self.issues.append({
                    'type': 'duplicate_link',
                    'file': filename,
                    'severity': 'medium',
                    'message': f'Дублирующаяся ссылка: {link}'
                })
            seen.add(link)
    
    def _check_duplicates(self):
        """Проверка дублирующихся файлов"""
        files = list(self.templates_dir.glob("*.html"))
        names = [f.name.lower() for f in files]
        
        # Проверяем опечатки
        if 'my_assigments.html' in names and 'my_assignments.html' in names:
            self.issues.append({
                'type': 'typo_file',
                'file': 'my_assigments.html',
                'severity': 'high',
                'message': 'Файл my_assigments.html - опечатка, должен быть my_assignments.html'
            })
    
    def _check_links(self):
        """Проверка ссылок"""
        # Проверяем ссылки, которые встречаются только в одном месте
        for link, files in self.links.items():
            if len(files) == 1:
                # Возможно, неиспользуемая ссылка
                if link not in ['auth_logout', 'auth_login']:  # Исключения
                    self.issues.append({
                        'type': 'unused_link',
                        'file': files[0],
                        'severity': 'low',
                        'message': f'Ссылка {link} используется только в одном месте'
                    })
    
    def _check_structure(self):
        """Проверка структуры страниц"""
        base_file = self.templates_dir / "base.html"
        if base_file.exists():
            content = base_file.read_text(encoding='utf-8')
            
            # Проверяем наличие скрипта для мобильного меню
            if 'mobile-menu-button' in content and not re.search(r'getElementById\([\'"]mobile-menu-button[\'"]\)', content):
                self.issues.append({
                    'type': 'missing_script',
                    'file': 'base.html',
                    'severity': 'medium',
                    'message': 'Кнопка mobile-menu-button есть, но нет обработчика события'
                })
            
            # Проверяем дублирующиеся ссылки в меню
            admin_links = re.findall(r'href=["\']{{ url_for\([\'"]admin_users[\'"]\) }}["\']', content)
            if len(admin_links) > 1:
                self.issues.append({
                    'type': 'duplicate_menu_link',
                    'file': 'base.html',
                    'severity': 'high',
                    'message': 'Ссылка admin_users дублируется в меню (Мой профиль и Управление пользователями)'
                })
            
            # Проверяем пустые ссылки в мобильном меню
            if 'performance_analytics' in content:
                # Проверяем, что у ссылки есть текст
                perf_link_pattern = r'<a[^>]*url_for\([\'"]performance_analytics[\'"]\)[^>]*>([^<]*)<'
                matches = re.findall(perf_link_pattern, content)
                for match in matches:
                    if not match.strip() or match.strip() == '<i':
                        self.issues.append({
                            'type': 'empty_link_text',
                            'file': 'base.html',
                            'severity': 'medium',
                            'message': 'В мобильном меню ссылка performance_analytics без текста'
                        })
    
    def _check_roles(self):
        """Проверка ролевой модели"""
        base_file = self.templates_dir / "base.html"
        if base_file.exists():
            content = base_file.read_text(encoding='utf-8')
            
            # Проверяем, что админские элементы правильно защищены
            admin_elements = [
                ('operators_page', 'Операторы'),
                ('review_vulnerabilities', 'Проверка'),
                ('admin_users', 'Управление пользователями')
            ]
            
            for route, name in admin_elements:
                # Ищем использование без проверки роли
                pattern = rf'href=["\']{{{{ url_for\([\'"]{re.escape(route)}[\'"]\) }}}}["\']'
                matches = list(re.finditer(pattern, content))
                
                for match in matches:
                    # Проверяем, есть ли перед этим {% if session.role == 'admin' %}
                    before = content[:match.start()]
                    # Ищем ближайшую проверку роли перед этой ссылкой
                    admin_check = re.search(r'{%\s*if\s+session\.role\s*==\s*[\'"]admin[\'"]\s*%}', before)
                    if not admin_check:
                        # Проверяем, не внутри уже защищенного блока
                        if '{% if session.role == \'admin\' %}' not in before[-500:]:
                            self.issues.append({
                                'type': 'missing_role_check',
                                'file': 'base.html',
                                'severity': 'high',
                                'message': f'Ссылка {name} ({route}) не защищена проверкой роли'
                            })
    
    def _check_accessibility(self):
        """Проверка доступности"""
        for html_file in self.templates_dir.glob("*.html"):
            content = html_file.read_text(encoding='utf-8')
            filename = html_file.name
            
            # Проверяем изображения без alt
            images = re.findall(r'<img[^>]*>', content, re.IGNORECASE)
            for img in images:
                if 'alt=' not in img.lower():
                    self.issues.append({
                        'type': 'missing_alt',
                        'file': filename,
                        'severity': 'medium',
                        'message': f'Изображение без атрибута alt: {img[:50]}...'
                    })
            
            # Проверяем формы без label
            inputs = re.findall(r'<input[^>]*>', content, re.IGNORECASE)
            for inp in inputs:
                input_id = re.search(r'id=["\']([^"\']+)["\']', inp)
                if input_id:
                    input_id_value = input_id.group(1)
                    # Проверяем наличие label с for="input_id_value"
                    if not re.search(rf'<label[^>]*for=["\']{re.escape(input_id_value)}["\']', content, re.IGNORECASE):
                        if 'type="hidden"' not in inp.lower():
                            self.issues.append({
                                'type': 'missing_label',
                                'file': filename,
                                'severity': 'medium',
                                'message': f'Input без label: {inp[:50]}...'
                            })
    
    def _generate_summary(self) -> Dict:
        """Генерация сводки"""
        severity_count = defaultdict(int)
        type_count = defaultdict(int)
        
        for issue in self.issues:
            severity_count[issue['severity']] += 1
            type_count[issue['type']] += 1
        
        return {
            'total_issues': len(self.issues),
            'by_severity': dict(severity_count),
            'by_type': dict(type_count),
            'routes_found': len(self.routes),
            'links_analyzed': len(self.links)
        }

def main():
    """Главная функция"""
    tester = WebTester()
    results = tester.analyze()
    
    # Выводим результаты
    print("\n" + "="*60)
    print("📊 РЕЗУЛЬТАТЫ АНАЛИЗА")
    print("="*60)
    
    print(f"\n📈 Сводка:")
    summary = results['summary']
    print(f"  Всего проблем: {summary['total_issues']}")
    print(f"  По серьезности: {summary['by_severity']}")
    print(f"  Найдено маршрутов: {summary['routes_found']}")
    print(f"  Проанализировано ссылок: {summary['links_analyzed']}")
    
    print(f"\n🔴 Критические проблемы (high):")
    high_issues = [i for i in results['issues'] if i['severity'] == 'high']
    for issue in high_issues:
        print(f"  ❌ [{issue['file']}] {issue['message']}")
    
    print(f"\n🟡 Средние проблемы (medium):")
    medium_issues = [i for i in results['issues'] if i['severity'] == 'medium']
    for issue in medium_issues[:10]:  # Показываем первые 10
        print(f"  ⚠️  [{issue['file']}] {issue['message']}")
    
    print(f"\n🟢 Низкие проблемы (low):")
    low_issues = [i for i in results['issues'] if i['severity'] == 'low']
    for issue in low_issues[:5]:  # Показываем первые 5
        print(f"  💡 [{issue['file']}] {issue['message']}")
    
    # Сохраняем полный отчет
    report_file = Path("web_test_report.json")
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print(f"\n💾 Полный отчет сохранен в: {report_file}")
    
    return results

if __name__ == '__main__':
    main()

