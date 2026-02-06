#!/usr/bin/env python3
"""
Агент автоматического исправления кода на основе ошибок
Читает JSON с ошибками и применяет исправления
"""
import sys
import json
import re
import os
from pathlib import Path
from typing import Dict, List, Optional

class CodeFixer:
    """Автоматическое исправление кода на основе ошибок"""
    
    def __init__(self):
        self.fixes_applied = []
    
    def fix_undefined_column(self, error: Dict) -> bool:
        """Исправление ошибки UndefinedColumn"""
        file_path = error.get('file')
        if not file_path:
            return False
        
        details = error.get('details', [])
        if not details:
            return False
        
        column_name = details[0]
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Ищем упоминания колонки в SQL запросах
            patterns = [
                rf'\b{column_name}\b',  # Простое упоминание
                rf'"{column_name}"',     # В кавычках
                rf"'{column_name}'",     # В одинарных кавычках
            ]
            
            fixed = False
            for pattern in patterns:
                if re.search(pattern, content):
                    # Комментируем строки с этой колонкой
                    lines = content.split('\n')
                    new_lines = []
                    for line in lines:
                        if re.search(pattern, line) and not line.strip().startswith('#'):
                            new_lines.append(f"# FIXED: {line}  # Column {column_name} removed")
                            fixed = True
                        else:
                            new_lines.append(line)
                    
                    if fixed:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write('\n'.join(new_lines))
                        self.fixes_applied.append({
                            'file': file_path,
                            'error_type': 'UndefinedColumn',
                            'fix': f'Commented out column {column_name}'
                        })
                        return True
        except Exception as e:
            print(f"Error fixing file {file_path}: {e}", file=sys.stderr)
        
        return False
    
    def fix_attribute_error(self, error: Dict) -> bool:
        """Исправление AttributeError"""
        file_path = error.get('file')
        line_num = error.get('line')
        
        if not file_path or not line_num:
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            if line_num > len(lines):
                return False
            
            line = lines[line_num - 1]
            
            # Добавляем проверку на None перед использованием атрибута
            if '.id' in line or '.get(' in line:
                # Ищем переменную перед точкой
                match = re.search(r'(\w+)\.[a-zA-Z_]+\s*=', line) or re.search(r'(\w+)\.[a-zA-Z_]+\(', line)
                if match:
                    var_name = match.group(1)
                    indent = len(line) - len(line.lstrip())
                    new_line = ' ' * indent + f"if {var_name} is not None:\n"
                    lines.insert(line_num - 1, new_line)
                    
                    # Увеличиваем отступ следующей строки
                    lines[line_num] = ' ' * (indent + 4) + lines[line_num].lstrip()
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.writelines(lines)
                    
                    self.fixes_applied.append({
                        'file': file_path,
                        'error_type': 'AttributeError',
                        'fix': f'Added None check before line {line_num}'
                    })
                    return True
        except Exception as e:
            print(f"Error fixing file {file_path}: {e}", file=sys.stderr)
        
        return False
    
    def fix_import_error(self, error: Dict) -> bool:
        """Исправление ImportError - добавляет в requirements.txt"""
        details = error.get('details', [])
        if not details:
            return False
        
        module_name = details[0]
        
        # Маппинг модулей на пакеты pip
        module_mapping = {
            'bcrypt': 'bcrypt>=4.0.0',
            'flask_cors': 'flask-cors>=4.0.0',
            'flask_wtf': 'flask-wtf>=1.1.0',
        }
        
        package = module_mapping.get(module_name.lower(), module_name.lower())
        
        requirements_file = Path('requirements.txt')
        if requirements_file.exists():
            try:
                with open(requirements_file, 'r') as f:
                    content = f.read()
                
                if package not in content:
                    with open(requirements_file, 'a') as f:
                        f.write(f'\n{package}\n')
                    
                    self.fixes_applied.append({
                        'file': str(requirements_file),
                        'error_type': 'ImportError',
                        'fix': f'Added {package} to requirements.txt'
                    })
                    return True
            except Exception as e:
                print(f"Error fixing requirements.txt: {e}", file=sys.stderr)
        
        return False
    
    def fix_permission_error(self, error: Dict) -> bool:
        """Исправление PermissionError - добавляет sudo или группу docker"""
        # Для permission errors мы не можем автоматически исправить код,
        # но можем создать скрипт для исправления на VM
        script_content = """#!/bin/bash
# Автоматическое исправление прав Docker
sudo usermod -aG docker $USER
newgrp docker
"""
        
        fix_script = Path('fix_docker_permissions.sh')
        with open(fix_script, 'w') as f:
            f.write(script_content)
        os.chmod(fix_script, 0o755)
        
        self.fixes_applied.append({
            'file': str(fix_script),
            'error_type': 'PermissionError',
            'fix': 'Created fix_docker_permissions.sh script'
        })
        
        return True
    
    def fix_error(self, error: Dict) -> bool:
        """Применяет исправление в зависимости от типа ошибки"""
        error_type = error.get('error_type', '')
        
        fixers = {
            'psycopg.UndefinedColumn': self.fix_undefined_column,
            'AttributeError': self.fix_attribute_error,
            'ImportError': self.fix_import_error,
            'PermissionError': self.fix_permission_error,
        }
        
        fixer = fixers.get(error_type)
        if fixer:
            return fixer(error)
        
        return False

def main():
    """Основная функция исправления"""
    fixer = CodeFixer()
    errors_to_fix = []
    
    # Читаем ошибки из stdin или файла
    input_data = sys.stdin.read()
    
    try:
        # Пытаемся распарсить как JSON
        if input_data.strip().startswith('{'):
            error = json.loads(input_data)
            errors_to_fix = [error]
        elif input_data.strip().startswith('['):
            errors_to_fix = json.loads(input_data)
        else:
            # Парсим построчно
            for line in input_data.strip().split('\n'):
                if line.strip():
                    try:
                        error = json.loads(line)
                        errors_to_fix.append(error)
                    except json.JSONDecodeError:
                        pass
    except json.JSONDecodeError:
        print("Invalid JSON input", file=sys.stderr)
        return
    
    # Применяем исправления
    for error in errors_to_fix:
        fixer.fix_error(error)
    
    # Выводим отчет
    result = {
        'total_errors': len(errors_to_fix),
        'fixes_applied': len(fixer.fixes_applied),
        'fixes': fixer.fixes_applied
    }
    
    print(json.dumps(result, indent=2, ensure_ascii=False))
    
    if fixer.fixes_applied:
        print(f"\n✅ Применено {len(fixer.fixes_applied)} исправлений", file=sys.stderr)
    else:
        print("\n⚠️  Не удалось автоматически исправить ошибки", file=sys.stderr)

if __name__ == '__main__':
    main()

