import re

# Читаем app.py
with open('app.py', 'r') as f:
    lines = f.readlines()

# Найдем место где инициализируются другие сервисы
vuln_service_line = -1
for i, line in enumerate(lines):
    if 'vuln_service = VulnerabilityService' in line:
        vuln_service_line = i
        break

if vuln_service_line != -1:
    # Проверим есть ли уже auth_service
    has_auth_service = False
    for line in lines:
        if 'auth_service = AuthService()' in line and not 'def auth_login' in ' '.join(lines[:i]):
            has_auth_service = True
            break
    
    if not has_auth_service:
        # Добавим auth_service после vuln_service
        lines.insert(vuln_service_line + 1, 'auth_service = AuthService()\n')
        print("✅ auth_service добавлен в инициализацию сервисов")
    else:
        print("✅ auth_service уже есть в инициализации")

# Теперь исправим маршрут auth_login чтобы использовал глобальный auth_service
for i in range(len(lines)):
    if 'def auth_login():' in lines[i]:
        # Ищем строку с auth_service = AuthService() внутри функции
        for j in range(i, min(i+20, len(lines))):
            if 'auth_service = AuthService()' in lines[j]:
                # Заменяем на использование глобального auth_service
                lines[j] = '        # Используем глобальный экземпляр auth_service\n'
                print("✅ Исправлен вызов AuthService() в auth_login")
                break
        break

# Запишем обратно
with open('app.py', 'w') as f:
    f.writelines(lines)

print("✅ Исправления применены")
