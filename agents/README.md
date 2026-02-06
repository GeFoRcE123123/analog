# 🤖 Агенты автономного деплоя

## Обзор

Система агентов для автономного мониторинга ошибок, автоматического исправления кода и деплоя на 4 VM.

---

## 🔧 Агенты

### 1. `error_monitor.py` - Мониторинг ошибок

Анализирует вывод терминала и определяет типы ошибок.

**Использование:**
```bash
# С перенаправлением вывода
python app.py 2>&1 | python agents/error_monitor.py

# Или с файлом
tail -f app.log | python agents/error_monitor.py
```

**Выход:** JSON с информацией об ошибках:
```json
{
  "error_type": "AttributeError",
  "file": "app.py",
  "line": 123,
  "details": ["NoneType", "id"],
  "suggested_fix": "Добавить проверку на None"
}
```

---

### 2. `code_fixer.py` - Автоматическое исправление

Читает JSON с ошибками и применяет исправления.

**Использование:**
```bash
# Из файла с ошибками
python agents/error_monitor.py < errors.log | python agents/code_fixer.py

# Интерактивно
echo '{"error_type": "ImportError", "details": ["bcrypt"]}' | python agents/code_fixer.py
```

**Поддерживаемые исправления:**
- `UndefinedColumn` - комментирует несуществующие колонки
- `AttributeError` - добавляет проверки на None
- `ImportError` - добавляет модули в requirements.txt
- `PermissionError` - создает скрипт для исправления прав

---

### 3. `deploy_agent.py` - Агент деплоя

Автоматически деплоит и мониторит сервисы.

**Использование:**
```bash
# Деплой всех сервисов
python agents/deploy_agent.py --all

# Деплой конкретного сервиса
python agents/deploy_agent.py --service backend

# Мониторинг состояния
python agents/deploy_agent.py --monitor --interval 30
```

---

### 4. `autonomous_deploy.sh` - Полный автономный цикл

Объединяет все агенты в один процесс.

**Использование:**
```bash
./agents/autonomous_deploy.sh
```

**Что делает:**
1. Запускает деплой с мониторингом ошибок
2. Автоматически исправляет найденные ошибки
3. Перезапускает деплой после исправлений
4. Проверяет здоровье всех сервисов
5. Повторяет до успешного деплоя (макс. 3 попытки)

---

## 📋 Примеры использования

### Базовый деплой с мониторингом:
```bash
./deploy.sh all 2>&1 | python agents/error_monitor.py
```

### Автоматическое исправление ошибок:
```bash
# Запуск приложения с мониторингом
python app.py 2>&1 | python agents/error_monitor.py > errors.json

# Применение исправлений
python agents/code_fixer.py < errors.json
```

### Полный автономный цикл:
```bash
./agents/autonomous_deploy.sh
```

---

## 🔍 Мониторинг после деплоя

```bash
# Проверка всех сервисов
python agents/deploy_agent.py --monitor --interval 10

# Проверка конкретного сервиса
python agents/deploy_agent.py --service backend
```

---

## ⚙️ Конфигурация

### Добавление новых паттернов ошибок

Отредактируйте `error_monitor.py`:
```python
ERROR_PATTERNS['YourErrorType'] = {
    'pattern': r'your regex pattern',
    'suggested_fix': 'Описание исправления',
    'file_pattern': r'File "([^"]+)", line (\d+)'
}
```

### Добавление новых исправлений

Отредактируйте `code_fixer.py`, добавив метод:
```python
def fix_your_error(self, error: Dict) -> bool:
    # Ваша логика исправления
    return True
```

И зарегистрируйте в `fix_error()`:
```python
fixers = {
    'YourErrorType': self.fix_your_error,
    # ...
}
```

---

## 📊 Форматы вывода

### error_monitor.py
```json
{
  "error_type": "ImportError",
  "details": ["bcrypt"],
  "file": "services/auth_service.py",
  "line": 15,
  "suggested_fix": "Установить модуль: pip install bcrypt",
  "timestamp": "2025-12-20T20:00:00"
}
```

### code_fixer.py
```json
{
  "total_errors": 2,
  "fixes_applied": 2,
  "fixes": [
    {
      "file": "requirements.txt",
      "error_type": "ImportError",
      "fix": "Added bcrypt>=4.0.0 to requirements.txt"
    }
  ]
}
```

---

## 🚀 Интеграция с CI/CD

```yaml
# .github/workflows/deploy.yml
- name: Autonomous Deploy
  run: |
    chmod +x agents/autonomous_deploy.sh
    ./agents/autonomous_deploy.sh
```

---

## 🔧 Устранение неполадок

### Агент не находит ошибки
- Проверьте, что вывод перенаправлен правильно: `2>&1`
- Убедитесь, что паттерны ошибок соответствуют формату

### Исправления не применяются
- Проверьте права на запись в файлы
- Убедитесь, что пути к файлам корректны

### Деплой не проходит
- Проверьте доступность VM: `ping 10.0.88.XX`
- Проверьте SSH доступ: `ssh user@10.0.88.XX`
- Проверьте права Docker: `sudo usermod -aG docker $USER`

