# 🖥️ Как запускать скрипты в терминале

## 📋 Базовые команды

### 1. Переход в директорию проекта

```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager
```

или если вы уже в другой директории:

```bash
cd ~/Downloads/vulnerability_manager
```

### 2. Проверка прав на выполнение

```bash
# Проверка прав
ls -l devops_agent.sh

# Если нет прав на выполнение, добавьте их:
chmod +x devops_agent.sh
```

### 3. Запуск скрипта

```bash
# Прямой запуск
./devops_agent.sh

# Или через bash
bash devops_agent.sh
```

## 🔧 Полный цикл работы

### Шаг 1: Открыть терминал

**macOS:**
- `Cmd + Space` → введите "Terminal" → Enter
- Или `Applications → Utilities → Terminal`

**Linux:**
- `Ctrl + Alt + T`
- Или найдите "Terminal" в меню приложений

**Windows (WSL/Git Bash):**
- Откройте WSL или Git Bash
- Или используйте PowerShell

### Шаг 2: Перейти в директорию проекта

```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager
```

### Шаг 3: Проверить наличие скрипта

```bash
ls -la devops_agent.sh
```

Должно показать что-то вроде:
```
-rwxr-xr-x  1 user  staff  25000 Dec 23 20:00 devops_agent.sh
```

### Шаг 4: Запустить скрипт

```bash
./devops_agent.sh
```

## 📊 Мониторинг выполнения

### Просмотр вывода в реальном времени

```bash
# Обычный запуск
./devops_agent.sh

# С сохранением в файл
./devops_agent.sh | tee output.log

# Только ошибки в файл
./devops_agent.sh 2> errors.log

# Все в один файл
./devops_agent.sh > full_output.log 2>&1
```

### Запуск в фоне

```bash
# Запуск в фоне с выводом в файл
nohup ./devops_agent.sh > agent_output.log 2>&1 &

# Проверка процесса
ps aux | grep devops_agent

# Просмотр логов
tail -f agent_output.log

# Остановка (если нужно)
pkill -f devops_agent.sh
```

## 🔍 Отладка

### Запуск с подробным выводом

```bash
# Режим отладки (показывает каждую команду)
bash -x devops_agent.sh

# Только ошибки
bash -x devops_agent.sh 2>&1 | grep ERROR
```

### Проверка синтаксиса

```bash
# Проверка без выполнения
bash -n devops_agent.sh
```

### Пошаговое выполнение

```bash
# Остановка на каждой команде (интерактивно)
bash -x -i devops_agent.sh
```

## ⚡ Быстрые команды

### Одной строкой

```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager && chmod +x devops_agent.sh && ./devops_agent.sh
```

### С проверкой зависимостей

```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager && \
which sshpass && \
which ping && \
which curl && \
chmod +x devops_agent.sh && \
./devops_agent.sh
```

## 🛠️ Установка зависимостей

### macOS

```bash
# Установка sshpass (через Homebrew)
brew install hudochenkov/sshpass/sshpass

# Или через MacPorts
sudo port install sshpass
```

### Linux (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y sshpass curl ping
```

### Linux (CentOS/RHEL)

```bash
sudo yum install -y sshpass curl iputils
```

## 📝 Примеры использования

### Пример 1: Первый запуск

```bash
# 1. Открыть терминал
# 2. Перейти в директорию
cd /Users/kirillstepanov/Downloads/vulnerability_manager

# 3. Проверить файл
ls -l devops_agent.sh

# 4. Добавить права (если нужно)
chmod +x devops_agent.sh

# 5. Запустить
./devops_agent.sh
```

### Пример 2: Запуск с логированием

```bash
cd /Users/kirillstepanov/Downloads/vulnerability_manager
./devops_agent.sh 2>&1 | tee -a agent_$(date +%Y%m%d_%H%M%S).log
```

### Пример 3: Периодический запуск (cron)

```bash
# Открыть crontab
crontab -e

# Добавить строку (каждые 5 минут)
*/5 * * * * /Users/kirillstepanov/Downloads/vulnerability_manager/devops_agent.sh >> /tmp/devops_agent.log 2>&1
```

### Пример 4: Запуск только диагностики

```bash
# Отредактировать devops_agent.sh и закомментировать start_all_vms()
# Или создать отдельный скрипт
cd /Users/kirillstepanov/Downloads/vulnerability_manager
bash -c 'source devops_agent.sh; test_all_services; diagnose_and_fix_all; generate_report'
```

## ❌ Решение проблем

### Проблема: "Permission denied"

```bash
chmod +x devops_agent.sh
```

### Проблема: "Command not found: sshpass"

```bash
# macOS
brew install hudochenkov/sshpass/sshpass

# Linux
sudo apt install sshpass
```

### Проблема: "No such file or directory"

```bash
# Проверьте путь
pwd
ls -la devops_agent.sh

# Используйте полный путь
/Users/kirillstepanov/Downloads/vulnerability_manager/devops_agent.sh
```

### Проблема: Скрипт зависает

```bash
# Прервать выполнение
Ctrl + C

# Или убить процесс
pkill -f devops_agent.sh
```

## 📚 Полезные команды терминала

```bash
# Текущая директория
pwd

# Список файлов
ls -la

# Поиск файла
find . -name "devops_agent.sh"

# Просмотр файла
cat devops_agent.sh
less devops_agent.sh

# Редактирование (nano/vim)
nano devops_agent.sh
vim devops_agent.sh

# История команд
history | grep devops

# Проверка переменных окружения
env | grep SSH
```

## 🎯 Чеклист перед запуском

- [ ] Терминал открыт
- [ ] Находитесь в правильной директории (`pwd`)
- [ ] Файл существует (`ls -l devops_agent.sh`)
- [ ] Файл исполняемый (`chmod +x devops_agent.sh`)
- [ ] Установлены зависимости (`which sshpass`, `which ping`, `which curl`)
- [ ] VM доступны по сети (`ping 10.0.88.10`)
- [ ] SSH доступен (`sshpass -p '123' ssh user@10.0.88.10 "echo OK"`)

## 🚀 Готово!

Теперь вы можете запускать скрипты прямо из терминала!

