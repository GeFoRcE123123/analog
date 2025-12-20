#!/bin/bash
# Автономный деплой с мониторингом ошибок и автоматическим исправлением

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Файлы для логирования
ERROR_LOG="$PROJECT_ROOT/errors.log"
FIX_LOG="$PROJECT_ROOT/fixes.log"

echo "🤖 Запуск автономного деплоя с мониторингом ошибок"
echo "=================================================="

# Создаем директорию для агентов если её нет
mkdir -p agents

# Проверяем наличие агентов
if [ ! -f "agents/error_monitor.py" ]; then
    echo "❌ error_monitor.py не найден"
    exit 1
fi

# Функция для обработки ошибок
handle_errors() {
    if [ -s "$ERROR_LOG" ]; then
        echo "🔧 Обнаружены ошибки, применяю исправления..."
        python3 agents/code_fixer.py < "$ERROR_LOG" | tee "$FIX_LOG"
        
        # Очищаем лог ошибок после исправления
        > "$ERROR_LOG"
        
        # Если были исправления, перезапускаем
        if grep -q "fixes_applied" "$FIX_LOG"; then
            echo "✅ Исправления применены, перезапускаю деплой..."
            return 0
        fi
    fi
    return 1
}

# Запуск деплоя с мониторингом ошибок
run_deploy_with_monitoring() {
    echo "📦 Запуск деплоя..."
    
    # Запускаем деплой и перехватываем ошибки
    ./deploy.sh all 2>&1 | tee >(
        python3 agents/error_monitor.py > "$ERROR_LOG" 2>&1
    )
    
    # Проверяем наличие ошибок
    if handle_errors; then
        # Перезапускаем деплой после исправлений
        sleep 2
        run_deploy_with_monitoring
    else
        echo "✅ Деплой завершен"
    fi
}

# Основной цикл
MAX_RETRIES=3
RETRY_COUNT=0

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    run_deploy_with_monitoring
    
    # Проверяем статус деплоя
    if python3 agents/deploy_agent.py --monitor --interval 5 2>/dev/null | grep -q "healthy"; then
        echo "✅ Все сервисы работают корректно"
        break
    else
        RETRY_COUNT=$((RETRY_COUNT + 1))
        if [ $RETRY_COUNT -lt $MAX_RETRIES ]; then
            echo "⚠️  Некоторые сервисы не работают, повторная попытка $RETRY_COUNT/$MAX_RETRIES..."
            sleep 10
        fi
    fi
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo "❌ Достигнуто максимальное количество попыток"
    exit 1
fi

echo "🎉 Автономный деплой завершен успешно"

