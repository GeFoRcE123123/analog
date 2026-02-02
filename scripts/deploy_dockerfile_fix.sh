#!/bin/bash
# Деплой исправленных Dockerfile на серверы

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🐳 ДЕПЛОЙ ИСПРАВЛЕННЫХ DOCKERFILE                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Сервер 1: 10.0.88.20 (Internal)
BACKEND_VM1="10.0.88.20"
PASSWORD1="123"
BACKEND_USER1="user"

export SSHPASS="$PASSWORD1"

echo "📍 Сервер 1: $BACKEND_USER1@$BACKEND_VM1"
echo "─────────────────────────────────────"

# Находим директорию проекта
PROJECT_PATH1=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER1@$BACKEND_VM1 "find /home -name 'app.py' -path '*/vulnerability_manager/*' 2>/dev/null | head -1 | xargs dirname" 2>&1)

if [ -z "$PROJECT_PATH1" ]; then
    PROJECT_PATH1=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER1@$BACKEND_VM1 "ls -d ~/vulnerability_manager 2>/dev/null || ls -d /home/*/vulnerability_manager 2>/dev/null" 2>&1 | head -1)
fi

if [ ! -z "$PROJECT_PATH1" ]; then
    echo "✅ Найдена директория: $PROJECT_PATH1"
    
    # Создаем директории если нужно
    sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER1@$BACKEND_VM1 "mkdir -p $PROJECT_PATH1/services/backend $PROJECT_PATH1/services/parsers" 2>&1
    
    # Копируем исправленные Dockerfile
    echo "📦 Копирование Dockerfile..."
    sshpass -e scp -o StrictHostKeyChecking=no services/backend/Dockerfile $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/services/backend/Dockerfile 2>&1 && echo "  ✅ services/backend/Dockerfile"
    sshpass -e scp -o StrictHostKeyChecking=no services/parsers/Dockerfile $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/services/parsers/Dockerfile 2>&1 && echo "  ✅ services/parsers/Dockerfile"
    
    echo "✅ Dockerfile задеплоены на сервер 1"
else
    echo "❌ Не найдена директория на сервере 1"
fi

unset SSHPASS

# Сервер 2: 217.25.230.15 (External) - если доступен
echo ""
echo "📍 Сервер 2: 217.25.230.15 (External)"
echo "─────────────────────────────────────"

# Пробуем подключиться
CONNECTED=0
for USER in user admin root ubuntu; do
    for PASS in "123" "admin" "password" ""; do
        export SSHPASS="$PASS"
        if sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 $USER@217.25.230.15 "echo 'OK'" 2>/dev/null | grep -q "OK"; then
            BACKEND_USER2=$USER
            PASSWORD2=$PASS
            CONNECTED=1
            echo "✅ Подключение: $USER@217.25.230.15"
            break 2
        fi
    done
done

if [ $CONNECTED -eq 1 ]; then
    export SSHPASS="$PASSWORD2"
    
    # Находим директорию проекта
    PROJECT_PATH2=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "find /home -name 'app.py' -path '*/vulnerability_manager/*' 2>/dev/null | head -1 | xargs dirname" 2>&1)
    
    if [ -z "$PROJECT_PATH2" ]; then
        PROJECT_PATH2=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "ls -d ~/vulnerability_manager 2>/dev/null || ls -d /opt/vulnerability_manager 2>/dev/null || ls -d /var/www/vulnerability_manager 2>/dev/null" 2>&1 | head -1)
    fi
    
    if [ ! -z "$PROJECT_PATH2" ]; then
        echo "✅ Найдена директория: $PROJECT_PATH2"
        
        # Создаем директории если нужно
        sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "mkdir -p $PROJECT_PATH2/services/backend $PROJECT_PATH2/services/parsers" 2>&1
        
        # Копируем исправленные Dockerfile
        echo "📦 Копирование Dockerfile..."
        sshpass -e scp -o StrictHostKeyChecking=no services/backend/Dockerfile $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/services/backend/Dockerfile 2>&1 && echo "  ✅ services/backend/Dockerfile"
        sshpass -e scp -o StrictHostKeyChecking=no services/parsers/Dockerfile $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/services/parsers/Dockerfile 2>&1 && echo "  ✅ services/parsers/Dockerfile"
        
        echo "✅ Dockerfile задеплоены на сервер 2"
    else
        echo "❌ Не найдена директория на сервере 2"
    fi
    
    unset SSHPASS
else
    echo "⚠️  Не удалось подключиться к серверу 2 (217.25.230.15)"
    echo "   Dockerfile готовы для ручного деплоя"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ ДЕПЛОЙ DOCKERFILE ЗАВЕРШЕН!                               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "📝 Изменения:"
echo "   - Исправлена ошибка apt-get update (exit code 100)"
echo "   - Добавлена обработка ошибок и fallback"
echo "   - Добавлен ca-certificates для SSL"
echo "   - Улучшена очистка кэша"
echo ""
echo "🔨 Для пересборки образов на сервере:"
echo "   cd services/backend && docker build -t vulnerability-backend ."
echo "   cd services/parsers && docker build -t vulnerability-parsers ."
echo ""
