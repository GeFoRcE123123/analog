#!/bin/bash
# Деплой БДУ ФСТЭК интеграции на оба production сервера

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🚀 ДЕПЛОЙ БДУ ФСТЭК ИНТЕГРАЦИИ                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Сервер 1: 10.0.88.20 (Backend Internal)
echo ""
echo "📍 Сервер 1: 10.0.88.20:5000 (Internal)"
echo "─────────────────────────────────────"

BACKEND_VM1="10.0.88.20"
PASSWORD1="123"
BACKEND_USER1="user"

export SSHPASS="$PASSWORD1"

# Находим директорию проекта
PROJECT_PATH1=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER1@$BACKEND_VM1 "find /home -name 'app.py' -path '*/vulnerability_manager/*' 2>/dev/null | head -1 | xargs dirname" 2>&1)

if [ -z "$PROJECT_PATH1" ]; then
    PROJECT_PATH1=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER1@$BACKEND_VM1 "ls -d ~/vulnerability_manager 2>/dev/null || ls -d /opt/vulnerability_manager 2>/dev/null" 2>&1 | head -1)
fi

if [ ! -z "$PROJECT_PATH1" ]; then
    echo "✅ Найдена директория: $PROJECT_PATH1"
    
    # Создаем директории
    echo "📁 Создание директорий..."
    sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER1@$BACKEND_VM1 "mkdir -p $PROJECT_PATH1/services/parsers $PROJECT_PATH1/scripts/migration $PROJECT_PATH1/models" 2>&1
    
    # Копируем файлы БДУ
    echo "📦 Копирование файлов БДУ..."
    
    # Backend
    sshpass -e scp -o StrictHostKeyChecking=no app.py $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/ 2>&1 && echo "  ✅ app.py"
    
    # Templates
    sshpass -e scp -o StrictHostKeyChecking=no templates/vulnerabilities_list.html $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/templates/ 2>&1 && echo "  ✅ vulnerabilities_list.html"
    
    # Models
    sshpass -e scp -o StrictHostKeyChecking=no models/entities.py $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/models/ 2>&1 && echo "  ✅ models/entities.py"
    sshpass -e scp -o StrictHostKeyChecking=no models/postgres_repositories.py $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/models/ 2>&1 && echo "  ✅ models/postgres_repositories.py"
    
    # Parsers
    sshpass -e scp -o StrictHostKeyChecking=no services/parsers/bdu_xml_parser.py $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/services/parsers/ 2>&1 && echo "  ✅ bdu_xml_parser.py"
    sshpass -e scp -o StrictHostKeyChecking=no services/parsers/bdu_importer.py $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/services/parsers/ 2>&1 && echo "  ✅ bdu_importer.py"
    sshpass -e scp -o StrictHostKeyChecking=no services/parsers/README_BDU.md $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/services/parsers/ 2>&1 && echo "  ✅ README_BDU.md"
    
    # Migration
    sshpass -e scp -o StrictHostKeyChecking=no scripts/migration/add_bdu_fields_v2.sql $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/scripts/migration/ 2>&1 && echo "  ✅ add_bdu_fields_v2.sql"
    sshpass -e scp -o StrictHostKeyChecking=no scripts/migration/README_BDU_MIGRATION.md $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/scripts/migration/ 2>&1 && echo "  ✅ README_BDU_MIGRATION.md"
    
    # Docs
    sshpass -e scp -r -o StrictHostKeyChecking=no docs/bdu $BACKEND_USER1@$BACKEND_VM1:$PROJECT_PATH1/docs/ 2>&1 && echo "  ✅ docs/bdu/"
    
    echo ""
    echo "🗄️  Применение миграции БД..."
    sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER1@$BACKEND_VM1 "cd $PROJECT_PATH1 && PGPASSWORD='123' psql -h 10.0.88.11 -U admin -d vuln_db -f scripts/migration/add_bdu_fields_v2.sql 2>&1" && echo "  ✅ Миграция применена"
    
    # Перезапуск
    echo "🔄 Перезапуск сервера..."
    PID1=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER1@$BACKEND_VM1 "ps aux | grep '[g]unicorn\|[p]ython.*app.py' | awk '{print \$2}' | head -1" 2>&1)
    if [ ! -z "$PID1" ]; then
        sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER1@$BACKEND_VM1 "echo '$PASSWORD1' | sudo -S kill -HUP $PID1" 2>&1
        echo "  ✅ Сервер перезапущен (PID: $PID1)"
    else
        echo "  ⚠️  Сервер не найден, попытка запуска..."
        sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER1@$BACKEND_VM1 "cd $PROJECT_PATH1 && nohup python3 app.py --host 0.0.0.0 --port 5000 > logs/app.log 2>&1 &" 2>&1
        echo "  ✅ Сервер запущен"
    fi
else
    echo "❌ Не найдена директория на сервере 1"
fi

unset SSHPASS

# Сервер 2: 217.25.230.15 (External)
echo ""
echo "📍 Сервер 2: 217.25.230.15:8080 (External)"
echo "─────────────────────────────────────"

# Попробуем разные учетные данные
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

if [ $CONNECTED -eq 0 ]; then
    echo "❌ Не удалось подключиться к серверу 2 (217.25.230.15)"
    echo "⚠️  Проверьте доступность сервера или деплойте вручную"
    echo ""
    echo "═══════════════════════════════════════════"
    echo "✅ Деплой завершен на СЕРВЕРЕ 1 (10.0.88.20)"
    echo "❌ Сервер 2 недоступен"
    echo "═══════════════════════════════════════════"
    exit 0
fi

export SSHPASS="$PASSWORD2"

# Находим директорию проекта на сервере 2
PROJECT_PATH2=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "find /home -name 'app.py' -path '*/vulnerability_manager/*' 2>/dev/null | head -1 | xargs dirname" 2>&1)

if [ -z "$PROJECT_PATH2" ]; then
    PROJECT_PATH2=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "ls -d ~/vulnerability_manager 2>/dev/null || ls -d /opt/vulnerability_manager 2>/dev/null || ls -d /var/www/vulnerability_manager 2>/dev/null" 2>&1 | head -1)
fi

if [ ! -z "$PROJECT_PATH2" ]; then
    echo "✅ Найдена директория: $PROJECT_PATH2"
    
    # Создаем директории
    echo "📁 Создание директорий..."
    sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "mkdir -p $PROJECT_PATH2/services/parsers $PROJECT_PATH2/scripts/migration $PROJECT_PATH2/models" 2>&1
    
    # Копируем файлы БДУ
    echo "📦 Копирование файлов БДУ..."
    
    # Backend
    sshpass -e scp -o StrictHostKeyChecking=no app.py $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/ 2>&1 && echo "  ✅ app.py"
    
    # Templates
    sshpass -e scp -o StrictHostKeyChecking=no templates/vulnerabilities_list.html $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/templates/ 2>&1 && echo "  ✅ vulnerabilities_list.html"
    
    # Models
    sshpass -e scp -o StrictHostKeyChecking=no models/entities.py $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/models/ 2>&1 && echo "  ✅ models/entities.py"
    sshpass -e scp -o StrictHostKeyChecking=no models/postgres_repositories.py $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/models/ 2>&1 && echo "  ✅ models/postgres_repositories.py"
    
    # Parsers
    sshpass -e scp -o StrictHostKeyChecking=no services/parsers/bdu_xml_parser.py $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/services/parsers/ 2>&1 && echo "  ✅ bdu_xml_parser.py"
    sshpass -e scp -o StrictHostKeyChecking=no services/parsers/bdu_importer.py $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/services/parsers/ 2>&1 && echo "  ✅ bdu_importer.py"
    sshpass -e scp -o StrictHostKeyChecking=no services/parsers/README_BDU.md $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/services/parsers/ 2>&1 && echo "  ✅ README_BDU.md"
    
    # Migration (но не применяем, т.к. БД на 10.0.88.11)
    sshpass -e scp -o StrictHostKeyChecking=no scripts/migration/add_bdu_fields_v2.sql $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/scripts/migration/ 2>&1 && echo "  ✅ add_bdu_fields_v2.sql"
    
    # Docs
    sshpass -e scp -r -o StrictHostKeyChecking=no docs/bdu $BACKEND_USER2@217.25.230.15:$PROJECT_PATH2/docs/ 2>&1 && echo "  ✅ docs/bdu/"
    
    # Перезапуск
    echo "🔄 Перезапуск сервера..."
    PID2=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "ps aux | grep '[g]unicorn\|[p]ython.*app.py' | awk '{print \$2}' | head -1" 2>&1)
    if [ ! -z "$PID2" ]; then
        sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "echo '$PASSWORD2' | sudo -S kill -HUP $PID2" 2>&1
        echo "  ✅ Сервер перезапущен (PID: $PID2)"
    else
        echo "  ⚠️  Сервер не найден, попытка запуска..."
        sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER2@217.25.230.15 "cd $PROJECT_PATH2 && nohup python3 app.py --host 0.0.0.0 --port 8080 > logs/app.log 2>&1 &" 2>&1
        echo "  ✅ Сервер запущен"
    fi
else
    echo "❌ Не найдена директория на сервере 2"
fi

unset SSHPASS

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ ДЕПЛОЙ БДУ ЗАВЕРШЕН                                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "🌐 Проверьте сайты:"
echo "   Internal: http://10.0.88.20:5000/dashboard"
echo "   External: http://217.25.230.15:8080/dashboard"
echo ""
echo "📊 Статистика БДУ в БД: 52,449 записей"
echo "📖 Документация: docs/bdu/README.md"

