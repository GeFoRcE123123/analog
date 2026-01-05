#!/bin/bash
# Ручной скрипт развертывания (без sshpass)
# Использование: ./deploy_manual.sh [frontend|backend|database|parsers|all]

set -e

FRONTEND_IP="10.0.88.10"
BACKEND_IP="10.0.88.20"
DATABASE_IP="10.0.88.11"
PARSERS_IP="10.0.88.23"

USER="user"

DEPLOY_TARGET=${1:-all}

echo "🚀 Начало развертывания Vulnerability Manager (ручной режим)"
echo "=============================================="
echo "⚠️  Внимание: Будет запрашиваться пароль для каждой VM"
echo "💡 Пароль по умолчанию: 123"
echo ""

# Функция для копирования файлов через scp
copy_files() {
    local target_ip=$1
    local source_dir=$2
    local target_dir=$3
    
    echo "📦 Копирование файлов на $target_ip..."
    echo "   Введите пароль при запросе..."
    scp -r -o StrictHostKeyChecking=no "$source_dir" "$USER@$target_ip:$target_dir"
    echo "✅ Файлы скопированы на $target_ip"
}

# Функция для выполнения команды на удаленной VM
run_remote() {
    local target_ip=$1
    local command=$2
    
    echo "🔧 Выполнение команды на $target_ip: $command"
    echo "   Введите пароль при запросе..."
    ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "$command"
}

# Database
if [ "$DEPLOY_TARGET" == "database" ] || [ "$DEPLOY_TARGET" == "all" ]; then
    echo ""
    echo "📊 Развертывание Database на $DATABASE_IP"
    echo "----------------------------------------"
    
    copy_files "$DATABASE_IP" "services/database/" "~/vulnerability_manager/database/"
    
    run_remote "$DATABASE_IP" "cd ~/vulnerability_manager/database && docker-compose down && docker-compose up -d --build"
    
    echo "✅ Database развернута"
fi

# Backend
if [ "$DEPLOY_TARGET" == "backend" ] || [ "$DEPLOY_TARGET" == "all" ]; then
    echo ""
    echo "🔌 Развертывание Backend на $BACKEND_IP"
    echo "----------------------------------------"
    
    # Создаем временную директорию с нужными файлами
    mkdir -p /tmp/backend_deploy/{models,services,utils}
    cp -r services/backend/* /tmp/backend_deploy/
    cp config.py /tmp/backend_deploy/  # Копируем основной config.py
    cp -r models/* /tmp/backend_deploy/models/
    # Копируем только нужные сервисы (без парсеров)
    cp services/vulnerability_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
    cp services/operator_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
    cp services/export_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
    cp services/assignment_manager.py /tmp/backend_deploy/services/ 2>/dev/null || true
    cp services/data_manager.py /tmp/backend_deploy/services/ 2>/dev/null || true
    cp services/analytics_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
    cp services/auth_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
    cp services/forms.py /tmp/backend_deploy/services/ 2>/dev/null || true
    # Копируем utils если есть
    if [ -d "utils" ]; then
        cp -r utils/* /tmp/backend_deploy/utils/ 2>/dev/null || true
    fi
    
    copy_files "$BACKEND_IP" "/tmp/backend_deploy/" "~/vulnerability_manager/backend/"
    
    run_remote "$BACKEND_IP" "cd ~/vulnerability_manager/backend && docker-compose down && docker-compose up -d --build"
    
    rm -rf /tmp/backend_deploy
    echo "✅ Backend развернут"
fi

# Frontend
if [ "$DEPLOY_TARGET" == "frontend" ] || [ "$DEPLOY_TARGET" == "all" ]; then
    echo ""
    echo "🎨 Развертывание Frontend на $FRONTEND_IP"
    echo "----------------------------------------"
    
    mkdir -p /tmp/frontend_deploy
    cp -r services/frontend/* /tmp/frontend_deploy/
    cp -r templates /tmp/frontend_deploy/
    cp -r static /tmp/frontend_deploy/
    
    copy_files "$FRONTEND_IP" "/tmp/frontend_deploy/" "~/vulnerability_manager/frontend/"
    
    run_remote "$FRONTEND_IP" "cd ~/vulnerability_manager/frontend && docker-compose down && docker-compose up -d --build"
    
    rm -rf /tmp/frontend_deploy
    echo "✅ Frontend развернут"
fi

# Parsers
if [ "$DEPLOY_TARGET" == "parsers" ] || [ "$DEPLOY_TARGET" == "all" ]; then
    echo ""
    echo "🤖 Развертывание Parsers на $PARSERS_IP"
    echo "----------------------------------------"
    
    mkdir -p /tmp/parsers_deploy/{models,services}
    cp -r services/parsers/* /tmp/parsers_deploy/
    cp config.py /tmp/parsers_deploy/  # Копируем основной config.py
    # Копируем только парсеры
    cp services/parsing_manager.py /tmp/parsers_deploy/services/ 2>/dev/null || true
    cp services/nvd_integration_service.py /tmp/parsers_deploy/services/ 2>/dev/null || true
    cp services/nvd_parser.py /tmp/parsers_deploy/services/ 2>/dev/null || true
    cp services/nvd_scheduler.py /tmp/parsers_deploy/services/ 2>/dev/null || true
    cp services/redhat_cve_importer.py /tmp/parsers_deploy/services/ 2>/dev/null || true
    cp services/osv_parser.py /tmp/parsers_deploy/services/ 2>/dev/null || true
    cp services/fast_osv_parser.py /tmp/parsers_deploy/services/ 2>/dev/null || true
    # Копируем models
    cp -r models/* /tmp/parsers_deploy/models/
    
    copy_files "$PARSERS_IP" "/tmp/parsers_deploy/" "~/vulnerability_manager/parsers/"
    
    run_remote "$PARSERS_IP" "cd ~/vulnerability_manager/parsers && docker-compose down && docker-compose up -d --build"
    
    rm -rf /tmp/parsers_deploy
    echo "✅ Parsers развернуты"
fi

echo ""
echo "🎉 Развертывание завершено!"
echo ""
echo "Проверка сервисов:"
echo "  Frontend:  http://$FRONTEND_IP"
echo "  Backend:   http://$BACKEND_IP:5000/api/health"
echo "  Database:  $DATABASE_IP:5432"
echo "  Parsers:   $PARSERS_IP (проверить логи: docker logs vulnerability-parsers)"

