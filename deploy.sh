#!/bin/bash
# Скрипт для развертывания на 4 VM
# Использование: ./deploy.sh [frontend|backend|database|parsers|all]

set -e

FRONTEND_IP="10.0.88.10"
BACKEND_IP="10.0.88.20"
DATABASE_IP="10.0.88.11"
PARSERS_IP="10.0.88.23"

USER="user"
PASSWORD="123"

DEPLOY_TARGET=${1:-all}

echo "🚀 Начало развертывания Vulnerability Manager"
echo "=============================================="

# Функция проверки доступности VM
check_vm_availability() {
    local target_ip=$1
    local vm_name=$2
    
    echo "🔍 Проверка доступности $vm_name ($target_ip)..."
    if ping -c 1 -W 2 "$target_ip" >/dev/null 2>&1; then
        echo "✅ $vm_name доступен"
        return 0
    else
        echo "❌ $vm_name недоступен (ping failed)"
        echo "💡 Проверьте:"
        echo "   - VM запущена?"
        echo "   - Правильный IP адрес?"
        echo "   - Сетевая доступность?"
        return 1
    fi
}

# Проверка наличия sshpass
if ! command -v sshpass &> /dev/null; then
    echo "⚠️  sshpass не найден. Пытаемся использовать ssh с ключами..."
    echo "💡 Для установки sshpass на macOS: brew install hudochenkov/sshpass/sshpass"
    echo "💡 Или настройте SSH ключи для автоматического входа"
    USE_SSHPASS=false
else
    USE_SSHPASS=true
fi

# Функция для копирования файлов через scp
copy_files() {
    local target_ip=$1
    local source_dir=$2
    local target_dir=$3
    
    # Убираем завершающий слэш из source_dir
    local clean_source="${source_dir%/}"
    
    # Проверяем существование source_dir
    if [ ! -d "$clean_source" ] && [ ! -f "$clean_source" ]; then
        echo "❌ Ошибка: $clean_source не существует!"
        return 1
    fi
    
    echo "📦 Копирование файлов на $target_ip..."
    
    # Получаем абсолютный путь на удаленной машине и создаем директорию
    local abs_target_dir
    if [ "$USE_SSHPASS" = true ]; then
        abs_target_dir=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "mkdir -p $target_dir && cd $target_dir && pwd")
    else
        abs_target_dir=$(ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "mkdir -p $target_dir && cd $target_dir && pwd")
    fi
    
    local target_parent=$(dirname "$abs_target_dir")
    local dir_name=$(basename "$abs_target_dir")
    
    # Копируем через временную директорию, затем перемещаем
    if [ "$USE_SSHPASS" = true ]; then
        sshpass -p "$PASSWORD" scp -r -o StrictHostKeyChecking=no "$clean_source" "$USER@$target_ip:$target_parent/.tmp_${dir_name}_$$" && \
        sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "rm -rf $abs_target_dir 2>/dev/null; mv $target_parent/.tmp_${dir_name}_$$ $abs_target_dir"
    else
        scp -r -o StrictHostKeyChecking=no "$clean_source" "$USER@$target_ip:$target_parent/.tmp_${dir_name}_$$" && \
        ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "rm -rf $abs_target_dir 2>/dev/null; mv $target_parent/.tmp_${dir_name}_$$ $abs_target_dir"
    fi
    echo "✅ Файлы скопированы на $target_ip"
}

# Функция для определения команды docker compose
get_docker_compose_cmd() {
    local target_ip=$1
    local cmd=""
    if [ "$USE_SSHPASS" = true ]; then
        cmd=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "if command -v docker-compose >/dev/null 2>&1; then echo 'docker-compose'; else echo 'docker compose'; fi")
    else
        cmd=$(ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "if command -v docker-compose >/dev/null 2>&1; then echo 'docker-compose'; else echo 'docker compose'; fi")
    fi
    echo "$cmd"
}

# Функция для выполнения команды на удаленной VM
run_remote() {
    local target_ip=$1
    local command=$2
    
    echo "🔧 Выполнение команды на $target_ip: $command"
    if [ "$USE_SSHPASS" = true ]; then
        sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "$command"
    else
        ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "$command"
    fi
}

# Функция для выполнения docker compose команд с автоматическим sudo
run_docker_compose() {
    local target_ip=$1
    local work_dir=$2
    local action=$3  # down, up, build, etc.
    
    DOCKER_COMPOSE_CMD=$(get_docker_compose_cmd "$target_ip")
    
    # Сначала пробуем без sudo, если не работает - используем sudo с паролем
    # Для down используем --remove-orphans чтобы удалить все связанные контейнеры
    if [[ "$action" == "down" ]]; then
        local full_command="cd $work_dir && ($DOCKER_COMPOSE_CMD down --remove-orphans 2>/dev/null || echo '$PASSWORD' | sudo -S $DOCKER_COMPOSE_CMD down --remove-orphans)"
    else
        local full_command="cd $work_dir && ($DOCKER_COMPOSE_CMD $action 2>/dev/null || echo '$PASSWORD' | sudo -S $DOCKER_COMPOSE_CMD $action)"
    fi
    
    run_remote "$target_ip" "$full_command"
}

# Database
if [ "$DEPLOY_TARGET" == "database" ] || [ "$DEPLOY_TARGET" == "all" ]; then
    echo ""
    echo "📊 Развертывание Database на $DATABASE_IP"
    echo "----------------------------------------"
    
    if ! check_vm_availability "$DATABASE_IP" "Database VM"; then
        echo "⚠️  Пропуск Database - VM недоступна"
        echo "   Используйте: ping $DATABASE_IP для диагностики"
        if [ "$DEPLOY_TARGET" == "database" ]; then
            exit 1
        fi
    else
        copy_files "$DATABASE_IP" "services/database" "~/vulnerability_manager/database"
    
    # Останавливаем существующий PostgreSQL если он запущен
    echo "🔧 Проверка порта 5432 на $DATABASE_IP..."
    run_remote "$DATABASE_IP" "sudo systemctl stop postgresql 2>/dev/null || true; sudo docker ps -q --filter 'publish=5432' | xargs -r sudo docker stop 2>/dev/null || true"
    
    # Используем sudo для всех docker команд
    run_docker_compose "$DATABASE_IP" "~/vulnerability_manager/database" "down"
    run_docker_compose "$DATABASE_IP" "~/vulnerability_manager/database" "up -d --build"
        
        echo "✅ Database развернута"
    fi
fi

# Backend
if [ "$DEPLOY_TARGET" == "backend" ] || [ "$DEPLOY_TARGET" == "all" ]; then
    echo ""
    echo "🔌 Развертывание Backend на $BACKEND_IP"
    echo "----------------------------------------"
    
    # Создаем временную директорию с нужными файлами
    mkdir -p /tmp/backend_deploy/{models,services,utils,templates,static}
    cp -r services/backend/* /tmp/backend_deploy/
    cp config.py /tmp/backend_deploy/  # Копируем основной config.py
    cp -r models/* /tmp/backend_deploy/models/
    # Удаляем файлы с psycopg2, которые не используются в backend
    rm -f /tmp/backend_deploy/models/optimized_database.py 2>/dev/null || true
    rm -f /tmp/backend_deploy/models/optimized_postgres_repositories.py 2>/dev/null || true
    # Удаляем __pycache__ чтобы избежать проблем с импортами
    find /tmp/backend_deploy/models -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    # Копируем templates и static для рендеринга страниц
    cp -r templates/* /tmp/backend_deploy/templates/ 2>/dev/null || true
    cp -r static/* /tmp/backend_deploy/static/ 2>/dev/null || true
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
    
    copy_files "$BACKEND_IP" "/tmp/backend_deploy" "~/vulnerability_manager/backend"
    
    # Используем sudo для всех docker команд
    run_docker_compose "$BACKEND_IP" "~/vulnerability_manager/backend" "down"
    run_docker_compose "$BACKEND_IP" "~/vulnerability_manager/backend" "up -d --build"
    
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
    
    copy_files "$FRONTEND_IP" "/tmp/frontend_deploy" "~/vulnerability_manager/frontend"
    
    # Удаляем существующие контейнеры вручную перед запуском
    run_remote "$FRONTEND_IP" "echo '$PASSWORD' | sudo -S docker rm -f vulnerability-frontend 2>/dev/null || true"
    # Используем sudo для всех docker команд
    run_docker_compose "$FRONTEND_IP" "~/vulnerability_manager/frontend" "down"
    run_docker_compose "$FRONTEND_IP" "~/vulnerability_manager/frontend" "up -d --build"
    
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
    
    copy_files "$PARSERS_IP" "/tmp/parsers_deploy" "~/vulnerability_manager/parsers"
    
    # Используем sudo для всех docker команд
    run_docker_compose "$PARSERS_IP" "~/vulnerability_manager/parsers" "down"
    run_docker_compose "$PARSERS_IP" "~/vulnerability_manager/parsers" "up -d --build"
    
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

