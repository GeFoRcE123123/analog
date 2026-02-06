#!/bin/bash
# 🚀 DevSecOps Deployment Script для Legacy Parsers
# Автоматический деплой с тестированием каждого шага
# Использование: ./deploy_legacy_parsers.sh [frontend|backend|database|parsers|all]

set -e  # Остановка при ошибке

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Конфигурация VM
FRONTEND_IP="10.0.88.10"
BACKEND_IP="10.0.88.20"
DATABASE_IP="10.0.88.11"
PARSERS_IP="10.0.88.23"

USER="user"
PASSWORD="123"

DEPLOY_TARGET=${1:-all}

echo -e "${BLUE}🚀 DevSecOps Deployment: Legacy Parsers Integration${NC}"
echo "=============================================="
echo ""

# Функция логирования
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Функция проверки доступности VM
check_vm_availability() {
    local target_ip=$1
    local vm_name=$2
    
    log_info "Проверка доступности $vm_name ($target_ip)..."
    if ping -c 1 -W 2 "$target_ip" >/dev/null 2>&1; then
        log_success "$vm_name доступен"
        return 0
    else
        log_error "$vm_name недоступен (ping failed)"
        return 1
    fi
}

# Функция проверки Docker контейнера
check_docker_container() {
    local target_ip=$1
    local container_name=$2
    local vm_name=$3
    
    log_info "Проверка контейнера $container_name на $vm_name..."
    
    if [ "$USE_SSHPASS" = true ]; then
        local result=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "sudo docker ps --filter 'name=$container_name' --format '{{.Names}}' 2>/dev/null || echo ''")
    else
        local result=$(ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "sudo docker ps --filter 'name=$container_name' --format '{{.Names}}' 2>/dev/null || echo ''")
    fi
    
    if [ -n "$result" ]; then
        log_success "Контейнер $container_name запущен"
        return 0
    else
        log_warning "Контейнер $container_name не запущен"
        # Показываем логи для диагностики
        if [ "$USE_SSHPASS" = true ]; then
            sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "echo '$PASSWORD' | sudo -S docker logs $container_name --tail 30 2>/dev/null || echo 'Не удалось получить логи'"
        else
            ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "sudo docker logs $container_name --tail 30 2>/dev/null || echo 'Не удалось получить логи'"
        fi
        return 1
    fi
}

# Функция проверки API endpoint
check_api_endpoint() {
    local url=$1
    local endpoint_name=$2
    
    log_info "Проверка API endpoint: $endpoint_name..."
    
    local response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
    
    if [ "$response" = "200" ] || [ "$response" = "404" ]; then
        log_success "API endpoint $endpoint_name доступен (HTTP $response)"
        return 0
    else
        log_warning "API endpoint $endpoint_name недоступен (HTTP $response)"
        return 1
    fi
}

# Проверка наличия sshpass
if ! command -v sshpass &> /dev/null; then
    log_warning "sshpass не найден. Используется ssh с ключами..."
    USE_SSHPASS=false
else
    USE_SSHPASS=true
fi

# Функция для копирования файлов через scp
copy_files() {
    local target_ip=$1
    local source_dir=$2
    local target_dir=$3
    
    local clean_source="${source_dir%/}"
    
    if [ ! -d "$clean_source" ] && [ ! -f "$clean_source" ]; then
        log_error "$clean_source не существует!"
        return 1
    fi
    
    log_info "Копирование файлов на $target_ip..."
    
    local abs_target_dir
    if [ "$USE_SSHPASS" = true ]; then
        abs_target_dir=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "mkdir -p $target_dir && cd $target_dir && pwd")
    else
        abs_target_dir=$(ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "mkdir -p $target_dir && cd $target_dir && pwd")
    fi
    
    local target_parent=$(dirname "$abs_target_dir")
    local dir_name=$(basename "$abs_target_dir")
    local tmp_dir="$target_parent/.tmp_${dir_name}_$$"
    
    # Копируем во временную директорию
    if [ "$USE_SSHPASS" = true ]; then
        sshpass -p "$PASSWORD" scp -r -o StrictHostKeyChecking=no "$clean_source" "$USER@$target_ip:$tmp_dir"
    else
        scp -r -o StrictHostKeyChecking=no "$clean_source" "$USER@$target_ip:$tmp_dir"
    fi
    
    # Перемещаем файлы из временной директории в целевую
    if [ "$USE_SSHPASS" = true ]; then
        sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "
            rm -rf $abs_target_dir/* $abs_target_dir/.[!.]* 2>/dev/null || true
            cp -r $tmp_dir/* $abs_target_dir/ 2>/dev/null || true
            cp -r $tmp_dir/.[!.]* $abs_target_dir/ 2>/dev/null || true
            rm -rf $tmp_dir
            ls -la $abs_target_dir | head -5
        "
    else
        ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "
            rm -rf $abs_target_dir/* $abs_target_dir/.[!.]* 2>/dev/null || true
            cp -r $tmp_dir/* $abs_target_dir/ 2>/dev/null || true
            cp -r $tmp_dir/.[!.]* $abs_target_dir/ 2>/dev/null || true
            rm -rf $tmp_dir
            ls -la $abs_target_dir | head -5
        "
    fi
    
    # Проверяем, что файлы действительно переместились
    if [ "$USE_SSHPASS" = true ]; then
        local files_moved=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "test -f $abs_target_dir/docker-compose.yml && echo 'yes' || echo 'no'")
    else
        local files_moved=$(ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "test -f $abs_target_dir/docker-compose.yml && echo 'yes' || echo 'no'")
    fi
    
    if [ "$files_moved" = "yes" ]; then
        log_success "Файлы скопированы и перемещены на $target_ip"
    else
        log_warning "Файлы скопированы, но docker-compose.yml не найден. Проверяем содержимое..."
        run_remote "$target_ip" "ls -la $abs_target_dir/ 2>/dev/null | head -10"
    fi
}

# Функция для выполнения команды на удаленной VM
run_remote() {
    local target_ip=$1
    local command=$2
    
    log_info "Выполнение команды на $target_ip: $command"
    if [ "$USE_SSHPASS" = true ]; then
        sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "$command"
    else
        ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "$command"
    fi
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

# Функция для выполнения docker compose команд
run_docker_compose() {
    local target_ip=$1
    local work_dir=$2
    local action=$3
    
    DOCKER_COMPOSE_CMD=$(get_docker_compose_cmd "$target_ip")
    
    # Проверяем существование docker-compose.yml
    log_info "Проверка docker-compose.yml в $work_dir..."
    if [ "$USE_SSHPASS" = true ]; then
        local compose_exists=$(sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "test -f $work_dir/docker-compose.yml && echo 'yes' || echo 'no'")
    else
        local compose_exists=$(ssh -o StrictHostKeyChecking=no "$USER@$target_ip" "test -f $work_dir/docker-compose.yml && echo 'yes' || echo 'no'")
    fi
    
    if [ "$compose_exists" != "yes" ]; then
        log_error "docker-compose.yml не найден в $work_dir"
        log_info "Содержимое директории:"
        run_remote "$target_ip" "ls -la $work_dir/ 2>/dev/null | head -10"
        return 1
    fi
    
    if [[ "$action" == "down" ]]; then
        local full_command="cd $work_dir && ($DOCKER_COMPOSE_CMD down --remove-orphans 2>/dev/null || echo '$PASSWORD' | sudo -S $DOCKER_COMPOSE_CMD down --remove-orphans)"
    else
        local full_command="cd $work_dir && ($DOCKER_COMPOSE_CMD $action 2>/dev/null || echo '$PASSWORD' | sudo -S $DOCKER_COMPOSE_CMD $action)"
    fi
    
    run_remote "$target_ip" "$full_command"
}

# ============================================
# BACKEND DEPLOYMENT
# ============================================
if [ "$DEPLOY_TARGET" == "backend" ] || [ "$DEPLOY_TARGET" == "all" ]; then
    echo ""
    echo -e "${BLUE}🔌 Развертывание Backend на $BACKEND_IP${NC}"
    echo "----------------------------------------"
    
    if ! check_vm_availability "$BACKEND_IP" "Backend VM"; then
        log_error "Пропуск Backend - VM недоступна"
        if [ "$DEPLOY_TARGET" == "backend" ]; then
            exit 1
        fi
    else
        # Создаем временную директорию с нужными файлами
        log_info "Подготовка файлов для Backend..."
        mkdir -p /tmp/backend_deploy/{models,services,utils,templates,static}
        
        # Копируем основные файлы Backend
        cp -r services/backend/* /tmp/backend_deploy/
        cp config.py /tmp/backend_deploy/
        cp -r models/* /tmp/backend_deploy/models/
        
        # Копируем unified_parser_service и его зависимости
        mkdir -p /tmp/backend_deploy/services
        cp services/unified_parser_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/html_vulnerability_parser.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/universal_vendor_parser.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/redhat_cve_importer.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/nvd_integration_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/vendor_parsers.py /tmp/backend_deploy/services/ 2>/dev/null || true
        
        # ⭐ КОПИРУЕМ LEGACY ПАРСЕРЫ
        log_info "Копирование Legacy парсеров..."
        if [ -d "services/legacy_parsers" ]; then
            cp -r services/legacy_parsers /tmp/backend_deploy/services/
            log_success "Legacy парсеры скопированы"
        else
            log_error "Папка services/legacy_parsers не найдена!"
            exit 1
        fi
        
        # Копируем другие сервисы
        cp services/vulnerability_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/operator_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/export_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/assignment_manager.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/data_manager.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/analytics_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/auth_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/forms.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/ai_integration_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/security_methodology_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/security_testing_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/cve_json5_adapter.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/cve_json_loader.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/cve_org_downloader.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/cve_org_integration_service.py /tmp/backend_deploy/services/ 2>/dev/null || true
        cp services/backend/cve_sync_status.py /tmp/backend_deploy/services/ 2>/dev/null || true
        
        # Удаляем файлы с psycopg2
        rm -f /tmp/backend_deploy/models/optimized_database.py 2>/dev/null || true
        rm -f /tmp/backend_deploy/models/optimized_postgres_repositories.py 2>/dev/null || true
        find /tmp/backend_deploy/models -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
        
        # Копируем templates и static
        cp -r templates/* /tmp/backend_deploy/templates/ 2>/dev/null || true
        cp -r static/* /tmp/backend_deploy/static/ 2>/dev/null || true
        
        # Копируем utils если есть
        if [ -d "utils" ]; then
            cp -r utils/* /tmp/backend_deploy/utils/ 2>/dev/null || true
        fi
        
        # Копируем на VM
        copy_files "$BACKEND_IP" "/tmp/backend_deploy" "~/vulnerability_manager/backend"
        
        # Останавливаем и перезапускаем контейнер
        log_info "Перезапуск Backend контейнера..."
        run_docker_compose "$BACKEND_IP" "~/vulnerability_manager/backend" "down"
        run_docker_compose "$BACKEND_IP" "~/vulnerability_manager/backend" "up -d --build"
        
        # Ожидание запуска контейнера
        log_info "Ожидание запуска Backend контейнера..."
        sleep 10
        
        # Проверка контейнера
        if check_docker_container "$BACKEND_IP" "vulnerability-backend" "Backend"; then
            log_success "Backend контейнер запущен"
        else
            log_error "Backend контейнер не запущен!"
            run_remote "$BACKEND_IP" "docker logs vulnerability-backend --tail 50"
            exit 1
        fi
        
        # Проверка API
        if check_api_endpoint "http://$BACKEND_IP:5000/api/health" "Backend Health"; then
            log_success "Backend API доступен"
        else
            log_warning "Backend API недоступен, проверьте логи"
        fi
        
        rm -rf /tmp/backend_deploy
        log_success "Backend развернут"
    fi
fi

# ============================================
# FRONTEND DEPLOYMENT
# ============================================
if [ "$DEPLOY_TARGET" == "frontend" ] || [ "$DEPLOY_TARGET" == "all" ]; then
    echo ""
    echo -e "${BLUE}🎨 Развертывание Frontend на $FRONTEND_IP${NC}"
    echo "----------------------------------------"
    
    if ! check_vm_availability "$FRONTEND_IP" "Frontend VM"; then
        log_error "Пропуск Frontend - VM недоступна"
        if [ "$DEPLOY_TARGET" == "frontend" ]; then
            exit 1
        fi
    else
        log_info "Подготовка файлов для Frontend..."
        mkdir -p /tmp/frontend_deploy
        cp -r services/frontend/* /tmp/frontend_deploy/
        cp -r templates /tmp/frontend_deploy/
        cp -r static /tmp/frontend_deploy/
        
        copy_files "$FRONTEND_IP" "/tmp/frontend_deploy" "~/vulnerability_manager/frontend"
        
        log_info "Перезапуск Frontend контейнера..."
        run_remote "$FRONTEND_IP" "echo '$PASSWORD' | sudo -S docker rm -f vulnerability-frontend 2>/dev/null || true"
        run_docker_compose "$FRONTEND_IP" "~/vulnerability_manager/frontend" "down"
        run_docker_compose "$FRONTEND_IP" "~/vulnerability_manager/frontend" "up -d --build"
        
        # Ожидание запуска
        sleep 5
        
        # Проверка контейнера
        if check_docker_container "$FRONTEND_IP" "vulnerability-frontend" "Frontend"; then
            log_success "Frontend контейнер запущен"
        else
            log_warning "Frontend контейнер не запущен"
        fi
        
        # Проверка веб-сервера
        if check_api_endpoint "http://$FRONTEND_IP" "Frontend Web"; then
            log_success "Frontend веб-сервер доступен"
        else
            log_warning "Frontend веб-сервер недоступен"
        fi
        
        rm -rf /tmp/frontend_deploy
        log_success "Frontend развернут"
    fi
fi

# ============================================
# PARSERS DEPLOYMENT
# ============================================
if [ "$DEPLOY_TARGET" == "parsers" ] || [ "$DEPLOY_TARGET" == "all" ]; then
    echo ""
    echo -e "${BLUE}🤖 Развертывание Parsers на $PARSERS_IP${NC}"
    echo "----------------------------------------"
    
    if ! check_vm_availability "$PARSERS_IP" "Parsers VM"; then
        log_error "Пропуск Parsers - VM недоступна"
        if [ "$DEPLOY_TARGET" == "parsers" ]; then
            exit 1
        fi
    else
        log_info "Подготовка файлов для Parsers..."
        mkdir -p /tmp/parsers_deploy/{models,services}
        cp -r services/parsers/* /tmp/parsers_deploy/
        cp config.py /tmp/parsers_deploy/
        
        # Копируем парсеры
        cp services/parsing_manager.py /tmp/parsers_deploy/services/ 2>/dev/null || true
        cp services/nvd_integration_service.py /tmp/parsers_deploy/services/ 2>/dev/null || true
        cp services/nvd_parser.py /tmp/parsers_deploy/services/ 2>/dev/null || true
        cp services/nvd_scheduler.py /tmp/parsers_deploy/services/ 2>/dev/null || true
        cp services/redhat_cve_importer.py /tmp/parsers_deploy/services/ 2>/dev/null || true
        cp services/osv_parser.py /tmp/parsers_deploy/services/ 2>/dev/null || true
        cp services/fast_osv_parser.py /tmp/parsers_deploy/services/ 2>/dev/null || true
        
        # ⭐ КОПИРУЕМ LEGACY ПАРСЕРЫ
        log_info "Копирование Legacy парсеров..."
        if [ -d "services/legacy_parsers" ]; then
            cp -r services/legacy_parsers /tmp/parsers_deploy/services/
            log_success "Legacy парсеры скопированы"
        else
            log_error "Папка services/legacy_parsers не найдена!"
            exit 1
        fi
        
        # Копируем models
        cp -r models/* /tmp/parsers_deploy/models/
        
        copy_files "$PARSERS_IP" "/tmp/parsers_deploy" "~/vulnerability_manager/parsers"
        
        log_info "Перезапуск Parsers контейнера..."
        run_docker_compose "$PARSERS_IP" "~/vulnerability_manager/parsers" "down"
        run_docker_compose "$PARSERS_IP" "~/vulnerability_manager/parsers" "up -d --build"
        
        # Ожидание запуска
        sleep 5
        
        # Проверка контейнера
        if check_docker_container "$PARSERS_IP" "vulnerability-parsers" "Parsers"; then
            log_success "Parsers контейнер запущен"
        else
            log_warning "Parsers контейнер не запущен"
        fi
        
        rm -rf /tmp/parsers_deploy
        log_success "Parsers развернуты"
    fi
fi

# ============================================
# FINAL SUMMARY
# ============================================
echo ""
echo -e "${GREEN}🎉 Развертывание завершено!${NC}"
echo ""
echo "Проверка сервисов:"
echo "  Frontend:  http://$FRONTEND_IP"
echo "  Backend:   http://$BACKEND_IP:5000/api/health"
echo "  Database:  $DATABASE_IP:5432"
echo "  Parsers:   $PARSERS_IP"
echo ""
echo -e "${BLUE}📋 Legacy парсеры развернуты:${NC}"
echo "  - RedHat, Debian, Cisco, Cert"
echo "  - FortiGuard, IBM, PostgreSQL, SUSE"
echo "  - Palo Alto, Juniper, CyberSecurity"
echo "  - CXSecurity, Kaspersky, NVD Keywords"
echo "  - Zero Day Initiative, CVE Details"
echo ""

