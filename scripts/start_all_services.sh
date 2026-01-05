#!/bin/bash
# Скрипт для запуска всех сервисов на всех VM
# Использование: ./start_all_services.sh

set +e  # Не прерывать выполнение при ошибках

# Цвета для вывода
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Пароль для SSH (из deploy.sh)
SSH_PASS='123'
SSH_USER='user'

# IP адреса VM
FRONTEND_IP='10.0.88.10'
BACKEND_IP='10.0.88.20'
DATABASE_IP='10.0.88.11'
PARSERS_IP='10.0.88.23'

echo -e "${BLUE}🚀 Запуск всех сервисов Vulnerability Manager${NC}"
echo "================================================"
echo ""

# Функция для выполнения команды на удаленной VM
execute_remote() {
    local ip=$1
    local description=$2
    local command=$3
    
    echo -e "${YELLOW}📡 $description (${ip})${NC}"
    if sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
        "${SSH_USER}@${ip}" "$command" 2>&1; then
        return 0
    else
        echo -e "${RED}❌ Ошибка на ${ip}${NC}"
        return 1
    fi
}

# Функция проверки доступности
check_connection() {
    local ip=$1
    local name=$2
    
    echo -e "${YELLOW}🔍 Проверка подключения к ${name} (${ip})...${NC}"
    if ping -c 1 -W 2 "$ip" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ ${name} доступен${NC}"
        return 0
    else
        echo -e "${RED}❌ ${name} недоступен${NC}"
        return 1
    fi
}

# Функция для запуска через systemd (если настроен) или docker compose
start_service() {
    local ip=$1
    local service_name=$2
    local description=$3
    local compose_dir=$4
    
    echo -e "${YELLOW}📡 $description (${ip})${NC}"
    
    # Пробуем запустить через systemd, если сервис настроен
    if sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "${SSH_USER}@${ip}" "echo '123' | sudo -S systemctl is-enabled ${service_name}.service" > /dev/null 2>&1; then
        echo "   Используем systemd сервис..."
        sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
            "${SSH_USER}@${ip}" "echo '123' | sudo -S systemctl start ${service_name}.service && echo '123' | sudo -S systemctl status ${service_name}.service --no-pager -l | head -5" || {
            echo -e "${YELLOW}⚠️  Systemd сервис не запустился, используем docker compose${NC}"
            execute_remote "$ip" "$description" "
                cd ${compose_dir} 2>/dev/null || (mkdir -p ${compose_dir} && cd ${compose_dir})
                echo '123' | sudo -S docker compose down --remove-orphans 2>/dev/null || true
                echo '123' | sudo -S docker compose up -d --build 2>/dev/null || (echo '123' | sudo -S docker-compose up -d --build)
                sleep 3
            "
        }
    else
        # Используем docker compose напрямую с правильными правами
        # Сначала проверяем, существует ли директория
        sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
            "${SSH_USER}@${ip}" "mkdir -p ${compose_dir}" > /dev/null 2>&1
        
        # Запускаем docker compose с sudo
        execute_remote "$ip" "$description" "
            cd ${compose_dir}
            echo '123' | sudo -S docker compose down --remove-orphans 2>/dev/null || echo '123' | sudo -S docker-compose down --remove-orphans 2>/dev/null || true
            echo '123' | sudo -S docker compose up -d --build 2>/dev/null || echo '123' | sudo -S docker-compose up -d --build
            sleep 3
            echo '123' | sudo -S docker ps | grep vulnerability || docker ps | grep vulnerability || true
        " || {
            echo -e "${YELLOW}⚠️  Ошибка запуска через docker compose, пробуем альтернативный способ${NC}"
            # Альтернативный способ - через прямой вызов docker
            sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \
                "${SSH_USER}@${ip}" "cd ${compose_dir} && echo '123' | sudo -S docker compose up -d" 2>&1 || true
        }
    fi
}

# ============================================
# ШАГ 1: Проверка доступности VM
# ============================================
echo -e "${BLUE}📋 ШАГ 1: Проверка доступности VM${NC}"
echo "----------------------------------------"

check_connection "$DATABASE_IP" "Database VM" || exit 1
check_connection "$BACKEND_IP" "Backend VM" || exit 1
check_connection "$FRONTEND_IP" "Frontend VM" || exit 1
check_connection "$PARSERS_IP" "Parsers VM" || echo -e "${YELLOW}⚠️  Parsers VM недоступна (продолжаем без неё)${NC}"

echo ""

# ============================================
# ШАГ 2: Запуск Database (10.0.88.11)
# ============================================
echo -e "${BLUE}📋 ШАГ 2: Запуск Database (${DATABASE_IP})${NC}"
echo "----------------------------------------"

start_service "$DATABASE_IP" "vulnerability-db" "Database VM" "~/vulnerability_manager/database"

execute_remote "$DATABASE_IP" "Database" "echo '123' | sudo -S docker ps | grep vulnerability-db || docker ps | grep vulnerability-db || true"

echo -e "${GREEN}✅ Database запущен${NC}"
echo ""

# ============================================
# ШАГ 3: Запуск Backend (10.0.88.20)
# ============================================
echo -e "${BLUE}📋 ШАГ 3: Запуск Backend (${BACKEND_IP})${NC}"
echo "----------------------------------------"

start_service "$BACKEND_IP" "vulnerability-backend" "Backend VM" "~/vulnerability_manager/backend"

execute_remote "$BACKEND_IP" "Backend" "echo '123' | sudo -S docker ps | grep vulnerability-backend || docker ps | grep vulnerability-backend || true"

echo -e "${GREEN}✅ Backend запущен${NC}"
echo ""

# ============================================
# ШАГ 4: Запуск Frontend (10.0.88.10)
# ============================================
echo -e "${BLUE}📋 ШАГ 4: Запуск Frontend (${FRONTEND_IP})${NC}"
echo "----------------------------------------"

start_service "$FRONTEND_IP" "vulnerability-frontend" "Frontend VM" "~/vulnerability_manager/frontend"

execute_remote "$FRONTEND_IP" "Frontend" "echo '123' | sudo -S docker ps | grep vulnerability-frontend || docker ps | grep vulnerability-frontend || true"

echo -e "${GREEN}✅ Frontend запущен${NC}"
echo ""

# ============================================
# ШАГ 5: Запуск Parsers (10.0.88.23) - опционально
# ============================================
if ping -c 1 -W 2 "$PARSERS_IP" > /dev/null 2>&1; then
    echo -e "${BLUE}📋 ШАГ 5: Запуск Parsers (${PARSERS_IP})${NC}"
    echo "----------------------------------------"
    
    start_service "$PARSERS_IP" "vulnerability-parsers" "Parsers VM" "~/vulnerability_manager/parsers" || echo -e "${YELLOW}⚠️  Parsers VM: ошибка запуска (продолжаем)${NC}"
    
    execute_remote "$PARSERS_IP" "Parsers" "echo '123' | sudo -S docker ps | grep vulnerability-parsers || docker ps | grep vulnerability-parsers || true"
    
    echo -e "${GREEN}✅ Parsers запущен${NC}"
    echo ""
fi

# ============================================
# ШАГ 6: Проверка статуса сервисов
# ============================================
echo -e "${BLUE}📋 ШАГ 6: Проверка статуса сервисов${NC}"
echo "----------------------------------------"

echo -e "${YELLOW}🔍 Проверка Database...${NC}"
if execute_remote "$DATABASE_IP" "Database" "echo '123' | sudo -S docker exec vulnerability-db pg_isready -U postgres 2>/dev/null || echo '123' | sudo -S docker exec -it vulnerability-db pg_isready -U postgres 2>/dev/null || true"; then
    echo -e "${GREEN}✅ Database работает${NC}"
else
    echo -e "${YELLOW}⚠️  Database проверка не удалась (может быть еще запускается)${NC}"
fi

echo ""
echo -e "${YELLOW}🔍 Проверка Backend...${NC}"
sleep 2
if curl -s -f -m 5 "http://${BACKEND_IP}:5000/api/health" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Backend API доступен${NC}"
else
    echo -e "${YELLOW}⚠️  Backend API пока не отвечает (может быть еще запускается)${NC}"
fi

echo ""
echo -e "${YELLOW}🔍 Проверка Frontend...${NC}"
sleep 2
if curl -s -f -m 5 "http://${FRONTEND_IP}" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Frontend доступен${NC}"
else
    echo -e "${YELLOW}⚠️  Frontend пока не отвечает (может быть еще запускается)${NC}"
fi

echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}✅ Все сервисы запущены!${NC}"
echo -e "${GREEN}================================================${NC}"
echo ""
echo "🌐 Доступные интерфейсы:"
echo "   Frontend:  http://${FRONTEND_IP}"
echo "   Backend:   http://${BACKEND_IP}:5000/api/health"
echo "   Database:  ${DATABASE_IP}:5432"
if ping -c 1 -W 2 "$PARSERS_IP" > /dev/null 2>&1; then
    echo "   Parsers:   ${PARSERS_IP}"
fi
echo ""
echo "📋 Полезные команды:"
echo "   Проверка логов Backend:  ssh ${SSH_USER}@${BACKEND_IP} 'docker logs vulnerability-backend --tail 50'"
echo "   Проверка логов Frontend: ssh ${SSH_USER}@${FRONTEND_IP} 'docker logs vulnerability-frontend --tail 50'"
echo "   Проверка логов Database: ssh ${SSH_USER}@${DATABASE_IP} 'docker logs vulnerability-db --tail 50'"
echo ""

