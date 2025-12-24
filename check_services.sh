#!/bin/bash
# Скрипт для проверки статуса всех сервисов
# Использование: ./check_services.sh

# Цвета
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

SSH_PASS='123'
SSH_USER='user'

FRONTEND_IP='10.0.88.10'
BACKEND_IP='10.0.88.20'
DATABASE_IP='10.0.88.11'
PARSERS_IP='10.0.88.23'

echo -e "${BLUE}🔍 Проверка статуса сервисов${NC}"
echo "================================================"
echo ""

# Проверка Database
echo -e "${YELLOW}📊 Database (${DATABASE_IP})${NC}"
if sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "${SSH_USER}@${DATABASE_IP}" "echo '123' | sudo -S docker ps | grep vulnerability-db" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Контейнер запущен${NC}"
    if sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "${SSH_USER}@${DATABASE_IP}" "echo '123' | sudo -S docker exec vulnerability-db pg_isready -U postgres" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ PostgreSQL доступен${NC}"
    else
        echo -e "${RED}❌ PostgreSQL не отвечает${NC}"
    fi
else
    echo -e "${RED}❌ Контейнер не запущен${NC}"
fi
echo ""

# Проверка Backend
echo -e "${YELLOW}📊 Backend (${BACKEND_IP})${NC}"
if sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "${SSH_USER}@${BACKEND_IP}" "echo '123' | sudo -S docker ps | grep vulnerability-backend" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Контейнер запущен${NC}"
    if curl -s -f -m 3 "http://${BACKEND_IP}:5000/api/health" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ API доступен${NC}"
    else
        echo -e "${YELLOW}⚠️  API не отвечает${NC}"
    fi
else
    echo -e "${RED}❌ Контейнер не запущен${NC}"
fi
echo ""

# Проверка Frontend
echo -e "${YELLOW}📊 Frontend (${FRONTEND_IP})${NC}"
if sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "${SSH_USER}@${FRONTEND_IP}" "echo '123' | sudo -S docker ps | grep vulnerability-frontend" > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Контейнер запущен${NC}"
    if curl -s -f -m 3 "http://${FRONTEND_IP}" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Веб-интерфейс доступен${NC}"
    else
        echo -e "${YELLOW}⚠️  Веб-интерфейс не отвечает${NC}"
    fi
else
    echo -e "${RED}❌ Контейнер не запущен${NC}"
fi
echo ""

# Проверка Parsers
if ping -c 1 -W 2 "$PARSERS_IP" > /dev/null 2>&1; then
    echo -e "${YELLOW}📊 Parsers (${PARSERS_IP})${NC}"
    if sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        "${SSH_USER}@${PARSERS_IP}" "echo '123' | sudo -S docker ps | grep vulnerability-parsers" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ Контейнер запущен${NC}"
    else
        echo -e "${RED}❌ Контейнер не запущен${NC}"
    fi
    echo ""
fi

echo -e "${BLUE}================================================${NC}"

