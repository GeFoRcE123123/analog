#!/bin/bash
# Скрипт для установки и запуска postgres-exporter на Database VM

set -e

VM_IP="10.0.88.11"
VM_USER="user"
VM_PASSWORD="123"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}📊 Установка postgres-exporter на Database VM${NC}"
echo "=============================================="
echo ""

# Функция для выполнения команды
run_cmd() {
    local cmd=$1
    if command -v sshpass &> /dev/null; then
        sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no "$VM_USER@$VM_IP" "$cmd" 2>&1
    else
        ssh -o StrictHostKeyChecking=no "$VM_USER@$VM_IP" "$cmd" 2>&1
    fi
}

echo -e "${BLUE}1. Проверка существующего postgres-exporter${NC}"
echo "----------------------------------------"

EXISTING=$(run_cmd "docker ps -a | grep postgres-exporter || echo ''")
if [ -n "$EXISTING" ]; then
    echo -e "  ${YELLOW}⚠️  postgres-exporter уже существует${NC}"
    echo "  Удаление старого контейнера..."
    run_cmd "docker rm -f postgres-exporter 2>/dev/null || true"
fi

echo ""
echo -e "${BLUE}2. Запуск postgres-exporter${NC}"
echo "----------------------------------------"

run_cmd "docker run -d \
  --name postgres-exporter \
  --restart unless-stopped \
  -p 9187:9187 \
  -e DATA_SOURCE_NAME='postgresql://admin:123@localhost:5432/vuln_db?sslmode=disable' \
  prometheuscommunity/postgres-exporter:latest"

echo ""
echo -e "${BLUE}3. Проверка запуска${NC}"
echo "----------------------------------------"

sleep 3

STATUS=$(run_cmd "docker ps | grep postgres-exporter || echo ''")
if [ -n "$STATUS" ]; then
    echo -e "  ${GREEN}✅ postgres-exporter запущен${NC}"
else
    echo -e "  ${RED}❌ postgres-exporter не запустился${NC}"
    echo "  Логи:"
    run_cmd "docker logs postgres-exporter --tail 10 2>&1" | tail -5
    exit 1
fi

echo ""
echo -e "${BLUE}4. Проверка метрик${NC}"
echo "----------------------------------------"

sleep 2

if curl -s --connect-timeout 5 "http://$VM_IP:9187/metrics" 2>/dev/null | head -1 | grep -q ".*"; then
    echo -e "  ${GREEN}✅ Метрики доступны на http://$VM_IP:9187/metrics${NC}"
else
    echo -e "  ${YELLOW}⚠️  Метрики пока недоступны (может потребоваться время)${NC}"
fi

echo ""
echo -e "${GREEN}✅ Установка завершена!${NC}"
echo ""
echo "Проверьте в Prometheus:"
echo "  http://10.0.88.41:9090"
echo "  Status → Target health"

