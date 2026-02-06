#!/bin/bash
# Скрипт для исправления Prometheus

set -e

VM_IP="10.0.88.41"
VM_USER="test"
VM_PASSWORD="123"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔧 Исправление Prometheus${NC}"
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

echo -e "${BLUE}1. Проверка статуса Prometheus${NC}"
echo "----------------------------------------"

STATUS=$(run_cmd "docker ps | grep prometheus || echo 'не запущен'")
if echo "$STATUS" | grep -q "prometheus"; then
    echo -e "  ${GREEN}✅ Контейнер запущен${NC}"
    echo "$STATUS"
else
    echo -e "  ${RED}❌ Контейнер не запущен${NC}"
fi

echo ""
echo -e "${BLUE}2. Проверка логов${NC}"
echo "----------------------------------------"
run_cmd "docker logs prometheus --tail 10 2>&1" | tail -5

echo ""
echo -e "${BLUE}3. Перезапуск Prometheus${NC}"
echo "----------------------------------------"

run_cmd "cd ~/monitoring/monitoring-stack/prometheus && docker compose restart prometheus 2>&1 || docker restart prometheus 2>&1"

echo ""
echo "  Ожидание запуска..."
sleep 5

echo ""
echo -e "${BLUE}4. Проверка после перезапуска${NC}"
echo "----------------------------------------"

STATUS=$(run_cmd "docker ps | grep prometheus || echo 'не запущен'")
if echo "$STATUS" | grep -q "prometheus"; then
    echo -e "  ${GREEN}✅ Prometheus запущен${NC}"
    echo "$STATUS"
else
    echo -e "  ${RED}❌ Prometheus не запустился${NC}"
    echo "  Логи:"
    run_cmd "docker logs prometheus --tail 20 2>&1" | tail -10
fi

echo ""
echo -e "${BLUE}5. Проверка порта${NC}"
echo "----------------------------------------"

PORT_CHECK=$(run_cmd "netstat -tlnp 2>/dev/null | grep 9090 || ss -tlnp 2>/dev/null | grep 9090 || echo 'порт не слушается'")
if echo "$PORT_CHECK" | grep -q "9090"; then
    echo -e "  ${GREEN}✅ Порт 9090 слушается${NC}"
    echo "$PORT_CHECK"
else
    echo -e "  ${RED}❌ Порт 9090 не слушается${NC}"
fi

echo ""
echo -e "${GREEN}✅ Исправление завершено!${NC}"
echo ""
echo "Проверьте Prometheus:"
echo "  http://10.0.88.41:9090"

