#!/bin/bash
# Скрипт для исправления доступа к Prometheus

set -e

VM_IP="10.0.88.41"
VM_USER="test"
VM_PASSWORD="123"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔧 Исправление доступа к Prometheus${NC}"
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

echo -e "${BLUE}1. Проверка Prometheus на VM${NC}"
echo "----------------------------------------"

LOCAL_CHECK=$(run_cmd "curl -s http://localhost:9090/api/v1/status/config 2>&1 | head -1")
if echo "$LOCAL_CHECK" | grep -q "status"; then
    echo -e "  ${GREEN}✅ Prometheus работает на VM${NC}"
else
    echo -e "  ${RED}❌ Prometheus не работает на VM${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}2. Открытие порта 9090 в файрволе${NC}"
echo "----------------------------------------"

# Отключить UFW если активен
run_cmd "sudo ufw --force disable 2>/dev/null || true"

# Добавить правило iptables
run_cmd "sudo iptables -I INPUT -p tcp --dport 9090 -j ACCEPT 2>&1"
echo -e "  ${GREEN}✅ Правило iptables добавлено${NC}"

# Сохранить правила (если возможно)
run_cmd "sudo iptables-save > /tmp/iptables.rules 2>/dev/null || true"

echo ""
echo -e "${BLUE}3. Проверка доступности${NC}"
echo "----------------------------------------"

sleep 2

if curl -s --connect-timeout 5 "http://$VM_IP:9090/api/v1/status/config" 2>/dev/null | head -1 | grep -q "status"; then
    echo -e "  ${GREEN}✅ Prometheus доступен извне!${NC}"
else
    echo -e "  ${YELLOW}⚠️  Prometheus все еще недоступен извне${NC}"
    echo "  Возможные причины:"
    echo "    - Файрвол на уровне сети"
    echo "    - Проблемы с маршрутизацией"
    echo "    - Prometheus слушает только localhost"
fi

echo ""
echo -e "${GREEN}✅ Исправление завершено!${NC}"
echo ""
echo "Проверьте Prometheus:"
echo "  http://10.0.88.41:9090"

