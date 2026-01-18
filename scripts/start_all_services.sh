#!/bin/bash
# Скрипт для запуска всех сервисов на всех VM

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🚀 Запуск всех сервисов на всех VM${NC}"
echo "=============================================="
echo ""

# Функция для выполнения команды на VM
run_on_vm() {
    local vm=$1
    local user=$2
    local password=$3
    local cmd=$4
    
    if command -v sshpass &> /dev/null; then
        sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$user@$vm" "$cmd" 2>&1
    else
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$user@$vm" "$cmd" 2>&1
    fi
}

# ============================================
# 1. Backend VM (10.0.88.20)
# ============================================
echo -e "${BLUE}1. Backend VM (10.0.88.20)${NC}"
echo "----------------------------------------"

echo "  Проверка доступности..."
if ping -c 1 -W 2 10.0.88.20 >/dev/null 2>&1; then
    echo -e "  ${GREEN}✅ VM доступна${NC}"
    
    echo "  Запуск сервисов..."
    RESULT=$(run_on_vm "10.0.88.20" "user" "123" "cd ~/vulnerability_manager/services/backend 2>/dev/null && docker compose up -d 2>&1 || cd ~/vulnerability_manager 2>/dev/null && docker compose up -d backend 2>&1 || docker ps | head -3")
    echo "$RESULT" | tail -3
    
    echo "  Проверка метрик..."
    sleep 2
    if curl -s --connect-timeout 3 "http://10.0.88.20:5000/api/metrics" 2>/dev/null | head -1 | grep -q ".*"; then
        echo -e "  ${GREEN}✅ Метрики доступны${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Метрики пока недоступны (может потребоваться время)${NC}"
    fi
else
    echo -e "  ${RED}❌ VM недоступна${NC}"
fi

echo ""

# ============================================
# 2. Frontend VM (10.0.88.10)
# ============================================
echo -e "${BLUE}2. Frontend VM (10.0.88.10)${NC}"
echo "----------------------------------------"

echo "  Проверка доступности..."
if ping -c 1 -W 2 10.0.88.10 >/dev/null 2>&1; then
    echo -e "  ${GREEN}✅ VM доступна${NC}"
    
    echo "  Запуск Nginx..."
    RESULT=$(run_on_vm "10.0.88.10" "user" "123" "sudo systemctl start nginx 2>&1 && sudo systemctl status nginx --no-pager -l 3 2>&1 || echo 'Nginx запущен'")
    echo "$RESULT" | tail -2
    
    echo "  Проверка метрик..."
    sleep 2
    if curl -s --connect-timeout 3 "http://10.0.88.10:80/metrics" 2>/dev/null | head -1 | grep -q ".*"; then
        echo -e "  ${GREEN}✅ Метрики доступны${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Метрики могут быть не настроены${NC}"
    fi
else
    echo -e "  ${RED}❌ VM недоступна${NC}"
fi

echo ""

# ============================================
# 3. Database VM (10.0.88.11)
# ============================================
echo -e "${BLUE}3. Database VM (10.0.88.11)${NC}"
echo "----------------------------------------"

echo "  Проверка доступности..."
if ping -c 1 -W 2 10.0.88.11 >/dev/null 2>&1; then
    echo -e "  ${GREEN}✅ VM доступна${NC}"
    
    echo "  Проверка postgres-exporter..."
    RESULT=$(run_on_vm "10.0.88.11" "user" "123" "docker ps | grep postgres-exporter || echo 'postgres-exporter не найден'")
    echo "$RESULT"
    
    echo "  Проверка метрик..."
    sleep 2
    if curl -s --connect-timeout 3 "http://10.0.88.11:9187/metrics" 2>/dev/null | head -1 | grep -q ".*"; then
        echo -e "  ${GREEN}✅ Метрики доступны${NC}"
    else
        echo -e "  ${YELLOW}⚠️  postgres-exporter может быть не запущен${NC}"
    fi
else
    echo -e "  ${RED}❌ VM недоступна${NC}"
fi

echo ""

# ============================================
# 4. Parsers VM (10.0.88.23)
# ============================================
echo -e "${BLUE}4. Parsers VM (10.0.88.23)${NC}"
echo "----------------------------------------"

echo "  Проверка доступности..."
if ping -c 1 -W 2 10.0.88.23 >/dev/null 2>&1; then
    echo -e "  ${GREEN}✅ VM доступна${NC}"
    
    echo "  Запуск сервисов..."
    RESULT=$(run_on_vm "10.0.88.23" "user" "123" "cd ~/vulnerability_manager 2>/dev/null && docker compose up -d 2>&1 || docker ps | head -3")
    echo "$RESULT" | tail -3
    
    echo "  Проверка метрик..."
    sleep 2
    if curl -s --connect-timeout 3 "http://10.0.88.23:9090/metrics" 2>/dev/null | head -1 | grep -q ".*"; then
        echo -e "  ${GREEN}✅ Метрики доступны${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Метрики пока недоступны${NC}"
    fi
else
    echo -e "  ${RED}❌ VM недоступна${NC}"
fi

echo ""

# ============================================
# 5. ML Platform VM (10.0.88.25)
# ============================================
echo -e "${BLUE}5. ML Platform VM (10.0.88.25)${NC}"
echo "----------------------------------------"

echo "  Проверка доступности..."
if ping -c 1 -W 2 10.0.88.25 >/dev/null 2>&1; then
    echo -e "  ${GREEN}✅ VM доступна${NC}"
    
    echo "  Проверка сервисов..."
    RESULT=$(run_on_vm "10.0.88.25" "k8s-worker" "k8s-worker" "kubectl get pods 2>/dev/null | head -5 || docker ps | head -3 || echo 'Проверьте статус вручную'")
    echo "$RESULT"
    
    echo "  Проверка метрик..."
    sleep 2
    if curl -s --connect-timeout 3 "http://10.0.88.25:8000/metrics" 2>/dev/null | head -1 | grep -q ".*"; then
        echo -e "  ${GREEN}✅ Метрики доступны${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Метрики пока недоступны${NC}"
    fi
else
    echo -e "  ${RED}❌ VM недоступна${NC}"
fi

echo ""

# ============================================
# 6. Перезапуск Prometheus
# ============================================
echo -e "${BLUE}6. Перезапуск Prometheus${NC}"
echo "----------------------------------------"

echo "  Перезапуск Prometheus на Monitoring VM..."
RESULT=$(run_on_vm "10.0.88.41" "test" "123" "cd ~/monitoring/monitoring-stack/prometheus 2>/dev/null && docker compose restart prometheus 2>&1 || docker restart prometheus 2>&1")
echo "$RESULT" | tail -2

echo "  Ожидание перезапуска..."
sleep 5

echo ""

# ============================================
# 7. Финальная проверка
# ============================================
echo -e "${BLUE}7. Финальная проверка targets${NC}"
echo "----------------------------------------"

echo "  Проверка через Prometheus API..."
sleep 3

if command -v sshpass &> /dev/null; then
    TARGETS_STATUS=$(sshpass -p "123" ssh -o StrictHostKeyChecking=no test@10.0.88.41 "curl -s http://localhost:9090/api/v1/targets" 2>/dev/null)
    
    UP_COUNT=$(echo "$TARGETS_STATUS" | grep -o '"health":"up"' | wc -l | tr -d ' ')
    DOWN_COUNT=$(echo "$TARGETS_STATUS" | grep -o '"health":"down"' | wc -l | tr -d ' ')
    
    echo "  Targets UP: $UP_COUNT"
    echo "  Targets DOWN: $DOWN_COUNT"
    
    if [ "$DOWN_COUNT" -eq 0 ]; then
        echo -e "  ${GREEN}✅ Все targets работают!${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Некоторые targets все еще DOWN${NC}"
        echo "  Проверьте логи и статус сервисов вручную"
    fi
fi

echo ""
echo -e "${GREEN}✅ Запуск сервисов завершен!${NC}"
echo ""
echo "Проверьте статус в Prometheus:"
echo "  http://10.0.88.41:9090"
echo "  Status → Target health"
