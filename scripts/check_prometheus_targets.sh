#!/bin/bash
# Скрипт для проверки и исправления Prometheus targets

set -e

VM_IP="10.0.88.41"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔍 Проверка Prometheus Targets${NC}"
echo "=============================================="
echo ""

# Функция для проверки доступности
check_service() {
    local ip=$1
    local port=$2
    local name=$3
    
    echo -n "  $name ($ip:$port)... "
    if timeout 2 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
        echo -e "${GREEN}✅ Доступен${NC}"
        return 0
    else
        echo -e "${RED}❌ Недоступен${NC}"
        return 1
    fi
}

# Функция для проверки метрик
check_metrics() {
    local url=$1
    local name=$2
    
    echo -n "  $name метрики ($url)... "
    if curl -s --connect-timeout 3 "$url" 2>/dev/null | grep -q ".*"; then
        echo -e "${GREEN}✅ Доступны${NC}"
        return 0
    else
        echo -e "${RED}❌ Недоступны${NC}"
        return 1
    fi
}

echo -e "${BLUE}1. Проверка доступности сервисов${NC}"
echo "----------------------------------------"

TARGETS=(
    "10.0.88.10:80:Frontend"
    "10.0.88.20:5000:Backend"
    "10.0.88.11:9187:Database (postgres-exporter)"
    "10.0.88.23:9090:Parsers"
    "10.0.88.25:8000:ML Platform"
)

ALL_UP=true
for target in "${TARGETS[@]}"; do
    IFS=':' read -r ip port name <<< "$target"
    if ! check_service "$ip" "$port" "$name"; then
        ALL_UP=false
    fi
done

echo ""
echo -e "${BLUE}2. Проверка endpoints метрик${NC}"
echo "----------------------------------------"

METRICS_ENDPOINTS=(
    "http://10.0.88.10:80/metrics:Frontend"
    "http://10.0.88.20:5000/api/metrics:Backend"
    "http://10.0.88.11:9187/metrics:Database"
    "http://10.0.88.23:9090/metrics:Parsers"
    "http://10.0.88.25:8000/metrics:ML Platform"
)

for endpoint in "${METRICS_ENDPOINTS[@]}"; do
    IFS=':' read -r url name <<< "$endpoint"
    check_metrics "$url" "$name"
done

echo ""
echo -e "${BLUE}3. Проверка через Prometheus API${NC}"
echo "----------------------------------------"

if command -v sshpass &> /dev/null; then
    echo "  Получение статуса targets..."
    TARGETS_STATUS=$(sshpass -p "123" ssh -o StrictHostKeyChecking=no test@$VM_IP "curl -s http://localhost:9090/api/v1/targets" 2>/dev/null)
    
    UP_COUNT=$(echo "$TARGETS_STATUS" | grep -o '"health":"up"' | wc -l | tr -d ' ')
    DOWN_COUNT=$(echo "$TARGETS_STATUS" | grep -o '"health":"down"' | wc -l | tr -d ' ')
    
    echo "  Targets UP: $UP_COUNT"
    echo "  Targets DOWN: $DOWN_COUNT"
    
    if [ "$DOWN_COUNT" -gt 0 ]; then
        echo ""
        echo "  Ошибки:"
        echo "$TARGETS_STATUS" | grep -o '"lastError":"[^"]*"' | sed 's/"lastError":"/    - /' | sed 's/"$//' | head -5
    fi
fi

echo ""
echo -e "${BLUE}📊 Итоговый отчет${NC}"
echo "=============================================="

if [ "$ALL_UP" = true ]; then
    echo -e "${GREEN}✅ Все сервисы доступны${NC}"
else
    echo -e "${RED}❌ Некоторые сервисы недоступны${NC}"
    echo ""
    echo "Рекомендации:"
    echo "1. Проверьте, запущены ли сервисы на соответствующих VM"
    echo "2. Проверьте файрволы на VM"
    echo "3. Проверьте конфигурацию Prometheus"
    echo ""
    echo "См. документацию: docs/PROMETHEUS_ALERTS_FIX.md"
fi

echo ""

