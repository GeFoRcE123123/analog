#!/bin/bash
# Полное тестирование SIEM VM
# Проверяет все сервисы и порты

set -e

VM_IP="10.0.88.41"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}🔬 ПОЛНОЕ ТЕСТИРОВАНИЕ SIEM VM${NC}"
echo "=============================================="
echo "VM: $VM_IP"
echo "Дата: $(date)"
echo ""

TOTAL_TESTS=0
PASSED_TESTS=0

# ============================================
# ТЕСТ 1: Базовая доступность
# ============================================
echo -e "${BLUE}📡 ТЕСТ 1: Базовая доступность${NC}"
echo "----------------------------------------"

TOTAL_TESTS=$((TOTAL_TESTS + 1))
echo -n "  Ping тест... "
if ping -c 2 -W 2 "$VM_IP" >/dev/null 2>&1; then
    echo -e "${GREEN}✅ VM доступна${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo -e "${RED}❌ VM недоступна${NC}"
fi

echo ""

# ============================================
# ТЕСТ 2: Проверка портов
# ============================================
echo -e "${BLUE}🔌 ТЕСТ 2: Проверка портов${NC}"
echo "----------------------------------------"

PORTS=(
    "22:SSH"
    "3000:Grafana"
    "9090:Prometheus"
    "3100:Loki"
    "9100:Node Exporter"
)

for port_info in "${PORTS[@]}"; do
    IFS=':' read -r port service <<< "$port_info"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -n "  Порт $port ($service)... "
    if timeout 2 bash -c "echo >/dev/tcp/$VM_IP/$port" 2>/dev/null; then
        echo -e "${GREEN}✅ Открыт${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}❌ Закрыт${NC}"
    fi
done

echo ""

# ============================================
# ТЕСТ 3: Проверка HTTP сервисов
# ============================================
echo -e "${BLUE}🌐 ТЕСТ 3: Проверка HTTP сервисов${NC}"
echo "----------------------------------------"

HTTP_SERVICES=(
    "http://$VM_IP:3000:Grafana"
    "http://$VM_IP:9090:Prometheus"
    "http://$VM_IP:3100/ready:Loki"
)

for service_info in "${HTTP_SERVICES[@]}"; do
    IFS=':' read -r url service <<< "$service_info"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -n "  $service ($url)... "
    
    status=$(curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    
    if [ "$status" = "200" ] || [ "$status" = "302" ] || [ "$status" = "401" ] || [ "$status" = "204" ]; then
        echo -e "${GREEN}✅ Доступен (HTTP $status)${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    elif curl -s --connect-timeout 3 "$url" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Доступен${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}❌ Недоступен${NC}"
    fi
done

echo ""

# ============================================
# ТЕСТ 4: Проверка SSH подключения
# ============================================
echo -e "${BLUE}🔐 ТЕСТ 4: Проверка SSH подключения${NC}"
echo "----------------------------------------"

TOTAL_TESTS=$((TOTAL_TESTS + 1))
SSH_WORKING=false

for user in test user; do
    echo -n "  SSH $user@$VM_IP... "
    if command -v sshpass &> /dev/null; then
        if sshpass -p "123" ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$user@$VM_IP" "echo 'SSH OK' && hostname && whoami" 2>/dev/null; then
            echo -e "${GREEN}✅ Работает${NC}"
            SSH_WORKING=true
            PASSED_TESTS=$((PASSED_TESTS + 1))
            break
        else
            echo -e "${RED}❌ Недоступен${NC}"
        fi
    else
        if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$user@$VM_IP" "echo 'SSH OK'" 2>/dev/null; then
            echo -e "${GREEN}✅ Работает${NC}"
            SSH_WORKING=true
            PASSED_TESTS=$((PASSED_TESTS + 1))
            break
        else
            echo -e "${RED}❌ Недоступен${NC}"
        fi
    fi
done

echo ""

# ============================================
# ТЕСТ 5: Проверка API сервисов
# ============================================
echo -e "${BLUE}🔌 ТЕСТ 5: Проверка API сервисов${NC}"
echo "----------------------------------------"

# Prometheus API
TOTAL_TESTS=$((TOTAL_TESTS + 1))
echo -n "  Prometheus API... "
if curl -s --connect-timeout 3 "http://$VM_IP:9090/api/v1/status/config" 2>/dev/null | grep -q "status"; then
    echo -e "${GREEN}✅ Работает${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo -e "${RED}❌ Недоступен${NC}"
fi

# Loki API
TOTAL_TESTS=$((TOTAL_TESTS + 1))
echo -n "  Loki API... "
if curl -s --connect-timeout 3 "http://$VM_IP:3100/ready" 2>/dev/null | grep -q "ready"; then
    echo -e "${GREEN}✅ Работает${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo -e "${RED}❌ Недоступен${NC}"
fi

# Grafana API
TOTAL_TESTS=$((TOTAL_TESTS + 1))
echo -n "  Grafana API... "
grafana_status=$(curl -s --connect-timeout 3 -o /dev/null -w "%{http_code}" "http://$VM_IP:3000/api/health" 2>/dev/null || echo "000")
if [ "$grafana_status" = "200" ] || [ "$grafana_status" = "401" ]; then
    echo -e "${GREEN}✅ Работает (HTTP $grafana_status)${NC}"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo -e "${RED}❌ Недоступен${NC}"
fi

echo ""

# ============================================
# ИТОГОВЫЙ ОТЧЕТ
# ============================================
echo -e "${CYAN}📊 ИТОГОВЫЙ ОТЧЕТ${NC}"
echo "=============================================="
echo "Пройдено тестов: $PASSED_TESTS / $TOTAL_TESTS"
echo "Процент успеха: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"
echo ""

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo -e "${GREEN}✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!${NC}"
    exit 0
elif [ $PASSED_TESTS -gt $((TOTAL_TESTS / 2)) ]; then
    echo -e "${YELLOW}⚠️  Большинство тестов пройдено, но есть проблемы${NC}"
    exit 1
else
    echo -e "${RED}❌ Многие тесты не пройдены, требуется исправление${NC}"
    exit 1
fi

