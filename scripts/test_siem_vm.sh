#!/bin/bash
# Скрипт для тестирования и диагностики SIEM/Monitoring VM (10.0.88.41)
# Экспертное тестирование как QA тестировщик

set -e

VM_IP="10.0.88.41"
VM_USER="user"
VM_PASSWORD="123"

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔍 Экспертное тестирование SIEM/Monitoring VM${NC}"
echo "=============================================="
echo ""

# Функция для выполнения команды через SSH
ssh_exec() {
    local cmd=$1
    if command -v sshpass &> /dev/null; then
        sshpass -p "$VM_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$VM_USER@$VM_IP" "$cmd" 2>/dev/null
    else
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$VM_USER@$VM_IP" "$cmd" 2>/dev/null
    fi
}

# Функция для проверки порта
check_port() {
    local port=$1
    local service=$2
    echo -n "  Проверка порта $port ($service)... "
    if timeout 3 bash -c "echo >/dev/tcp/$VM_IP/$port" 2>/dev/null; then
        echo -e "${GREEN}✅ Открыт${NC}"
        return 0
    else
        echo -e "${RED}❌ Закрыт${NC}"
        return 1
    fi
}

# Функция для проверки HTTP сервиса
check_http() {
    local url=$1
    local service=$2
    echo -n "  Проверка $service ($url)... "
    if curl -s --connect-timeout 5 "$url" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Доступен${NC}"
        return 0
    else
        echo -e "${RED}❌ Недоступен${NC}"
        return 1
    fi
}

# ============================================
# ТЕСТ 1: Базовая доступность
# ============================================
echo -e "${BLUE}📡 ТЕСТ 1: Базовая доступность${NC}"
echo "----------------------------------------"

echo -n "Ping тест... "
if ping -c 2 -W 2 "$VM_IP" >/dev/null 2>&1; then
    echo -e "${GREEN}✅ VM доступна${NC}"
else
    echo -e "${RED}❌ VM недоступна${NC}"
    exit 1
fi

# Проверка SSH
echo -n "SSH подключение... "
if ssh_exec "echo 'SSH OK'" >/dev/null 2>&1; then
    echo -e "${GREEN}✅ SSH работает${NC}"
    SSH_OK=true
else
    echo -e "${YELLOW}⚠️  SSH не работает, проверяю альтернативные методы${NC}"
    SSH_OK=false
fi

echo ""

# ============================================
# ТЕСТ 2: Проверка портов SIEM сервисов
# ============================================
echo -e "${BLUE}🔌 ТЕСТ 2: Проверка портов SIEM сервисов${NC}"
echo "----------------------------------------"

PORTS=(
    "3000:Grafana"
    "9090:Prometheus"
    "3100:Loki"
    "9100:Node Exporter"
    "22:SSH"
)

PORT_STATUS=0
for port_info in "${PORTS[@]}"; do
    IFS=':' read -r port service <<< "$port_info"
    if ! check_port "$port" "$service"; then
        PORT_STATUS=1
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

HTTP_STATUS=0
for service_info in "${HTTP_SERVICES[@]}"; do
    IFS=':' read -r url service <<< "$service_info"
    if ! check_http "$url" "$service"; then
        HTTP_STATUS=1
    fi
done

echo ""

# ============================================
# ТЕСТ 4: Проверка Docker контейнеров (если SSH работает)
# ============================================
if [ "$SSH_OK" = true ]; then
    echo -e "${BLUE}🐳 ТЕСТ 4: Проверка Docker контейнеров${NC}"
    echo "----------------------------------------"
    
    echo "  Проверка запущенных контейнеров..."
    CONTAINERS=$(ssh_exec "docker ps --format '{{.Names}}' 2>/dev/null" || echo "")
    
    if [ -z "$CONTAINERS" ]; then
        echo -e "  ${RED}❌ Docker контейнеры не запущены${NC}"
    else
        echo -e "  ${GREEN}✅ Найдены контейнеры:${NC}"
        echo "$CONTAINERS" | while read -r container; do
            echo "    - $container"
        done
    fi
    
    echo ""
    echo "  Проверка контейнеров SIEM стека..."
    SIEM_CONTAINERS=("loki" "prometheus" "grafana" "promtail" "node-exporter")
    for container in "${SIEM_CONTAINERS[@]}"; do
        if echo "$CONTAINERS" | grep -q "$container"; then
            echo -e "    ${GREEN}✅ $container запущен${NC}"
            
            # Проверка статуса контейнера
            STATUS=$(ssh_exec "docker inspect --format='{{.State.Status}}' $container 2>/dev/null" || echo "unknown")
            if [ "$STATUS" = "running" ]; then
                echo -e "      Статус: ${GREEN}$STATUS${NC}"
            else
                echo -e "      Статус: ${RED}$STATUS${NC}"
            fi
            
            # Проверка логов на ошибки
            ERRORS=$(ssh_exec "docker logs $container --tail 20 2>&1 | grep -i 'error\|fatal\|failed' | head -3" || echo "")
            if [ -n "$ERRORS" ]; then
                echo -e "      ${YELLOW}⚠️  Найдены ошибки в логах:${NC}"
                echo "$ERRORS" | while read -r error; do
                    echo "        - $error"
                done
            fi
        else
            echo -e "    ${RED}❌ $container не запущен${NC}"
        fi
    done
    
    echo ""
fi

# ============================================
# ТЕСТ 5: Проверка файрвола
# ============================================
if [ "$SSH_OK" = true ]; then
    echo -e "${BLUE}🔥 ТЕСТ 5: Проверка файрвола${NC}"
    echo "----------------------------------------"
    
    UFW_STATUS=$(ssh_exec "sudo ufw status 2>/dev/null | head -1" || echo "unknown")
    if echo "$UFW_STATUS" | grep -q "Status: active"; then
        echo -e "  ${YELLOW}⚠️  UFW активен${NC}"
        echo "  Правила файрвола:"
        ssh_exec "sudo ufw status numbered 2>/dev/null" | head -20 || true
    else
        echo -e "  ${GREEN}✅ UFW не активен или не установлен${NC}"
    fi
    
    echo ""
fi

# ============================================
# ТЕСТ 6: Проверка системных ресурсов
# ============================================
if [ "$SSH_OK" = true ]; then
    echo -e "${BLUE}💻 ТЕСТ 6: Системные ресурсы${NC}"
    echo "----------------------------------------"
    
    echo "  CPU использование:"
    ssh_exec "top -bn1 | grep 'Cpu(s)' | head -1" || echo "    Не удалось получить данные"
    
    echo "  Память:"
    ssh_exec "free -h | grep Mem" || echo "    Не удалось получить данные"
    
    echo "  Диск:"
    ssh_exec "df -h / | tail -1" || echo "    Не удалось получить данные"
    
    echo ""
fi

# ============================================
# ТЕСТ 7: Проверка конфигурации сервисов
# ============================================
if [ "$SSH_OK" = true ]; then
    echo -e "${BLUE}⚙️  ТЕСТ 7: Конфигурация сервисов${NC}"
    echo "----------------------------------------"
    
    # Проверка наличия директории monitoring
    if ssh_exec "test -d ~/monitoring" 2>/dev/null; then
        echo -e "  ${GREEN}✅ Директория ~/monitoring существует${NC}"
        
        # Проверка структуры
        echo "  Структура директории:"
        ssh_exec "ls -la ~/monitoring 2>/dev/null" | head -10 || true
    else
        echo -e "  ${RED}❌ Директория ~/monitoring не найдена${NC}"
    fi
    
    # Проверка docker-compose файлов
    if ssh_exec "test -f ~/monitoring/monitoring-stack/loki/docker-compose.yml" 2>/dev/null; then
        echo -e "  ${GREEN}✅ Loki docker-compose найден${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Loki docker-compose не найден${NC}"
    fi
    
    if ssh_exec "test -f ~/monitoring/monitoring-stack/prometheus/docker-compose.yml" 2>/dev/null; then
        echo -e "  ${GREEN}✅ Prometheus docker-compose найден${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Prometheus docker-compose не найден${NC}"
    fi
    
    echo ""
fi

# ============================================
# РЕКОМЕНДАЦИИ ПО ИСПРАВЛЕНИЮ
# ============================================
echo -e "${BLUE}💡 РЕКОМЕНДАЦИИ ПО ИСПРАВЛЕНИЮ${NC}"
echo "=============================================="

if [ "$SSH_OK" = false ]; then
    echo -e "${YELLOW}1. Настройка SSH доступа:${NC}"
    echo "   - Проверьте пользователя (возможно нужен другой)"
    echo "   - Настройте SSH ключи: ./scripts/setup_ssh.sh"
    echo "   - Проверьте пароль: $VM_PASSWORD"
    echo ""
fi

if [ $PORT_STATUS -ne 0 ]; then
    echo -e "${YELLOW}2. Проблемы с портами:${NC}"
    echo "   - Проверьте, запущены ли контейнеры"
    echo "   - Проверьте файрвол (если активен)"
    echo "   - Проверьте docker-compose конфигурацию"
    echo ""
fi

if [ $HTTP_STATUS -ne 0 ]; then
    echo -e "${YELLOW}3. Проблемы с HTTP сервисами:${NC}"
    echo "   - Проверьте логи контейнеров: docker logs <container>"
    echo "   - Проверьте конфигурацию сервисов"
    echo "   - Убедитесь, что контейнеры запущены: docker ps"
    echo ""
fi

if [ "$SSH_OK" = true ]; then
    UFW_ACTIVE=$(ssh_exec "sudo ufw status 2>/dev/null | grep 'Status: active'" || echo "")
    if [ -n "$UFW_ACTIVE" ]; then
        echo -e "${YELLOW}4. Отключение файрвола (как запрошено):${NC}"
        echo "   Выполните на VM:"
        echo "   sudo ufw disable"
        echo "   или"
        echo "   sudo ufw --force reset"
        echo ""
    fi
fi

# ============================================
# ИТОГОВЫЙ ОТЧЕТ
# ============================================
echo -e "${BLUE}📊 ИТОГОВЫЙ ОТЧЕТ${NC}"
echo "=============================================="

TOTAL_TESTS=0
PASSED_TESTS=0

# Тест доступности
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if ping -c 1 -W 2 "$VM_IP" >/dev/null 2>&1; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
fi

# Тест SSH
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if [ "$SSH_OK" = true ]; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
fi

# Тест портов
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if [ $PORT_STATUS -eq 0 ]; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
fi

# Тест HTTP
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if [ $HTTP_STATUS -eq 0 ]; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
fi

echo "Пройдено тестов: $PASSED_TESTS / $TOTAL_TESTS"

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo -e "${GREEN}✅ Все тесты пройдены успешно!${NC}"
    exit 0
else
    echo -e "${RED}❌ Некоторые тесты не пройдены${NC}"
    exit 1
fi

