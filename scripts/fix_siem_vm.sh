#!/bin/bash
# Скрипт для исправления проблем с SIEM/Monitoring VM
# Отключает файрвол и проверяет/запускает сервисы

set -e

VM_IP="10.0.88.41"

# Попробуем разные варианты пользователей
USERS=("user" "admin" "ubuntu" "root" "test")
PASSWORD="123"

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔧 Исправление проблем с SIEM VM${NC}"
echo "=============================================="
echo ""

# Функция для выполнения команды через SSH
ssh_exec() {
    local user=$1
    local cmd=$2
    if command -v sshpass &> /dev/null; then
        sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$user@$VM_IP" "$cmd" 2>/dev/null
    else
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$user@$VM_IP" "$cmd" 2>/dev/null
    fi
}

# Поиск рабочего пользователя
echo -e "${BLUE}🔍 Поиск рабочего SSH пользователя...${NC}"
WORKING_USER=""
for user in "${USERS[@]}"; do
    echo -n "  Проверка пользователя '$user'... "
    if ssh_exec "$user" "echo 'OK'" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ Работает${NC}"
        WORKING_USER=$user
        break
    else
        echo -e "${RED}❌ Не работает${NC}"
    fi
done

if [ -z "$WORKING_USER" ]; then
    echo -e "${RED}❌ Не удалось подключиться ни с одним пользователем${NC}"
    echo ""
    echo "Возможные причины:"
    echo "  1. Файрвол блокирует SSH (порт 22)"
    echo "  2. SSH сервис не запущен"
    echo "  3. Неправильный пароль"
    echo "  4. VM не настроена"
    echo ""
    echo "Рекомендации:"
    echo "  - Проверьте доступ к консоли VM"
    echo "  - Убедитесь, что SSH сервис запущен: sudo systemctl start ssh"
    echo "  - Отключите файрвол вручную на VM: sudo ufw disable"
    exit 1
fi

echo -e "${GREEN}✅ Найден рабочий пользователь: $WORKING_USER${NC}"
echo ""

# ============================================
# ШАГ 1: Отключение файрвола
# ============================================
echo -e "${BLUE}🔥 ШАГ 1: Отключение файрвола${NC}"
echo "----------------------------------------"

# Проверка статуса UFW
UFW_STATUS=$(ssh_exec "$WORKING_USER" "sudo ufw status 2>/dev/null | head -1" || echo "not installed")

if echo "$UFW_STATUS" | grep -q "Status: active"; then
    echo -e "  ${YELLOW}⚠️  UFW активен, отключаю...${NC}"
    ssh_exec "$WORKING_USER" "sudo ufw --force disable" || true
    echo -e "  ${GREEN}✅ UFW отключен${NC}"
elif echo "$UFW_STATUS" | grep -q "Status: inactive"; then
    echo -e "  ${GREEN}✅ UFW уже неактивен${NC}"
else
    echo -e "  ${YELLOW}⚠️  UFW не установлен или недоступен${NC}"
fi

# Проверка iptables (если используется)
echo "  Проверка iptables..."
IPTABLES_RULES=$(ssh_exec "$WORKING_USER" "sudo iptables -L -n 2>/dev/null | wc -l" || echo "0")
if [ "$IPTABLES_RULES" -gt 3 ]; then
    echo -e "  ${YELLOW}⚠️  Найдены правила iptables${NC}"
    echo "  Очистка правил iptables..."
    ssh_exec "$WORKING_USER" "sudo iptables -F && sudo iptables -X && sudo iptables -t nat -F && sudo iptables -t nat -X && sudo iptables -t mangle -F && sudo iptables -t mangle -X && sudo iptables -P INPUT ACCEPT && sudo iptables -P FORWARD ACCEPT && sudo iptables -P OUTPUT ACCEPT" || true
    echo -e "  ${GREEN}✅ iptables очищен${NC}"
else
    echo -e "  ${GREEN}✅ iptables не блокирует${NC}"
fi

echo ""

# ============================================
# ШАГ 2: Проверка и запуск Docker
# ============================================
echo -e "${BLUE}🐳 ШАГ 2: Проверка Docker${NC}"
echo "----------------------------------------"

DOCKER_STATUS=$(ssh_exec "$WORKING_USER" "docker --version 2>/dev/null" || echo "")
if [ -n "$DOCKER_STATUS" ]; then
    echo -e "  ${GREEN}✅ Docker установлен: $DOCKER_STATUS${NC}"
    
    # Проверка статуса Docker сервиса
    DOCKER_SERVICE=$(ssh_exec "$WORKING_USER" "sudo systemctl is-active docker 2>/dev/null" || echo "unknown")
    if [ "$DOCKER_SERVICE" = "active" ]; then
        echo -e "  ${GREEN}✅ Docker сервис активен${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Docker сервис не активен, запускаю...${NC}"
        ssh_exec "$WORKING_USER" "sudo systemctl start docker && sudo systemctl enable docker" || true
        sleep 2
    fi
else
    echo -e "  ${RED}❌ Docker не установлен${NC}"
fi

echo ""

# ============================================
# ШАГ 3: Проверка контейнеров SIEM
# ============================================
echo -e "${BLUE}📦 ШАГ 3: Проверка контейнеров SIEM${NC}"
echo "----------------------------------------"

CONTAINERS=$(ssh_exec "$WORKING_USER" "docker ps -a --format '{{.Names}}' 2>/dev/null" || echo "")

if [ -z "$CONTAINERS" ]; then
    echo -e "  ${RED}❌ Контейнеры не найдены${NC}"
    echo "  Проверяю наличие docker-compose файлов..."
    
    if ssh_exec "$WORKING_USER" "test -d ~/monitoring/monitoring-stack" 2>/dev/null; then
        echo -e "  ${GREEN}✅ Директория monitoring-stack найдена${NC}"
        echo "  Запуск сервисов..."
        
        # Запуск Loki
        if ssh_exec "$WORKING_USER" "test -f ~/monitoring/monitoring-stack/loki/docker-compose.yml" 2>/dev/null; then
            echo "  Запуск Loki..."
            ssh_exec "$WORKING_USER" "cd ~/monitoring/monitoring-stack/loki && docker compose up -d" || true
        fi
        
        # Запуск Prometheus
        if ssh_exec "$WORKING_USER" "test -f ~/monitoring/monitoring-stack/prometheus/docker-compose.yml" 2>/dev/null; then
            echo "  Запуск Prometheus..."
            ssh_exec "$WORKING_USER" "cd ~/monitoring/monitoring-stack/prometheus && docker compose up -d" || true
        fi
        
        # Запуск Grafana (если есть отдельный compose)
        if ssh_exec "$WORKING_USER" "test -f ~/monitoring/monitoring-stack/grafana/docker-compose.yml" 2>/dev/null; then
            echo "  Запуск Grafana..."
            ssh_exec "$WORKING_USER" "cd ~/monitoring/monitoring-stack/grafana && docker compose up -d" || true
        fi
        
        sleep 5
    else
        echo -e "  ${RED}❌ Директория monitoring-stack не найдена${NC}"
        echo "  Возможно, SIEM система не установлена"
    fi
else
    echo "  Найденные контейнеры:"
    echo "$CONTAINERS" | while read -r container; do
        STATUS=$(ssh_exec "$WORKING_USER" "docker inspect --format='{{.State.Status}}' $container 2>/dev/null" || echo "unknown")
        if [ "$STATUS" = "running" ]; then
            echo -e "    ${GREEN}✅ $container - $STATUS${NC}"
        else
            echo -e "    ${YELLOW}⚠️  $container - $STATUS${NC}"
            echo "      Запуск контейнера..."
            ssh_exec "$WORKING_USER" "docker start $container" || true
        fi
    done
fi

echo ""

# ============================================
# ШАГ 4: Проверка портов после исправлений
# ============================================
echo -e "${BLUE}🔌 ШАГ 4: Проверка портов после исправлений${NC}"
echo "----------------------------------------"

sleep 3

PORTS=("3000:Grafana" "9090:Prometheus" "3100:Loki" "9100:Node Exporter")
for port_info in "${PORTS[@]}"; do
    IFS=':' read -r port service <<< "$port_info"
    echo -n "  Порт $port ($service)... "
    if timeout 3 bash -c "echo >/dev/tcp/$VM_IP/$port" 2>/dev/null; then
        echo -e "${GREEN}✅ Открыт${NC}"
    else
        echo -e "${RED}❌ Закрыт${NC}"
    fi
done

echo ""

# ============================================
# ШАГ 5: Проверка логов на ошибки
# ============================================
echo -e "${BLUE}📋 ШАГ 5: Проверка логов на ошибки${NC}"
echo "----------------------------------------"

SIEM_CONTAINERS=("loki" "prometheus" "grafana" "promtail")
for container in "${SIEM_CONTAINERS[@]}"; do
    if echo "$CONTAINERS" | grep -q "$container"; then
        echo "  Логи $container:"
        ERRORS=$(ssh_exec "$WORKING_USER" "docker logs $container --tail 10 2>&1 | grep -i 'error\|fatal\|failed' | head -3" || echo "")
        if [ -n "$ERRORS" ]; then
            echo -e "    ${YELLOW}⚠️  Найдены ошибки:${NC}"
            echo "$ERRORS" | while read -r error; do
                echo "      - $error"
            done
        else
            echo -e "    ${GREEN}✅ Ошибок не найдено${NC}"
        fi
    fi
done

echo ""

# ============================================
# ИТОГОВЫЙ ОТЧЕТ
# ============================================
echo -e "${BLUE}📊 ИТОГОВЫЙ ОТЧЕТ${NC}"
echo "=============================================="
echo "Пользователь: $WORKING_USER"
echo "IP: $VM_IP"
echo ""

# Финальная проверка сервисов
echo "Финальная проверка сервисов:"
curl -s --connect-timeout 3 "http://$VM_IP:3000" >/dev/null 2>&1 && echo -e "  ${GREEN}✅ Grafana доступен${NC}" || echo -e "  ${RED}❌ Grafana недоступен${NC}"
curl -s --connect-timeout 3 "http://$VM_IP:9090" >/dev/null 2>&1 && echo -e "  ${GREEN}✅ Prometheus доступен${NC}" || echo -e "  ${RED}❌ Prometheus недоступен${NC}"
curl -s --connect-timeout 3 "http://$VM_IP:3100/ready" >/dev/null 2>&1 && echo -e "  ${GREEN}✅ Loki доступен${NC}" || echo -e "  ${RED}❌ Loki недоступен${NC}"

echo ""
echo -e "${GREEN}✅ Исправление завершено!${NC}"

