#!/bin/bash
# Скрипт для исправления SSH и Grafana на SIEM VM
# Выполнять НА VM через консоль

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔧 Исправление SSH и Grafana на SIEM VM${NC}"
echo "=============================================="
echo ""

# ============================================
# ШАГ 1: Отключение файрвола для SSH
# ============================================
echo -e "${BLUE}1. Настройка файрвола для SSH${NC}"
echo "----------------------------------------"

# Отключить файрвол полностью (как запрошено ранее)
echo "Отключение UFW..."
sudo ufw --force disable 2>/dev/null || true
sudo ufw --force reset 2>/dev/null || true

# Очистить iptables
echo "Очистка iptables..."
sudo iptables -F 2>/dev/null || true
sudo iptables -X 2>/dev/null || true
sudo iptables -t nat -F 2>/dev/null || true
sudo iptables -t nat -X 2>/dev/null || true
sudo iptables -t mangle -F 2>/dev/null || true
sudo iptables -t mangle -X 2>/dev/null || true
sudo iptables -P INPUT ACCEPT 2>/dev/null || true
sudo iptables -P FORWARD ACCEPT 2>/dev/null || true
sudo iptables -P OUTPUT ACCEPT 2>/dev/null || true

echo -e "${GREEN}✅ Файрвол отключен${NC}"
echo ""

# ============================================
# ШАГ 2: Запуск SSH
# ============================================
echo -e "${BLUE}2. Запуск SSH сервиса${NC}"
echo "----------------------------------------"

# Проверка установки SSH
if ! command -v sshd &> /dev/null; then
    echo "Установка SSH сервера..."
    sudo apt update
    sudo apt install -y openssh-server
fi

# Запуск SSH
echo "Запуск SSH..."
sudo systemctl start ssh 2>/dev/null || sudo systemctl start sshd 2>/dev/null || true
sudo systemctl enable ssh 2>/dev/null || sudo systemctl enable sshd 2>/dev/null || true

# Проверка статуса
SSH_STATUS=$(sudo systemctl is-active ssh 2>/dev/null || sudo systemctl is-active sshd 2>/dev/null || echo "unknown")
if [ "$SSH_STATUS" = "active" ]; then
    echo -e "${GREEN}✅ SSH сервис активен${NC}"
else
    echo -e "${YELLOW}⚠️  SSH сервис не активен, проверяю...${NC}"
    sudo systemctl status ssh --no-pager -l 10 || sudo systemctl status sshd --no-pager -l 10
fi

# Проверка порта
if sudo netstat -tlnp 2>/dev/null | grep -q ":22 " || sudo ss -tlnp 2>/dev/null | grep -q ":22 "; then
    echo -e "${GREEN}✅ Порт 22 слушается${NC}"
else
    echo -e "${YELLOW}⚠️  Порт 22 не слушается${NC}"
fi

echo ""

# ============================================
# ШАГ 3: Проверка и запуск Grafana
# ============================================
echo -e "${BLUE}3. Проверка и запуск Grafana${NC}"
echo "----------------------------------------"

# Проверка Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker не установлен${NC}"
    echo "Установка Docker..."
    sudo apt update
    sudo apt install -y docker.io docker-compose
    sudo systemctl start docker
    sudo systemctl enable docker
fi

# Проверка статуса Docker
DOCKER_STATUS=$(sudo systemctl is-active docker 2>/dev/null || echo "unknown")
if [ "$DOCKER_STATUS" = "active" ]; then
    echo -e "${GREEN}✅ Docker активен${NC}"
else
    echo "Запуск Docker..."
    sudo systemctl start docker
    sudo systemctl enable docker
fi

# Проверка контейнеров Grafana
echo "Проверка контейнеров Grafana..."
GRAFANA_CONTAINERS=$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -i grafana || echo "")

if [ -z "$GRAFANA_CONTAINERS" ]; then
    echo -e "${YELLOW}⚠️  Контейнеры Grafana не найдены${NC}"
    echo "Проверяю директорию monitoring-stack..."
    
    if [ -d ~/monitoring/monitoring-stack ]; then
        echo "Директория найдена, проверяю структуру..."
        
        # Проверка Grafana в общем compose или отдельном
        if [ -f ~/monitoring/monitoring-stack/grafana/docker-compose.yml ]; then
            echo "Запуск Grafana из отдельной директории..."
            cd ~/monitoring/monitoring-stack/grafana
            docker compose up -d 2>/dev/null || docker-compose up -d 2>/dev/null || true
        elif [ -f ~/monitoring/monitoring-stack/docker-compose.yml ]; then
            echo "Запуск Grafana из общего compose..."
            cd ~/monitoring/monitoring-stack
            docker compose up -d grafana 2>/dev/null || docker-compose up -d grafana 2>/dev/null || true
        else
            echo -e "${YELLOW}⚠️  docker-compose.yml не найден${NC}"
            echo "Создание базовой конфигурации Grafana..."
            
            mkdir -p ~/monitoring/monitoring-stack/grafana
            cd ~/monitoring/monitoring-stack/grafana
            
            cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin123
      - GF_INSTALL_PLUGINS=
    volumes:
      - grafana-data:/var/lib/grafana
    networks:
      - monitoring
    restart: unless-stopped

volumes:
  grafana-data:

networks:
  monitoring:
    driver: bridge
EOF
            
            docker compose up -d
        fi
    else
        echo -e "${YELLOW}⚠️  Директория monitoring-stack не найдена${NC}"
        echo "Создание базовой структуры..."
        mkdir -p ~/monitoring/monitoring-stack/grafana
        cd ~/monitoring/monitoring-stack/grafana
        
        cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=admin123
    volumes:
      - grafana-data:/var/lib/grafana
    restart: unless-stopped

volumes:
  grafana-data:
EOF
        
        docker compose up -d
    fi
else
    echo "Найденные контейнеры Grafana:"
    echo "$GRAFANA_CONTAINERS" | while read -r container; do
        STATUS=$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "unknown")
        if [ "$STATUS" = "running" ]; then
            echo -e "  ${GREEN}✅ $container - $STATUS${NC}"
        else
            echo -e "  ${YELLOW}⚠️  $container - $STATUS (запуск...)${NC}"
            docker start "$container" 2>/dev/null || true
        fi
    done
fi

# Ожидание запуска
sleep 3

# Проверка порта 3000
if sudo netstat -tlnp 2>/dev/null | grep -q ":3000 " || sudo ss -tlnp 2>/dev/null | grep -q ":3000 "; then
    echo -e "${GREEN}✅ Порт 3000 слушается${NC}"
else
    echo -e "${YELLOW}⚠️  Порт 3000 не слушается${NC}"
fi

echo ""

# ============================================
# ШАГ 4: Финальная проверка
# ============================================
echo -e "${BLUE}4. Финальная проверка${NC}"
echo "----------------------------------------"

echo "Проверка SSH:"
if sudo systemctl is-active --quiet ssh || sudo systemctl is-active --quiet sshd; then
    echo -e "  ${GREEN}✅ SSH активен${NC}"
else
    echo -e "  ${RED}❌ SSH не активен${NC}"
fi

echo "Проверка Grafana:"
GRAFANA_RUNNING=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i grafana || echo "")
if [ -n "$GRAFANA_RUNNING" ]; then
    echo -e "  ${GREEN}✅ Grafana запущена: $GRAFANA_RUNNING${NC}"
else
    echo -e "  ${RED}❌ Grafana не запущена${NC}"
fi

echo ""
echo -e "${GREEN}✅ Исправление завершено!${NC}"
echo ""
echo "Проверьте подключение:"
echo "  ssh test@10.0.88.41"
echo "  Password: 123"
echo ""
echo "Проверьте Grafana:"
echo "  http://10.0.88.41:3000"
echo "  Username: admin"
echo "  Password: admin123"

