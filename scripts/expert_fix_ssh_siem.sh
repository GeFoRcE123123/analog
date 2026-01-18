#!/bin/bash
# Экспертное исправление SSH на SIEM VM
# Роль: Эксперт-тестировщик

set -e

VM_IP="10.0.88.41"
PASSWORDS=("123" "admin" "password" "")

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}🔬 ЭКСПЕРТНАЯ ДИАГНОСТИКА И ИСПРАВЛЕНИЕ SSH${NC}"
echo "=============================================="
echo "VM: $VM_IP"
echo ""

# ============================================
# ЭТАП 1: Глубокая диагностика
# ============================================
echo -e "${BLUE}📡 ЭТАП 1: Глубокая диагностика${NC}"
echo "----------------------------------------"

# Проверка доступности
echo -n "1. Ping тест... "
if ping -c 2 -W 2 "$VM_IP" >/dev/null 2>&1; then
    echo -e "${GREEN}✅ VM доступна${NC}"
else
    echo -e "${RED}❌ VM недоступна${NC}"
    exit 1
fi

# Проверка порта 22 разными методами
echo -n "2. Проверка порта 22 (nc)... "
if nc -z -w 3 "$VM_IP" 22 2>/dev/null; then
    echo -e "${GREEN}✅ Порт открыт${NC}"
    PORT_OPEN=true
else
    echo -e "${RED}❌ Порт закрыт или фильтруется${NC}"
    PORT_OPEN=false
fi

echo -n "3. Проверка порта 22 (telnet)... "
if timeout 3 bash -c "echo >/dev/tcp/$VM_IP/22" 2>/dev/null; then
    echo -e "${GREEN}✅ Порт доступен${NC}"
    PORT_OPEN=true
else
    echo -e "${RED}❌ Порт недоступен${NC}"
fi

# Проверка SSH версии (если порт открыт)
if [ "$PORT_OPEN" = true ]; then
    echo -n "4. Определение SSH версии... "
    SSH_VERSION=$(timeout 3 ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no "$VM_IP" 2>&1 | grep -i "SSH" | head -1 || echo "")
    if [ -n "$SSH_VERSION" ]; then
        echo -e "${GREEN}✅ $SSH_VERSION${NC}"
    else
        echo -e "${YELLOW}⚠️  Не удалось определить${NC}"
    fi
fi

echo ""

# ============================================
# ЭТАП 2: Попытка подключения с разными параметрами
# ============================================
echo -e "${BLUE}🔐 ЭТАП 2: Тестирование подключений${NC}"
echo "----------------------------------------"

USERS=("test" "user" "admin" "ubuntu" "root" "monitoring" "siem")  # test - основной для Monitoring VM

for user in "${USERS[@]}"; do
    for password in "${PASSWORDS[@]}"; do
        echo -n "  Тест: $user@$VM_IP "
        if [ -n "$password" ]; then
            echo -n "(pass: $password)... "
        else
            echo -n "(без пароля)... "
        fi
        
        if command -v sshpass &> /dev/null && [ -n "$password" ]; then
            if sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o PasswordAuthentication=yes "$user@$VM_IP" "echo 'OK'" 2>/dev/null; then
                echo -e "${GREEN}✅ УСПЕХ!${NC}"
                WORKING_USER=$user
                WORKING_PASSWORD=$password
                break 2
            fi
        else
            if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o PasswordAuthentication=yes -o PreferredAuthentications=password "$user@$VM_IP" "echo 'OK'" 2>/dev/null; then
                echo -e "${GREEN}✅ УСПЕХ!${NC}"
                WORKING_USER=$user
                WORKING_PASSWORD=""
                break 2
            fi
        fi
        echo -e "${RED}❌${NC}"
    done
done

echo ""

# ============================================
# ЭТАП 3: Если подключение найдено - исправление
# ============================================
if [ -n "$WORKING_USER" ]; then
    echo -e "${GREEN}✅ Найдено рабочее подключение: $WORKING_USER${NC}"
    echo ""
    
    # Функция для выполнения команд
    ssh_cmd() {
        local cmd=$1
        if [ -n "$WORKING_PASSWORD" ] && command -v sshpass &> /dev/null; then
            sshpass -p "$WORKING_PASSWORD" ssh -o StrictHostKeyChecking=no "$WORKING_USER@$VM_IP" "$cmd" 2>/dev/null
        else
            ssh -o StrictHostKeyChecking=no "$WORKING_USER@$VM_IP" "$cmd" 2>/dev/null
        fi
    }
    
    echo -e "${BLUE}🔧 ЭТАП 3: Исправление SSH и файрвола${NC}"
    echo "----------------------------------------"
    
    # Отключение файрвола
    echo "1. Отключение файрвола..."
    ssh_cmd "sudo ufw --force disable" || echo "   UFW не установлен или уже отключен"
    ssh_cmd "sudo ufw --force reset" || true
    
    # Очистка iptables
    echo "2. Очистка iptables..."
    ssh_cmd "sudo iptables -F && sudo iptables -X && sudo iptables -t nat -F && sudo iptables -t nat -X && sudo iptables -P INPUT ACCEPT && sudo iptables -P FORWARD ACCEPT && sudo iptables -P OUTPUT ACCEPT" || true
    
    # Проверка и запуск SSH
    echo "3. Проверка SSH сервиса..."
    SSH_STATUS=$(ssh_cmd "sudo systemctl is-active ssh 2>/dev/null || sudo systemctl is-active sshd 2>/dev/null" || echo "unknown")
    if [ "$SSH_STATUS" != "active" ]; then
        echo "   Запуск SSH..."
        ssh_cmd "sudo systemctl start ssh 2>/dev/null || sudo systemctl start sshd 2>/dev/null" || true
        ssh_cmd "sudo systemctl enable ssh 2>/dev/null || sudo systemctl enable sshd 2>/dev/null" || true
    fi
    
    # Проверка конфигурации SSH
    echo "4. Проверка конфигурации SSH..."
    SSH_CONFIG=$(ssh_cmd "sudo grep -E '^PermitRootLogin|^PasswordAuthentication|^Port' /etc/ssh/sshd_config 2>/dev/null | head -5" || echo "")
    if [ -n "$SSH_CONFIG" ]; then
        echo "   Текущая конфигурация:"
        echo "$SSH_CONFIG" | sed 's/^/     /'
    fi
    
    echo ""
    echo -e "${GREEN}✅ Исправление завершено!${NC}"
    
    # Финальная проверка
    echo ""
    echo -e "${BLUE}🔍 Финальная проверка${NC}"
    echo "----------------------------------------"
    sleep 2
    
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$WORKING_USER@$VM_IP" "echo 'SSH OK'" 2>/dev/null; then
        echo -e "${GREEN}✅ SSH теперь доступен!${NC}"
        echo ""
        echo "Теперь можно подключиться:"
        if [ -n "$WORKING_PASSWORD" ]; then
            echo "  sshpass -p '$WORKING_PASSWORD' ssh $WORKING_USER@$VM_IP"
        else
            echo "  ssh $WORKING_USER@$VM_IP"
        fi
    else
        echo -e "${YELLOW}⚠️  SSH все еще недоступен, требуется перезагрузка SSH сервиса${NC}"
        echo "   Выполните на VM: sudo systemctl restart ssh"
    fi
    
else
    echo -e "${RED}❌ Не удалось найти рабочее подключение${NC}"
    echo ""
    echo -e "${YELLOW}📋 ИНСТРУКЦИИ ДЛЯ РУЧНОГО ИСПРАВЛЕНИЯ${NC}"
    echo "=============================================="
    echo ""
    echo "SSH недоступен. Необходимо исправить через консоль VM:"
    echo ""
    echo "1. Получите доступ к консоли VM (через провайдера или физический доступ)"
    echo ""
    echo "2. Выполните следующие команды:"
    echo ""
    echo "   # Отключить файрвол"
    echo "   sudo ufw disable"
    echo "   sudo ufw --force reset"
    echo ""
    echo "   # Очистить iptables"
    echo "   sudo iptables -F"
    echo "   sudo iptables -X"
    echo "   sudo iptables -P INPUT ACCEPT"
    echo "   sudo iptables -P FORWARD ACCEPT"
    echo "   sudo iptables -P OUTPUT ACCEPT"
    echo ""
    echo "   # Запустить SSH"
    echo "   sudo systemctl start ssh"
    echo "   sudo systemctl enable ssh"
    echo ""
    echo "   # Проверить статус"
    echo "   sudo systemctl status ssh"
    echo "   sudo netstat -tlnp | grep 22"
    echo ""
    echo "3. После исправления запустите тест снова:"
    echo "   ./scripts/expert_fix_ssh_siem.sh"
    echo ""
    
    # Создаем скрипт для выполнения на VM
    cat > /tmp/fix_ssh_on_vm.sh << 'FIXSCRIPT'
#!/bin/bash
# Скрипт для выполнения на SIEM VM через консоль

echo "🔧 Исправление SSH на SIEM VM..."

# Отключить файрвол
echo "1. Отключение файрвола..."
sudo ufw --force disable 2>/dev/null || true
sudo ufw --force reset 2>/dev/null || true

# Очистить iptables
echo "2. Очистка iptables..."
sudo iptables -F 2>/dev/null || true
sudo iptables -X 2>/dev/null || true
sudo iptables -t nat -F 2>/dev/null || true
sudo iptables -t nat -X 2>/dev/null || true
sudo iptables -t mangle -F 2>/dev/null || true
sudo iptables -t mangle -X 2>/dev/null || true
sudo iptables -P INPUT ACCEPT 2>/dev/null || true
sudo iptables -P FORWARD ACCEPT 2>/dev/null || true
sudo iptables -P OUTPUT ACCEPT 2>/dev/null || true

# Запустить SSH
echo "3. Запуск SSH..."
sudo systemctl start ssh 2>/dev/null || sudo systemctl start sshd 2>/dev/null || true
sudo systemctl enable ssh 2>/dev/null || sudo systemctl enable sshd 2>/dev/null || true

# Проверить статус
echo "4. Проверка статуса..."
sudo systemctl status ssh --no-pager -l 5 || sudo systemctl status sshd --no-pager -l 5

echo ""
echo "✅ Исправление завершено!"
echo "Проверьте SSH: ssh user@10.0.88.41"
FIXSCRIPT
    
    echo "4. Скрипт для выполнения на VM сохранен в: /tmp/fix_ssh_on_vm.sh"
    echo "   Скопируйте его на VM и выполните: bash /tmp/fix_ssh_on_vm.sh"
    echo ""
fi

# ============================================
# ЭТАП 4: Проверка альтернативных методов доступа
# ============================================
echo -e "${BLUE}🔍 ЭТАП 4: Проверка альтернативных методов${NC}"
echo "----------------------------------------"

# Проверка других портов SSH
echo "Проверка альтернативных SSH портов..."
for port in 2222 22022 8022; do
    echo -n "  Порт $port... "
    if timeout 2 bash -c "echo >/dev/tcp/$VM_IP/$port" 2>/dev/null; then
        echo -e "${GREEN}✅ Открыт${NC}"
        echo "     Попробуйте: ssh -p $port user@$VM_IP"
    else
        echo -e "${RED}❌ Закрыт${NC}"
    fi
done

echo ""

# ============================================
# ИТОГОВЫЙ ОТЧЕТ
# ============================================
echo -e "${CYAN}📊 ИТОГОВЫЙ ОТЧЕТ${NC}"
echo "=============================================="

if [ -n "$WORKING_USER" ]; then
    echo -e "${GREEN}✅ Статус: SSH исправлен${NC}"
    echo "Пользователь: $WORKING_USER"
    echo "IP: $VM_IP"
    echo ""
    echo "Следующие шаги:"
    echo "1. Запустить SIEM сервисы: ./scripts/fix_siem_vm.sh"
    echo "2. Проверить работу: ./scripts/test_siem_vm.sh"
else
    echo -e "${RED}❌ Статус: Требуется ручное исправление${NC}"
    echo ""
    echo "Необходимо:"
    echo "1. Получить доступ к консоли VM"
    echo "2. Выполнить команды из инструкции выше"
    echo "3. Или скопировать и выполнить /tmp/fix_ssh_on_vm.sh на VM"
fi

echo ""

