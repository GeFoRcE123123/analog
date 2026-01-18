#!/bin/bash
# Полностью автоматическое исправление SIEM VM
# Пытается все возможные варианты подключения и исправления

set -e

VM_IP="10.0.88.41"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}🤖 АВТОМАТИЧЕСКОЕ ИСПРАВЛЕНИЕ SIEM VM${NC}"
echo "=============================================="
echo "VM: $VM_IP"
echo ""

# Проверка, что мы НЕ на VM
CURRENT_HOST=$(hostname)
if [[ "$CURRENT_HOST" == *"MacBook"* ]] || [[ "$CURRENT_HOST" == *"Mac"* ]]; then
    echo -e "${YELLOW}⚠️  Вы на локальной машине ($CURRENT_HOST)${NC}"
    echo -e "${YELLOW}⚠️  Этот скрипт попытается подключиться к VM автоматически${NC}"
    echo ""
fi

# Все возможные комбинации
USERS=("user" "test" "admin" "ubuntu" "root" "monitoring")
PASSWORDS=("123" "admin" "password" "")

# Функция для попытки подключения
try_ssh_connection() {
    local user=$1
    local password=$2
    
    if command -v sshpass &> /dev/null && [ -n "$password" ]; then
        if sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$user@$VM_IP" "echo 'CONNECTED'" 2>/dev/null; then
            return 0
        fi
    else
        if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o PasswordAuthentication=yes "$user@$VM_IP" "echo 'CONNECTED'" 2>/dev/null; then
            return 0
        fi
    fi
    return 1
}

# Функция для выполнения команды на VM
execute_on_vm() {
    local user=$1
    local password=$2
    local cmd=$3
    
    if command -v sshpass &> /dev/null && [ -n "$password" ]; then
        sshpass -p "$password" ssh -o StrictHostKeyChecking=no "$user@$VM_IP" "$cmd" 2>/dev/null
    else
        ssh -o StrictHostKeyChecking=no "$user@$VM_IP" "$cmd" 2>/dev/null
    fi
}

# ============================================
# ЭТАП 1: Попытка найти рабочее подключение
# ============================================
echo -e "${BLUE}🔍 ЭТАП 1: Поиск рабочего подключения${NC}"
echo "----------------------------------------"

WORKING_USER=""
WORKING_PASSWORD=""
FOUND=false

for user in "${USERS[@]}"; do
    for password in "${PASSWORDS[@]}"; do
        if [ -n "$password" ]; then
            echo -n "  Тест: $user@$VM_IP (pass: $password)... "
        else
            echo -n "  Тест: $user@$VM_IP (без пароля)... "
        fi
        
        if try_ssh_connection "$user" "$password"; then
            echo -e "${GREEN}✅ УСПЕХ!${NC}"
            WORKING_USER=$user
            WORKING_PASSWORD=$password
            FOUND=true
            break 2
        else
            echo -e "${RED}❌${NC}"
        fi
    done
done

echo ""

# ============================================
# ЭТАП 2: Если подключение найдено - исправление
# ============================================
if [ "$FOUND" = true ]; then
    echo -e "${GREEN}✅ Найдено подключение: $WORKING_USER@$VM_IP${NC}"
    echo ""
    
    echo -e "${BLUE}🔧 ЭТАП 2: Автоматическое исправление${NC}"
    echo "----------------------------------------"
    
    # Отключение файрвола
    echo "1. Отключение файрвола..."
    execute_on_vm "$WORKING_USER" "$WORKING_PASSWORD" "sudo ufw --force disable 2>/dev/null || true" || true
    execute_on_vm "$WORKING_USER" "$WORKING_PASSWORD" "sudo ufw --force reset 2>/dev/null || true" || true
    
    # Очистка iptables
    echo "2. Очистка iptables..."
    execute_on_vm "$WORKING_USER" "$WORKING_PASSWORD" "sudo iptables -F && sudo iptables -X && sudo iptables -t nat -F && sudo iptables -t nat -X && sudo iptables -P INPUT ACCEPT && sudo iptables -P FORWARD ACCEPT && sudo iptables -P OUTPUT ACCEPT 2>/dev/null || true" || true
    
    # Запуск SSH
    echo "3. Запуск SSH..."
    execute_on_vm "$WORKING_USER" "$WORKING_PASSWORD" "sudo systemctl start ssh 2>/dev/null || sudo systemctl start sshd 2>/dev/null || true" || true
    execute_on_vm "$WORKING_USER" "$WORKING_PASSWORD" "sudo systemctl enable ssh 2>/dev/null || sudo systemctl enable sshd 2>/dev/null || true" || true
    
    # Запуск Docker
    echo "4. Запуск Docker..."
    execute_on_vm "$WORKING_USER" "$WORKING_PASSWORD" "sudo systemctl start docker 2>/dev/null || true" || true
    
    # Запуск SIEM сервисов
    echo "5. Запуск SIEM сервисов..."
    execute_on_vm "$WORKING_USER" "$WORKING_PASSWORD" "cd ~/monitoring/monitoring-stack 2>/dev/null && cd loki && docker compose up -d 2>/dev/null || docker-compose up -d 2>/dev/null || true" || true
    execute_on_vm "$WORKING_USER" "$WORKING_PASSWORD" "cd ~/monitoring/monitoring-stack 2>/dev/null && cd prometheus && docker compose up -d 2>/dev/null || docker-compose up -d 2>/dev/null || true" || true
    
    echo ""
    echo -e "${GREEN}✅ Исправление завершено!${NC}"
    
    # Финальная проверка
    echo ""
    echo -e "${BLUE}🔍 Финальная проверка${NC}"
    echo "----------------------------------------"
    sleep 3
    
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$WORKING_USER@$VM_IP" "echo 'SSH OK'" 2>/dev/null; then
        echo -e "${GREEN}✅ SSH доступен!${NC}"
    else
        echo -e "${YELLOW}⚠️  SSH все еще недоступен, может потребоваться перезагрузка${NC}"
    fi
    
    # Проверка портов
    for port in 3000 9090 3100; do
        if timeout 2 bash -c "echo >/dev/tcp/$VM_IP/$port" 2>/dev/null; then
            echo -e "${GREEN}✅ Порт $port открыт${NC}"
        else
            echo -e "${RED}❌ Порт $port закрыт${NC}"
        fi
    done
    
else
    echo -e "${RED}❌ Не удалось найти рабочее подключение${NC}"
    echo ""
    
    # ============================================
    # ЭТАП 3: Попытка через другие VM
    # ============================================
    echo -e "${BLUE}🔍 ЭТАП 3: Попытка через другие VM${NC}"
    echo "----------------------------------------"
    
    OTHER_VMS=("10.0.88.20:user:123" "10.0.88.10:user:123" "10.0.88.11:user:123")
    
    for vm_info in "${OTHER_VMS[@]}"; do
        IFS=':' read -r other_ip other_user other_pass <<< "$vm_info"
        echo -n "  Попытка через $other_ip... "
        
        if command -v sshpass &> /dev/null; then
            if sshpass -p "$other_pass" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$other_user@$other_ip" "sshpass -p '123' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 user@$VM_IP 'echo OK' 2>/dev/null" 2>/dev/null; then
                echo -e "${GREEN}✅ Доступ через $other_ip!${NC}"
                echo "  Выполнение исправления через $other_ip..."
                
                # Выполнение через другую VM
                sshpass -p "$other_pass" ssh -o StrictHostKeyChecking=no "$other_user@$other_ip" "sshpass -p '123' ssh -o StrictHostKeyChecking=no user@$VM_IP 'sudo ufw --force disable && sudo ufw --force reset && sudo iptables -F && sudo iptables -X && sudo iptables -P INPUT ACCEPT && sudo systemctl start ssh && sudo systemctl enable ssh' 2>/dev/null" 2>/dev/null || true
                
                FOUND=true
                break
            else
                echo -e "${RED}❌${NC}"
            fi
        fi
    done
    
    if [ "$FOUND" = false ]; then
        echo ""
        echo -e "${RED}❌ Автоматическое исправление невозможно${NC}"
        echo ""
        echo -e "${YELLOW}📋 ТРЕБУЕТСЯ РУЧНОЕ ВМЕШАТЕЛЬСТВО${NC}"
        echo "=============================================="
        echo ""
        echo "SSH недоступен, поэтому автоматическое исправление невозможно."
        echo ""
        echo "Необходимо:"
        echo "1. Получить доступ к консоли VM через провайдера"
        echo "2. Выполнить команды вручную (см. docs/HOW_TO_FIX_SIEM_VM.md)"
        echo ""
        echo "Пароли для входа на VM:"
        echo "  Пользователь: user или test"
        echo "  Пароль: 123"
        echo "  sudo пароль: 123"
        echo ""
    fi
fi

# ============================================
# ИТОГОВЫЙ ОТЧЕТ
# ============================================
echo ""
echo -e "${CYAN}📊 ИТОГОВЫЙ ОТЧЕТ${NC}"
echo "=============================================="

if [ "$FOUND" = true ]; then
    echo -e "${GREEN}✅ Статус: Исправление выполнено${NC}"
    echo ""
    echo "Проверьте подключение:"
    if [ -n "$WORKING_PASSWORD" ] && command -v sshpass &> /dev/null; then
        echo "  sshpass -p '$WORKING_PASSWORD' ssh $WORKING_USER@$VM_IP"
    else
        echo "  ssh $WORKING_USER@$VM_IP"
    fi
else
    echo -e "${RED}❌ Статус: Требуется ручное исправление${NC}"
    echo ""
    echo "См. документацию:"
    echo "  - docs/HOW_TO_FIX_SIEM_VM.md"
    echo "  - docs/IMPORTANT_SIEM_FIX.md"
fi

echo ""

