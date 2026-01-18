#!/bin/bash
# Скрипт для настройки SSH подключений к VM проекта
# Использование: ./scripts/setup_ssh.sh [--with-keys]

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Конфигурация VM
declare -A VMS=(
    ["database"]="10.0.88.11:user"
    ["frontend"]="10.0.88.10:user"
    ["backend"]="10.0.88.20:user"
    ["parsers"]="10.0.88.23:user"
    ["ml-platform"]="10.0.88.25:k8s-worker"
)

# Пароли по умолчанию (можно изменить через переменные окружения)
DB_PASS=${DB_PASS:-"123"}
FRONTEND_PASS=${FRONTEND_PASS:-"123"}
BACKEND_PASS=${BACKEND_PASS:-"123"}
PARSERS_PASS=${PARSERS_PASS:-"123"}
ML_PLATFORM_PASS=${ML_PLATFORM_PASS:-"k8s-worker"}

declare -A PASSWORDS=(
    ["database"]="$DB_PASS"
    ["frontend"]="$FRONTEND_PASS"
    ["backend"]="$BACKEND_PASS"
    ["parsers"]="$PARSERS_PASS"
    ["ml-platform"]="$ML_PLATFORM_PASS"
)

echo -e "${GREEN}🔐 Настройка SSH подключений к VM проекта${NC}"
echo "=============================================="
echo ""

# Создаем директорию .ssh если её нет
mkdir -p ~/.ssh
chmod 700 ~/.ssh

# Проверяем наличие sshpass
USE_SSHPASS=false
if command -v sshpass &> /dev/null; then
    USE_SSHPASS=true
    echo -e "${GREEN}✅ sshpass найден${NC}"
else
    echo -e "${YELLOW}⚠️  sshpass не найден${NC}"
    echo "   Для установки на macOS: brew install hudochenkov/sshpass/sshpass"
    echo "   Или используйте опцию --with-keys для настройки SSH ключей"
fi

# Функция для проверки доступности VM
check_vm() {
    local vm_name=$1
    local ip=$2
    
    echo -n "🔍 Проверка $vm_name ($ip)... "
    if ping -c 1 -W 2 "$ip" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ доступна${NC}"
        return 0
    else
        echo -e "${RED}❌ недоступна${NC}"
        return 1
    fi
}

# Функция для настройки SSH ключей
setup_ssh_keys() {
    local key_name="vulnerability_manager_key"
    local key_path="$HOME/.ssh/$key_name"
    
    echo ""
    echo -e "${GREEN}🔑 Настройка SSH ключей${NC}"
    echo "----------------------------------------"
    
    # Генерируем ключ если его нет
    if [ ! -f "$key_path" ]; then
        echo "Генерация SSH ключа..."
        ssh-keygen -t ed25519 -C "vulnerability_manager@$(hostname)" -f "$key_path" -N ""
        echo -e "${GREEN}✅ SSH ключ создан: $key_path${NC}"
    else
        echo -e "${YELLOW}⚠️  SSH ключ уже существует: $key_path${NC}"
        read -p "Пересоздать? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -f "$key_path" "$key_path.pub"
            ssh-keygen -t ed25519 -C "vulnerability_manager@$(hostname)" -f "$key_path" -N ""
            echo -e "${GREEN}✅ SSH ключ пересоздан${NC}"
        fi
    fi
    
    chmod 600 "$key_path"
    chmod 644 "$key_path.pub"
    
    # Копируем ключ на каждую VM
    for vm_name in "${!VMS[@]}"; do
        IFS=':' read -r ip user <<< "${VMS[$vm_name]}"
        
        if ! check_vm "$vm_name" "$ip"; then
            echo -e "${YELLOW}⚠️  Пропуск $vm_name - VM недоступна${NC}"
            continue
        fi
        
        echo -n "📤 Копирование ключа на $vm_name ($ip)... "
        
        if [ "$USE_SSHPASS" = true ]; then
            password="${PASSWORDS[$vm_name]}"
            if sshpass -p "$password" ssh-copy-id -i "$key_path.pub" -o StrictHostKeyChecking=no "$user@$ip" 2>/dev/null; then
                echo -e "${GREEN}✅${NC}"
            else
                echo -e "${RED}❌${NC}"
                echo "   Попробуйте вручную: ssh-copy-id -i $key_path.pub $user@$ip"
            fi
        else
            if ssh-copy-id -i "$key_path.pub" -o StrictHostKeyChecking=no "$user@$ip" 2>/dev/null; then
                echo -e "${GREEN}✅${NC}"
            else
                echo -e "${YELLOW}⚠️  Требуется ввод пароля${NC}"
                ssh-copy-id -i "$key_path.pub" "$user@$ip"
            fi
        fi
    done
    
    echo ""
    echo -e "${GREEN}✅ SSH ключи настроены${NC}"
}

# Функция для создания SSH config
create_ssh_config() {
    local config_file="$HOME/.ssh/config"
    local key_path="$HOME/.ssh/vulnerability_manager_key"
    
    echo ""
    echo -e "${GREEN}📝 Создание SSH config${NC}"
    echo "----------------------------------------"
    
    # Создаем резервную копию существующего config
    if [ -f "$config_file" ]; then
        cp "$config_file" "${config_file}.backup.$(date +%Y%m%d_%H%M%S)"
        echo "✅ Резервная копия создана: ${config_file}.backup.*"
    fi
    
    # Проверяем, есть ли уже конфигурация для наших VM
    if grep -q "Host database-vm\|Host frontend-vm\|Host backend-vm\|Host parsers-vm\|Host ml-platform-vm" "$config_file" 2>/dev/null; then
        echo -e "${YELLOW}⚠️  Конфигурация для VM уже существует в $config_file${NC}"
        read -p "Перезаписать? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Пропуск создания SSH config"
            return
        fi
        # Удаляем старую конфигурацию
        sed -i.bak '/# Vulnerability Manager VM Config/,/# End Vulnerability Manager VM Config/d' "$config_file" 2>/dev/null || true
    fi
    
    # Добавляем конфигурацию
    cat >> "$config_file" << EOF

# Vulnerability Manager VM Config
# Автоматически создано скриптом setup_ssh.sh

Host database-vm
    HostName 10.0.88.11
    User user
    IdentityFile $key_path
    StrictHostKeyChecking no
    UserKnownHostsFile ~/.ssh/known_hosts

Host frontend-vm
    HostName 10.0.88.10
    User user
    IdentityFile $key_path
    StrictHostKeyChecking no
    UserKnownHostsFile ~/.ssh/known_hosts

Host backend-vm
    HostName 10.0.88.20
    User user
    IdentityFile $key_path
    StrictHostKeyChecking no
    UserKnownHostsFile ~/.ssh/known_hosts

Host parsers-vm
    HostName 10.0.88.23
    User user
    IdentityFile $key_path
    StrictHostKeyChecking no
    UserKnownHostsFile ~/.ssh/known_hosts

Host ml-platform-vm
    HostName 10.0.88.25
    User k8s-worker
    IdentityFile $key_path
    StrictHostKeyChecking no
    UserKnownHostsFile ~/.ssh/known_hosts

# End Vulnerability Manager VM Config
EOF
    
    chmod 600 "$config_file"
    echo -e "${GREEN}✅ SSH config создан: $config_file${NC}"
    echo ""
    echo "Теперь вы можете подключаться к VM используя короткие имена:"
    echo "  ssh database-vm"
    echo "  ssh frontend-vm"
    echo "  ssh backend-vm"
    echo "  ssh parsers-vm"
    echo "  ssh ml-platform-vm"
}

# Функция для тестирования подключений
test_connections() {
    echo ""
    echo -e "${GREEN}🧪 Тестирование SSH подключений${NC}"
    echo "----------------------------------------"
    
    for vm_name in "${!VMS[@]}"; do
        IFS=':' read -r ip user <<< "${VMS[$vm_name]}"
        local host_alias="${vm_name}-vm"
        
        echo -n "Тест $host_alias... "
        if ssh -o ConnectTimeout=5 -o BatchMode=yes "$host_alias" "echo 'OK'" 2>/dev/null; then
            echo -e "${GREEN}✅${NC}"
        else
            echo -e "${RED}❌${NC}"
        fi
    done
}

# Основная логика
if [ "$1" == "--with-keys" ]; then
    setup_ssh_keys
    create_ssh_config
    test_connections
else
    echo "Выберите вариант настройки:"
    echo "1. Только SSH config (без ключей, будет использоваться sshpass/пароли)"
    echo "2. Настроить SSH ключи + SSH config (рекомендуется)"
    echo ""
    read -p "Ваш выбор (1/2): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[2]$ ]]; then
        setup_ssh_keys
        create_ssh_config
        test_connections
    else
        # Создаем SSH config без ключей (для использования с паролями)
        key_path="$HOME/.ssh/id_rsa"  # Используем стандартный ключ если есть
        if [ ! -f "$key_path" ]; then
            key_path="$HOME/.ssh/id_ed25519"
        fi
        create_ssh_config
        echo ""
        echo -e "${YELLOW}💡 Для использования без паролей запустите: $0 --with-keys${NC}"
    fi
fi

echo ""
echo -e "${GREEN}🎉 Настройка SSH завершена!${NC}"
echo ""
echo "Полезные команды:"
echo "  ssh database-vm          # Подключение к Database VM"
echo "  ssh frontend-vm          # Подключение к Frontend VM"
echo "  ssh backend-vm           # Подключение к Backend VM"
echo "  ssh parsers-vm           # Подключение к Parsers VM"
echo "  ssh ml-platform-vm       # Подключение к ML Platform VM"
echo ""
echo "  scp file.txt backend-vm:~/  # Копирование файла"
echo "  rsync -avz ./ backend-vm:~/vulnerability_manager/  # Синхронизация директории"

