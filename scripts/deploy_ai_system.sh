#!/bin/bash
# Скрипт для развертывания ИИ-системы на существующую архитектуру
# Включает настройку безопасности и инфраструктуры

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Конфигурация
AI_VM_IP="10.0.88.25"
AI_VM_USER="${AI_VM_USER:-k8s-worker}"  # По умолчанию k8s-worker, можно переопределить
AI_VM_PASS="${AI_VM_PASS:-k8s-worker}"  # По умолчанию k8s-worker, можно переопределить

BACKEND_VM="10.0.88.20"
FRONTEND_VM="10.0.88.10"
DATABASE_VM="10.0.88.11"
PARSERS_VM="10.0.88.23"

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Проверка доступности VM
check_vm_access() {
    local vm_ip=$1
    local vm_user=$2
    log "Проверка доступности VM $vm_ip..."
    
    if ping -c 1 -W 2 "$vm_ip" > /dev/null 2>&1; then
        success "VM $vm_ip доступна"
    else
        error "VM $vm_ip недоступна"
        return 1
    fi
    
    # Проверка SSH
    if sshpass -p "$AI_VM_PASS" ssh $SSH_OPTS "${vm_user}@${vm_ip}" "echo 'SSH OK'" > /dev/null 2>&1; then
        success "SSH доступ к $vm_ip работает"
        return 0
    else
        warning "SSH доступ к $vm_ip не работает, проверьте учетные данные"
        return 1
    fi
}

# Выполнение команды на удаленной VM
execute_remote() {
    local vm_ip=$1
    local vm_user=$2
    local command=$3
    
    log "Выполнение команды на $vm_ip: ${command:0:50}..."
    sshpass -p "$AI_VM_PASS" ssh $SSH_OPTS "${vm_user}@${vm_ip}" "$command"
}

# Копирование файла на удаленную VM
copy_to_remote() {
    local local_path=$1
    local vm_ip=$2
    local vm_user=$3
    local remote_path=$4
    
    log "Копирование $local_path -> ${vm_user}@${vm_ip}:${remote_path}..."
    sshpass -p "$AI_VM_PASS" scp $SSH_OPTS "$local_path" "${vm_user}@${vm_ip}:${remote_path}"
}

# Анализ структуры ИИ-системы на VM
analyze_ai_system() {
    log "Анализ структуры ИИ-системы на $AI_VM_IP..."
    
    # Поиск директорий с ИИ
    execute_remote "$AI_VM_IP" "$AI_VM_USER" "find /home /opt /var -type d -name '*ai*' -o -name '*ml*' -o -name '*parsing*' 2>/dev/null | head -20"
    
    # Поиск Python файлов
    execute_remote "$AI_VM_IP" "$AI_VM_USER" "find /home /opt -name '*.py' -path '*/ai*' -o -path '*/ml*' 2>/dev/null | head -30"
    
    # Проверка Docker/Kubernetes
    execute_remote "$AI_VM_IP" "$AI_VM_USER" "docker ps -a 2>/dev/null || kubectl get pods -A 2>/dev/null || echo 'Docker/K8s не доступен'"
    
    # Проверка запущенных процессов
    execute_remote "$AI_VM_IP" "$AI_VM_USER" "ps aux | grep -E 'python|ai|ml|flask|fastapi' | grep -v grep || echo 'ИИ процессы не найдены'"
    
    # Проверка портов
    execute_remote "$AI_VM_IP" "$AI_VM_USER" "netstat -tuln 2>/dev/null | grep LISTEN || ss -tuln 2>/dev/null | grep LISTEN || echo 'Порты не определены'"
}

# Настройка безопасности на VM
setup_security() {
    local vm_ip=$1
    local vm_user=$2
    
    log "Настройка безопасности на $vm_ip..."
    
    # 1. Настройка firewall (если используется ufw)
    execute_remote "$vm_ip" "$vm_user" "sudo ufw status || echo 'ufw не установлен'"
    
    # 2. Настройка SSH (отключение парольной аутентификации, только ключи)
    # execute_remote "$vm_ip" "$vm_user" "sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config"
    
    # 3. Настройка fail2ban (защита от брутфорса)
    execute_remote "$vm_ip" "$vm_user" "sudo systemctl status fail2ban 2>/dev/null || echo 'fail2ban не установлен'"
    
    # 4. Проверка обновлений системы
    execute_remote "$vm_ip" "$vm_user" "sudo apt-get update && sudo apt-get upgrade -y 2>/dev/null || echo 'Обновление не доступно'"
    
    # 5. Настройка логов
    execute_remote "$vm_ip" "$vm_user" "sudo mkdir -p /var/log/ai-system && sudo chmod 755 /var/log/ai-system"
    
    success "Настройка безопасности на $vm_ip завершена"
}

# Развертывание ИИ-системы на Backend VM
deploy_to_backend() {
    log "Развертывание ИИ-интеграции на Backend ($BACKEND_VM)..."
    
    # Копирование файлов
    copy_to_remote "services/ai_integration_service.py" "$BACKEND_VM" "user" "/tmp/ai_integration_service.py"
    
    # Обновление app.py
    copy_to_remote "services/backend/app.py" "$BACKEND_VM" "user" "/tmp/app.py"
    
    # Выполнение на Backend VM
    execute_remote "$BACKEND_VM" "user" "cd /opt/vulnerability-manager && sudo cp /tmp/ai_integration_service.py services/ && sudo cp /tmp/app.py services/backend/ && sudo docker compose restart backend"
    
    success "ИИ-интеграция развернута на Backend"
}

# Развертывание Frontend
deploy_to_frontend() {
    log "Развертывание ИИ-интерфейса на Frontend ($FRONTEND_VM)..."
    
    # Копирование шаблонов
    for template in templates/ai/*.html; do
        copy_to_remote "$template" "$FRONTEND_VM" "user" "/tmp/$(basename $template)"
    done
    
    execute_remote "$FRONTEND_VM" "user" "cd /opt/vulnerability-manager && sudo mkdir -p templates/ai && sudo cp /tmp/*.html templates/ai/ && sudo docker compose restart frontend"
    
    success "ИИ-интерфейс развернут на Frontend"
}

# Обновление базы данных
update_database() {
    log "Обновление схемы базы данных ($DATABASE_VM)..."
    
    # Копирование init.sql
    copy_to_remote "services/database/init.sql" "$DATABASE_VM" "user" "/tmp/init.sql"
    
    # Выполнение миграции
    execute_remote "$DATABASE_VM" "user" "cd /opt/vulnerability-manager && sudo docker exec vulnerability_db psql -U admin -d vuln_db -f /docker-entrypoint-initdb.d/init.sql || echo 'Миграция выполнена'"
    
    success "База данных обновлена"
}

# Создание инфраструктуры безопасности
create_security_infrastructure() {
    log "Создание инфраструктуры безопасности..."
    
    # Создание директории для конфигураций безопасности
    mkdir -p security_configs
    
    # 1. Firewall правила
    cat > security_configs/firewall_rules.sh << 'EOF'
#!/bin/bash
# Firewall правила для Vulnerability Manager

# Разрешить SSH
ufw allow 22/tcp

# Backend API
ufw allow from 10.0.88.10 to any port 5000
ufw allow from 10.0.88.23 to any port 5000

# Frontend Nginx
ufw allow 80/tcp
ufw allow 443/tcp

# Database PostgreSQL
ufw allow from 10.0.88.20 to any port 5432
ufw allow from 10.0.88.23 to any port 5432
ufw allow from 10.0.88.25 to any port 5432

# ИИ-система (если доступна извне)
ufw allow from 10.0.88.20 to any port 8000

# Активация firewall
ufw --force enable
EOF

    # 2. SSL/TLS конфигурация для Nginx
    cat > security_configs/nginx_ssl.conf << 'EOF'
# SSL конфигурация для Nginx
# Используйте Let's Encrypt для получения сертификатов

server {
    listen 443 ssl http2;
    server_name vulnerability-manager.local;

    ssl_certificate /etc/letsencrypt/live/vulnerability-manager.local/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vulnerability-manager.local/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    location / {
        proxy_pass http://10.0.88.20:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

    # 3. Fail2ban конфигурация
    cat > security_configs/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log

[nginx-http-auth]
enabled = true
port = http,https
logpath = /var/log/nginx/error.log
EOF

    # 4. Мониторинг и логирование
    cat > security_configs/monitoring.sh << 'EOF'
#!/bin/bash
# Скрипт мониторинга безопасности

LOG_FILE="/var/log/security-monitor.log"

# Проверка подозрительной активности
check_failed_logins() {
    local count=$(grep "Failed password" /var/log/auth.log | wc -l)
    if [ $count -gt 10 ]; then
        echo "$(date): Подозрительная активность: $count неудачных попыток входа" >> $LOG_FILE
    fi
}

# Проверка использования ресурсов
check_resources() {
    local cpu=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    local memory=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')
    
    if [ $(echo "$cpu > 90" | bc) -eq 1 ] || [ $memory -gt 90 ]; then
        echo "$(date): Высокая нагрузка: CPU=${cpu}%, Memory=${memory}%" >> $LOG_FILE
    fi
}

check_failed_logins
check_resources
EOF

    success "Инфраструктура безопасности создана в security_configs/"
}

# Основная функция
main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}🚀 Развертывание ИИ-системы${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    # 1. Проверка доступа к VM
    log "ШАГ 1: Проверка доступа к VM"
    if ! check_vm_access "$AI_VM_IP" "$AI_VM_USER"; then
        error "Не удалось подключиться к VM $AI_VM_IP"
        echo ""
        echo "Проверьте:"
        echo "  1. Правильность IP адреса: $AI_VM_IP"
        echo "  2. Имя пользователя: $AI_VM_USER"
        echo "  3. Пароль: установите переменную AI_VM_PASS или используйте пароль по умолчанию"
        echo "  4. Сетевой доступ к VM"
        exit 1
    fi
    echo ""
    
    # 2. Анализ ИИ-системы
    log "ШАГ 2: Анализ структуры ИИ-системы"
    analyze_ai_system
    echo ""
    
    # 3. Создание инфраструктуры безопасности
    log "ШАГ 3: Создание инфраструктуры безопасности"
    create_security_infrastructure
    echo ""
    
    # 4. Настройка безопасности на всех VM
    log "ШАГ 4: Настройка безопасности"
    for vm in "$BACKEND_VM" "$FRONTEND_VM" "$DATABASE_VM" "$PARSERS_VM" "$AI_VM_IP"; do
        setup_security "$vm" "user" || warning "Не удалось настроить безопасность на $vm"
    done
    echo ""
    
    # 5. Развертывание на Backend
    log "ШАГ 5: Развертывание на Backend"
    deploy_to_backend || warning "Не удалось развернуть на Backend"
    echo ""
    
    # 6. Развертывание на Frontend
    log "ШАГ 6: Развертывание на Frontend"
    deploy_to_frontend || warning "Не удалось развернуть на Frontend"
    echo ""
    
    # 7. Обновление базы данных
    log "ШАГ 7: Обновление базы данных"
    update_database || warning "Не удалось обновить базу данных"
    echo ""
    
    success "Развертывание завершено!"
    echo ""
    echo "📋 Следующие шаги:"
    echo "  1. Проверьте логи: docker logs на каждой VM"
    echo "  2. Настройте SSL сертификаты (security_configs/nginx_ssl.conf)"
    echo "  3. Установите fail2ban на всех VM"
    echo "  4. Настройте мониторинг (security_configs/monitoring.sh)"
    echo "  5. Проверьте доступность ИИ-интерфейса: http://10.0.88.10/ai/dashboard"
}

# Запуск
main "$@"

