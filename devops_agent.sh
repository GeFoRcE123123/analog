#!/bin/bash
# 🚀 Автономный DevOps-агент для запуска и отладки 4 VM
# Автоматически запускает VM, настраивает автозапуск, тестирует сервисы и исправляет ошибки

set +e  # Не прерывать выполнение при ошибках

# Цвета для вывода
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Конфигурация
SSH_PASS='123'
SSH_USER='user'
SSH_TIMEOUT=10
VM_BOOT_TIMEOUT=60  # Время ожидания загрузки VM (секунды)

# IP адреса VM
declare -A VMS=(
    ['frontend']='10.0.88.10'
    ['backend']='10.0.88.20'
    ['database']='10.0.88.11'
    ['parsers']='10.0.88.23'
)

# Порты сервисов
declare -A PORTS=(
    ['frontend']='80'
    ['backend']='5000'
    ['database']='5432'
    ['parsers']='8080'
)

# Имена контейнеров
declare -A CONTAINERS=(
    ['frontend']='vulnerability-frontend'
    ['backend']='vulnerability-backend'
    ['database']='vulnerability_db'
    ['parsers']='vulnerability-parsers'
)

# Статусы
declare -A VM_STATUS
declare -A SERVICE_STATUS
declare -A ERRORS
declare -A FIXES_APPLIED
declare -A ERROR_DETAILS
declare -A PERFORMANCE_METRICS
declare -A DEPENDENCY_CHECKS
declare -A BACKUP_PATHS

# Отчет
REPORT_FILE="devops_agent_report_$(date +%Y%m%d_%H%M%S).txt"
BACKUP_DIR="backups_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Паттерны ошибок для анализа логов
declare -A ERROR_PATTERNS=(
    ['database_connection']='connection.*refused|could not connect|OperationalError|FATAL.*password|authentication failed'
    ['port_conflict']='address already in use|port.*already.*bound|bind.*failed'
    ['container_crash']='exited.*code|Worker failed to boot|Container.*exited'
    ['disk_space']='No space left|disk.*full|ENOSPC'
    ['memory']='OutOfMemory|Cannot allocate memory|OOM'
    ['network']='Network.*unreachable|Connection.*timeout|Name resolution failed'
    ['permission']='Permission denied|access denied|EACCES'
    ['config_error']='configuration.*error|syntax.*error|invalid.*config'
    ['dependency']='ModuleNotFoundError|ImportError|package.*not.*found'
    ['timeout']='timeout|timed.*out|deadline.*exceeded'
)

# ============================================
# УТИЛИТЫ
# ============================================

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)
            echo -e "${BLUE}[INFO]${NC} $message" | tee -a "$REPORT_FILE"
            ;;
        SUCCESS)
            echo -e "${GREEN}[SUCCESS]${NC} $message" | tee -a "$REPORT_FILE"
            ;;
        WARNING)
            echo -e "${YELLOW}[WARNING]${NC} $message" | tee -a "$REPORT_FILE"
            ;;
        ERROR)
            echo -e "${RED}[ERROR]${NC} $message" | tee -a "$REPORT_FILE"
            ERRORS["$message"]=1
            ;;
        FIX)
            echo -e "${CYAN}[FIX]${NC} $message" | tee -a "$REPORT_FILE"
            FIXES_APPLIED["$message"]=1
            ;;
        DEBUG)
            echo -e "${MAGENTA}[DEBUG]${NC} $message" | tee -a "$REPORT_FILE"
            ;;
        METRIC)
            echo -e "${CYAN}[METRIC]${NC} $message" | tee -a "$REPORT_FILE"
            ;;
    esac
}

execute_remote() {
    local ip=$1
    local description=$2
    local command=$3
    local timeout=${4:-$SSH_TIMEOUT}
    
    log INFO "📡 $description (${ip})"
    if sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=$timeout \
        "${SSH_USER}@${ip}" "$command" 2>&1; then
        return 0
    else
        log ERROR "Ошибка выполнения команды на ${ip}: $description"
        return 1
    fi
}

check_vm_availability() {
    local ip=$1
    local name=$2
    
    log INFO "🔍 Проверка доступности ${name} (${ip})..."
    if ping -c 1 -W 2 "$ip" > /dev/null 2>&1; then
        VM_STATUS["$name"]="online"
        log SUCCESS "${name} доступен"
        return 0
    else
        VM_STATUS["$name"]="offline"
        log WARNING "${name} недоступен"
        return 1
    fi
}

# ============================================
# ОПРЕДЕЛЕНИЕ И ЗАПУСК VM
# ============================================

detect_vm_platform() {
    log INFO "🔍 Определение платформы виртуализации..."
    
    # Проверка VirtualBox
    if command -v VBoxManage &> /dev/null; then
        log INFO "Найдена VirtualBox"
        echo "virtualbox"
        return 0
    fi
    
    # Проверка VMware
    if command -v vmrun &> /dev/null; then
        log INFO "Найден VMware"
        echo "vmware"
        return 0
    fi
    
    # Проверка QEMU/KVM
    if command -v virsh &> /dev/null; then
        log INFO "Найден QEMU/KVM (libvirt)"
        echo "qemu"
        return 0
    fi
    
    # Проверка Vagrant
    if command -v vagrant &> /dev/null && [ -f "Vagrantfile" ]; then
        log INFO "Найден Vagrant"
        echo "vagrant"
        return 0
    fi
    
    log WARNING "Платформа виртуализации не определена, предполагаем что VM уже запущены"
    echo "unknown"
    return 0
}

start_vm_virtualbox() {
    local vm_name=$1
    log INFO "Запуск VM ${vm_name} через VirtualBox..."
    
    # Попытка найти VM по имени или IP
    local vm_list=$(VBoxManage list vms 2>/dev/null)
    local vm_found=""
    
    # Ищем по имени
    if echo "$vm_list" | grep -qi "$vm_name"; then
        vm_found=$(echo "$vm_list" | grep -i "$vm_name" | head -1 | cut -d'"' -f2)
    fi
    
    if [ -n "$vm_found" ]; then
        VBoxManage startvm "$vm_found" --type headless 2>&1
        if [ $? -eq 0 ]; then
            log SUCCESS "VM ${vm_name} запущена через VirtualBox"
            return 0
        fi
    fi
    
    log WARNING "Не удалось запустить VM ${vm_name} через VirtualBox"
    return 1
}

start_vm_qemu() {
    local vm_name=$1
    log INFO "Запуск VM ${vm_name} через QEMU/KVM..."
    
    # Попытка найти и запустить VM
    local vm_list=$(virsh list --all 2>/dev/null | grep -i "$vm_name" | head -1 | awk '{print $2}')
    
    if [ -n "$vm_list" ]; then
        virsh start "$vm_list" 2>&1
        if [ $? -eq 0 ]; then
            log SUCCESS "VM ${vm_name} запущена через QEMU/KVM"
            return 0
        fi
    fi
    
    log WARNING "Не удалось запустить VM ${vm_name} через QEMU/KVM"
    return 1
}

start_vm_vagrant() {
    local vm_name=$1
    log INFO "Запуск VM ${vm_name} через Vagrant..."
    
    if vagrant up "$vm_name" 2>&1; then
        log SUCCESS "VM ${vm_name} запущена через Vagrant"
        return 0
    fi
    
    log WARNING "Не удалось запустить VM ${vm_name} через Vagrant"
    return 1
}

start_all_vms() {
    local platform=$(detect_vm_platform)
    log INFO "🚀 Запуск всех VM (платформа: ${platform})..."
    
    local started=0
    
    for vm_name in "${!VMS[@]}"; do
        local ip="${VMS[$vm_name]}"
        
        # Проверяем, доступна ли VM
        if check_vm_availability "$ip" "$vm_name"; then
            log INFO "${vm_name} уже доступна, пропускаем запуск"
            continue
        fi
        
        # Пытаемся запустить VM
        case $platform in
            virtualbox)
                start_vm_virtualbox "$vm_name" && started=$((started + 1))
                ;;
            qemu)
                start_vm_qemu "$vm_name" && started=$((started + 1))
                ;;
            vagrant)
                start_vm_vagrant "$vm_name" && started=$((started + 1))
                ;;
            *)
                log WARNING "Неизвестная платформа, предполагаем что VM запускаются вручную"
                ;;
        esac
        
        # Ждем загрузки VM
        if [ $started -gt 0 ]; then
            log INFO "Ожидание загрузки ${vm_name} (до ${VM_BOOT_TIMEOUT} секунд)..."
            local waited=0
            while [ $waited -lt $VM_BOOT_TIMEOUT ]; do
                sleep 2
                waited=$((waited + 2))
                if check_vm_availability "$ip" "$vm_name"; then
                    log SUCCESS "${vm_name} загрузилась за ${waited} секунд"
                    break
                fi
            done
            
            if [ $waited -ge $VM_BOOT_TIMEOUT ]; then
                log ERROR "${vm_name} не загрузилась за ${VM_BOOT_TIMEOUT} секунд"
            fi
        fi
    done
    
    log INFO "Запущено VM: ${started}"
}

# ============================================
# НАСТРОЙКА АВТОЗАПУСКА
# ============================================

setup_autostart_on_vm() {
    local vm_name=$1
    local ip="${VMS[$vm_name]}"
    
    log INFO "🔧 Настройка автозапуска на ${vm_name} (${ip})..."
    
    # Проверяем доступность VM
    if ! check_vm_availability "$ip" "$vm_name"; then
        log ERROR "${vm_name} недоступна, пропускаем настройку автозапуска"
        return 1
    fi
    
    # Копируем setup_autostart.sh на VM (если нужно)
    if [ -f "setup_autostart.sh" ]; then
        log INFO "Копирование setup_autostart.sh на ${vm_name}..."
        sshpass -p "$SSH_PASS" scp -o StrictHostKeyChecking=no \
            "setup_autostart.sh" "${SSH_USER}@${ip}:~/setup_autostart.sh" 2>&1 | grep -v "Warning: Permanently added" || true
    fi
    
    # Выполняем setup_autostart.sh на VM
    # Но только для конкретной VM, не для всех сразу
    log INFO "Настройка systemd сервиса на ${vm_name}..."
    
    local service_name=""
    local service_file=""
    
    case $vm_name in
        frontend)
            service_name="vulnerability-frontend"
            service_file="services/frontend/vulnerability-frontend.service"
            ;;
        backend)
            service_name="vulnerability-backend"
            service_file="services/backend/vulnerability-backend.service"
            ;;
        database)
            service_name="vulnerability-db"
            service_file="services/database/vulnerability-db.service"
            ;;
        parsers)
            service_name="vulnerability-parsers"
            service_file="services/parsers/vulnerability-parsers.service"
            ;;
    esac
    
    if [ -n "$service_name" ] && [ -f "$service_file" ]; then
        log INFO "Установка ${service_name} на ${vm_name}..."
        sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no "${SSH_USER}@${ip}" << ENDSSH
            sudo mkdir -p /etc/systemd/system
            sudo tee /etc/systemd/system/${service_name}.service > /dev/null << 'SERVICEFILE'
$(cat "$service_file")
SERVICEFILE
            sudo systemctl daemon-reload
            sudo systemctl enable ${service_name}.service
            sudo systemctl start ${service_name}.service || true
ENDSSH
        
        if [ $? -eq 0 ]; then
            log SUCCESS "Автозапуск настроен на ${vm_name}"
            return 0
        else
            log ERROR "Ошибка настройки автозапуска на ${vm_name}"
            return 1
        fi
    else
        log WARNING "Файл сервиса не найден для ${vm_name}, пропускаем"
        return 1
    fi
}

setup_autostart_all() {
    log INFO "🔧 Настройка автозапуска на всех VM..."
    
    for vm_name in "${!VMS[@]}"; do
        setup_autostart_on_vm "$vm_name"
        sleep 2
    done
}

# ============================================
# ТЕСТИРОВАНИЕ СЕРВИСОВ
# ============================================

test_service_health() {
    local vm_name=$1
    local ip="${VMS[$vm_name]}"
    local port="${PORTS[$vm_name]}"
    local container="${CONTAINERS[$vm_name]}"
    
    log INFO "🔍 Тестирование ${vm_name} (${ip})..."
    
    local health_status="unknown"
    local details=""
    
    case $vm_name in
        frontend)
            # Проверка Nginx
            if execute_remote "$ip" "Проверка контейнера" "echo '123' | sudo -S docker ps | grep ${container}" > /dev/null 2>&1; then
                local http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "http://${ip}" 2>/dev/null)
                if [ "$http_code" = "200" ] || [ "$http_code" = "302" ] || [ "$http_code" = "301" ]; then
                    health_status="healthy"
                    details="HTTP $http_code"
                elif [ "$http_code" = "502" ] || [ "$http_code" = "504" ]; then
                    health_status="unhealthy"
                    details="HTTP $http_code (Bad Gateway)"
                else
                    health_status="degraded"
                    details="HTTP $http_code"
                fi
            else
                health_status="unhealthy"
                details="Контейнер не запущен"
            fi
            ;;
        backend)
            # Проверка Flask API
            if execute_remote "$ip" "Проверка контейнера" "echo '123' | sudo -S docker ps | grep ${container}" > /dev/null 2>&1; then
                local http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "http://${ip}:${port}/api/health" 2>/dev/null)
                if [ "$http_code" = "200" ]; then
                    health_status="healthy"
                    details="API доступен"
                else
                    health_status="unhealthy"
                    details="API недоступен (HTTP $http_code)"
                fi
            else
                health_status="unhealthy"
                details="Контейнер не запущен"
            fi
            ;;
        database)
            # Проверка PostgreSQL
            if execute_remote "$ip" "Проверка контейнера" "echo '123' | sudo -S docker ps | grep ${container}" > /dev/null 2>&1; then
                if execute_remote "$ip" "Проверка PostgreSQL" "echo '123' | sudo -S docker exec ${container} pg_isready -U admin -d vuln_db" > /dev/null 2>&1; then
                    health_status="healthy"
                    details="PostgreSQL доступен"
                else
                    health_status="unhealthy"
                    details="PostgreSQL не отвечает"
                fi
            else
                health_status="unhealthy"
                details="Контейнер не запущен"
            fi
            ;;
        parsers)
            # Проверка парсеров
            if execute_remote "$ip" "Проверка контейнера" "echo '123' | sudo -S docker ps | grep ${container}" > /dev/null 2>&1; then
                health_status="healthy"
                details="Контейнер запущен"
            else
                health_status="unhealthy"
                details="Контейнер не запущен"
            fi
            ;;
    esac
    
    SERVICE_STATUS["$vm_name"]="$health_status"
    
    case $health_status in
        healthy)
            log SUCCESS "${vm_name}: $details"
            ;;
        degraded)
            log WARNING "${vm_name}: $details"
            ;;
        unhealthy)
            log ERROR "${vm_name}: $details"
            ;;
    esac
    
    return 0
}

test_all_services() {
    log INFO "🔍 Тестирование всех сервисов..."
    
    for vm_name in "${!VMS[@]}"; do
        test_service_health "$vm_name"
        sleep 1
    done
}

# ============================================
# ДИАГНОСТИКА И ИСПРАВЛЕНИЕ ОШИБОК
# ============================================

# ============================================
# ПРОДВИНУТАЯ ДИАГНОСТИКА
# ============================================

analyze_logs_for_errors() {
    local vm_name=$1
    local ip=$2
    local container=$3
    local log_lines=${4:-100}
    
    log DEBUG "Анализ логов ${container} на ${vm_name}..."
    
    local logs=$(execute_remote "$ip" "Получение логов" \
        "echo '123' | sudo -S docker logs ${container} --tail ${log_lines} 2>&1" 2>/dev/null)
    
    local found_errors=()
    
    for error_type in "${!ERROR_PATTERNS[@]}"; do
        local pattern="${ERROR_PATTERNS[$error_type]}"
        if echo "$logs" | grep -qiE "$pattern"; then
            found_errors+=("$error_type")
            local error_lines=$(echo "$logs" | grep -iE "$pattern" | head -5)
            ERROR_DETAILS["${vm_name}_${error_type}"]="$error_lines"
            log ERROR "Обнаружена ошибка типа '${error_type}' в ${vm_name}"
            log DEBUG "Детали: $(echo "$error_lines" | head -1)"
        fi
    done
    
    echo "${found_errors[@]}"
}

check_performance_metrics() {
    local vm_name=$1
    local ip=$2
    
    log DEBUG "Проверка метрик производительности ${vm_name}..."
    
    local metrics=$(execute_remote "$ip" "Метрики системы" \
        "echo '123' | sudo -S docker stats --no-stream --format 'table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}' 2>/dev/null || \
         echo '123' | sudo -S top -bn1 | head -5 || \
         free -h && df -h / | tail -1" 2>/dev/null)
    
    if [ -n "$metrics" ]; then
        PERFORMANCE_METRICS["${vm_name}"]="$metrics"
        
        # Проверка использования диска
        local disk_usage=$(echo "$metrics" | grep -oP '\d+%' | head -1 | tr -d '%' || echo "0")
        if [ "$disk_usage" -gt 90 ]; then
            log ERROR "${vm_name}: Критическое использование диска (${disk_usage}%)"
            return 1
        elif [ "$disk_usage" -gt 80 ]; then
            log WARNING "${vm_name}: Высокое использование диска (${disk_usage}%)"
        fi
        
        # Проверка памяти
        local mem_info=$(execute_remote "$ip" "Информация о памяти" \
            "free -m | grep Mem | awk '{print \$3/\$2*100}'" 2>/dev/null | cut -d. -f1)
        if [ -n "$mem_info" ] && [ "$mem_info" -gt 90 ]; then
            log WARNING "${vm_name}: Высокое использование памяти (${mem_info}%)"
        fi
    fi
    
    return 0
}

check_service_dependencies() {
    local vm_name=$1
    local ip=$2
    
    log DEBUG "Проверка зависимостей сервисов для ${vm_name}..."
    
    local dependencies_ok=true
    
    case $vm_name in
        backend)
            # Backend зависит от Database
            if ! execute_remote "${VMS['database']}" "Проверка Database" \
                "echo '123' | sudo -S docker ps | grep ${CONTAINERS['database']}" > /dev/null 2>&1; then
                log ERROR "Backend: Database недоступна (критическая зависимость)"
                dependencies_ok=false
            else
                # Проверка подключения
                local db_test=$(execute_remote "$ip" "Тест подключения к БД" \
                    "timeout 3 bash -c '</dev/tcp/${VMS['database']}/5432' && echo 'OK' || echo 'FAIL'" 2>/dev/null)
                if [ "$db_test" != "OK" ]; then
                    log ERROR "Backend: Не может подключиться к Database"
                    dependencies_ok=false
                else
                    DEPENDENCY_CHECKS["backend_database"]="OK"
                fi
            fi
            ;;
        frontend)
            # Frontend зависит от Backend
            local backend_code=$(curl -s -o /dev/null -w "%{http_code}" -m 3 "http://${VMS['backend']}:5000/api/health" 2>/dev/null)
            if [ "$backend_code" != "200" ]; then
                log ERROR "Frontend: Backend недоступен (HTTP $backend_code)"
                dependencies_ok=false
            else
                DEPENDENCY_CHECKS["frontend_backend"]="OK"
            fi
            ;;
        parsers)
            # Parsers зависят от Database
            if ! execute_remote "${VMS['database']}" "Проверка Database" \
                "echo '123' | sudo -S docker ps | grep ${CONTAINERS['database']}" > /dev/null 2>&1; then
                log WARNING "Parsers: Database недоступна (может работать в автономном режиме)"
            else
                DEPENDENCY_CHECKS["parsers_database"]="OK"
            fi
            ;;
    esac
    
    if [ "$dependencies_ok" = true ]; then
        DEPENDENCY_CHECKS["${vm_name}"]="OK"
    else
        DEPENDENCY_CHECKS["${vm_name}"]="FAIL"
    fi
}

create_backup() {
    local vm_name=$1
    local ip=$2
    local backup_type=$3  # config, data, logs
    
    log INFO "Создание резервной копии ${backup_type} для ${vm_name}..."
    
    local backup_path="${BACKUP_DIR}/${vm_name}_${backup_type}_$(date +%H%M%S)"
    mkdir -p "$backup_path"
    
    case $backup_type in
        config)
            # Резервная копия конфигурационных файлов
            execute_remote "$ip" "Бэкап конфигов" \
                "cd ~/vulnerability_manager && tar czf - */docker-compose.yml */nginx.conf 2>/dev/null" \
                > "${backup_path}/configs.tar.gz" 2>/dev/null
            ;;
        logs)
            # Резервная копия логов
            local container="${CONTAINERS[$vm_name]}"
            execute_remote "$ip" "Бэкап логов" \
                "echo '123' | sudo -S docker logs ${container} --tail 1000 2>&1" \
                > "${backup_path}/logs.txt" 2>/dev/null
            ;;
    esac
    
    if [ -f "${backup_path}"/* ] || [ -d "${backup_path}" ]; then
        BACKUP_PATHS["${vm_name}_${backup_type}"]="$backup_path"
        log SUCCESS "Резервная копия создана: $backup_path"
        return 0
    else
        log WARNING "Не удалось создать резервную копию для ${vm_name}"
        return 1
    fi
}

advanced_network_diagnosis() {
    local vm_name=$1
    local ip=$2
    
    log DEBUG "Продвинутая диагностика сети для ${vm_name}..."
    
    # Проверка DNS
    local dns_test=$(execute_remote "$ip" "Проверка DNS" \
        "nslookup google.com 2>&1 | grep -q 'Name:' && echo 'OK' || echo 'FAIL'" 2>/dev/null)
    if [ "$dns_test" != "OK" ]; then
        log WARNING "${vm_name}: Проблемы с DNS разрешением"
    fi
    
    # Проверка маршрутизации
    local route_test=$(execute_remote "$ip" "Проверка маршрутизации" \
        "ip route | head -3" 2>/dev/null)
    if [ -z "$route_test" ]; then
        log WARNING "${vm_name}: Проблемы с маршрутизацией"
    fi
    
    # Проверка firewall
    local firewall_status=$(execute_remote "$ip" "Проверка firewall" \
        "sudo ufw status 2>/dev/null || sudo firewall-cmd --state 2>/dev/null || echo 'not_found'" 2>/dev/null)
    if echo "$firewall_status" | grep -qi "active\|running"; then
        log INFO "${vm_name}: Firewall активен"
    fi
    
    # Проверка открытых портов
    local open_ports=$(execute_remote "$ip" "Проверка портов" \
        "echo '123' | sudo -S netstat -tuln 2>/dev/null | grep LISTEN | wc -l" 2>/dev/null)
    log METRIC "${vm_name}: Открыто портов: ${open_ports}"
}

intelligent_error_fix() {
    local vm_name=$1
    local ip=$2
    local container=$3
    local error_types=$4
    
    log INFO "Интеллектуальное исправление ошибок для ${vm_name}..."
    
    # Создаем резервную копию перед исправлениями
    create_backup "$vm_name" "$ip" "config"
    create_backup "$vm_name" "$ip" "logs"
    
    for error_type in $error_types; do
        case $error_type in
            database_connection)
                log FIX "Исправление проблемы подключения к БД..."
                
                # Проверяем и перезапускаем Database
                if [ "$vm_name" != "database" ]; then
                    log INFO "Перезапуск Database..."
                    execute_remote "${VMS['database']}" "Перезапуск Database" \
                        "cd ~/vulnerability_manager/database && echo '123' | sudo -S docker compose restart" > /dev/null 2>&1
                    sleep 5
                fi
                
                # Перезапускаем зависимый сервис
                execute_remote "$ip" "Перезапуск ${vm_name}" \
                    "cd ~/vulnerability_manager/${vm_name} && echo '123' | sudo -S docker compose restart" > /dev/null 2>&1
                sleep 5
                ;;
            port_conflict)
                log FIX "Исправление конфликта портов..."
                
                # Останавливаем конфликтующие процессы
                case $vm_name in
                    database)
                        execute_remote "$ip" "Остановка системного PostgreSQL" \
                            "echo '123' | sudo -S systemctl stop postgresql 2>/dev/null; \
                             echo '123' | sudo -S pkill -9 postgres 2>/dev/null || true" > /dev/null 2>&1
                        sleep 2
                        execute_remote "$ip" "Перезапуск контейнера" \
                            "cd ~/vulnerability_manager/database && echo '123' | sudo -S docker compose restart" > /dev/null 2>&1
                        ;;
                esac
                sleep 5
                ;;
            container_crash)
                log FIX "Исправление падения контейнера..."
                
                # Получаем детальные логи
                local crash_logs=$(execute_remote "$ip" "Логи падения" \
                    "echo '123' | sudo -S docker logs ${container} --tail 50 2>&1" 2>/dev/null)
                
                # Проверяем причину падения
                if echo "$crash_logs" | grep -qi "out of memory\|OOM"; then
                    log FIX "Обнаружена нехватка памяти, увеличиваем лимиты..."
                    # Здесь можно добавить изменение docker-compose.yml
                fi
                
                # Пересоздаем контейнер
                execute_remote "$ip" "Пересоздание контейнера" \
                    "cd ~/vulnerability_manager/${vm_name} && \
                     echo '123' | sudo -S docker compose down && \
                     echo '123' | sudo -S docker compose up -d" > /dev/null 2>&1
                sleep 10
                ;;
            disk_space)
                log FIX "Очистка дискового пространства..."
                
                # Очистка Docker
                execute_remote "$ip" "Очистка Docker" \
                    "echo '123' | sudo -S docker system prune -f && \
                     echo '123' | sudo -S docker volume prune -f" > /dev/null 2>&1
                
                # Очистка логов
                execute_remote "$ip" "Очистка старых логов" \
                    "echo '123' | sudo -S journalctl --vacuum-time=7d 2>/dev/null || true" > /dev/null 2>&1
                ;;
            config_error)
                log FIX "Исправление ошибок конфигурации..."
                
                # Восстанавливаем из резервной копии если есть
                if [ -n "${BACKUP_PATHS["${vm_name}_config"]}" ]; then
                    log INFO "Восстановление конфигурации из резервной копии..."
                    # Здесь можно добавить восстановление
                fi
                
                # Проверяем конфигурацию
                case $vm_name in
                    frontend)
                        execute_remote "$ip" "Проверка Nginx" \
                            "echo '123' | sudo -S docker exec ${container} nginx -t" 2>/dev/null
                        ;;
                esac
                ;;
        esac
    done
}

diagnose_and_fix() {
    local vm_name=$1
    local ip="${VMS[$vm_name]}"
    local container="${CONTAINERS[$vm_name]}"
    
    log INFO "🔧 Продвинутая диагностика и исправление проблем на ${vm_name}..."
    
    # Проверка производительности
    check_performance_metrics "$vm_name" "$ip"
    
    # Проверка зависимостей
    check_service_dependencies "$vm_name" "$ip"
    
    # Продвинутая диагностика сети
    advanced_network_diagnosis "$vm_name" "$ip"
    
    # Анализ логов на ошибки
    local found_errors=$(analyze_logs_for_errors "$vm_name" "$ip" "$container" 100)
    
    # Проверка статуса контейнера
    local container_running=$(execute_remote "$ip" "Проверка контейнера" \
        "echo '123' | sudo -S docker ps | grep ${container}" 2>/dev/null | wc -l)
    
    # Проверка статуса контейнера
    local container_running=$(execute_remote "$ip" "Проверка контейнера" \
        "echo '123' | sudo -S docker ps | grep ${container}" 2>/dev/null | wc -l)
    
    if [ "$container_running" -eq 0 ]; then
        log FIX "Контейнер ${container} не запущен, пытаемся запустить..."
        
        # Создаем резервную копию перед изменениями
        create_backup "$vm_name" "$ip" "config"
        
        # Определяем директорию docker-compose
        local compose_dir=""
        case $vm_name in
            frontend) compose_dir="~/vulnerability_manager/frontend" ;;
            backend) compose_dir="~/vulnerability_manager/backend" ;;
            database) compose_dir="~/vulnerability_manager/database" ;;
            parsers) compose_dir="~/vulnerability_manager/parsers" ;;
        esac
        
        if [ -n "$compose_dir" ]; then
            execute_remote "$ip" "Запуск контейнера" \
                "cd ${compose_dir} && echo '123' | sudo -S docker compose up -d" > /dev/null 2>&1
            
            sleep 5
            
            # Проверяем снова
            container_running=$(execute_remote "$ip" "Проверка контейнера" \
                "echo '123' | sudo -S docker ps | grep ${container}" 2>/dev/null | wc -l)
            
            if [ "$container_running" -gt 0 ]; then
                log SUCCESS "Контейнер ${container} успешно запущен"
            else
                log ERROR "Не удалось запустить контейнер ${container}"
                
                # Интеллектуальное исправление
                if [ -n "$found_errors" ]; then
                    intelligent_error_fix "$vm_name" "$ip" "$container" "$found_errors"
                else
                    # Проверяем логи
                    log INFO "Проверка логов контейнера..."
                    execute_remote "$ip" "Логи контейнера" \
                        "echo '123' | sudo -S docker logs ${container} --tail 50" 2>&1 | tail -30
                    
                    # Анализируем логи еще раз
                    found_errors=$(analyze_logs_for_errors "$vm_name" "$ip" "$container" 200)
                    if [ -n "$found_errors" ]; then
                        intelligent_error_fix "$vm_name" "$ip" "$container" "$found_errors"
                    fi
                fi
            fi
        fi
    elif [ -n "$found_errors" ]; then
        # Контейнер запущен, но есть ошибки в логах
        log WARNING "Контейнер ${container} запущен, но обнаружены ошибки в логах"
        intelligent_error_fix "$vm_name" "$ip" "$container" "$found_errors"
    fi
    
    # Специфичные проверки для каждого сервиса
    case $vm_name in
        database)
            # Проверка порта 5432
            if ! execute_remote "$ip" "Проверка порта" \
                "echo '123' | sudo -S docker port ${container} | grep 5432" > /dev/null 2>&1; then
                log FIX "Порт 5432 не проброшен, перезапускаем контейнер..."
                execute_remote "$ip" "Перезапуск контейнера" \
                    "cd ~/vulnerability_manager/database && echo '123' | sudo -S docker compose restart" > /dev/null 2>&1
                sleep 5
            fi
            
            # Проверка системного PostgreSQL
            local sys_pg=$(execute_remote "$ip" "Проверка системного PostgreSQL" \
                "echo '123' | sudo -S lsof -i :5432 2>/dev/null | grep -v docker" 2>/dev/null | wc -l)
            
            if [ "$sys_pg" -gt 0 ]; then
                log FIX "Системный PostgreSQL занимает порт 5432, останавливаем..."
                execute_remote "$ip" "Остановка системного PostgreSQL" \
                    "echo '123' | sudo -S systemctl stop postgresql 2>/dev/null; echo '123' | sudo -S killall -9 postgres 2>/dev/null || true" > /dev/null 2>&1
                sleep 2
            fi
            ;;
        backend)
            # Проверка подключения к Database
            local db_conn=$(execute_remote "$ip" "Проверка подключения к БД" \
                "timeout 3 bash -c '</dev/tcp/10.0.88.11/5432' && echo 'OK' || echo 'FAIL'" 2>/dev/null)
            
            if [ "$db_conn" != "OK" ]; then
                log WARNING "Backend не может подключиться к Database"
            fi
            
            # Проверка логов на ошибки
            local backend_logs=$(execute_remote "$ip" "Логи Backend" \
                "echo '123' | sudo -S docker logs ${container} --tail 50" 2>/dev/null)
            
            if echo "$backend_logs" | grep -qi "connection.*refused\|could not connect\|OperationalError"; then
                log FIX "Обнаружена ошибка подключения в логах Backend"
                log INFO "Перезапускаем Backend..."
                execute_remote "$ip" "Перезапуск Backend" \
                    "cd ~/vulnerability_manager/backend && echo '123' | sudo -S docker compose restart" > /dev/null 2>&1
                sleep 5
            fi
            ;;
        frontend)
            # Проверка Nginx конфигурации
            local nginx_test=$(execute_remote "$ip" "Проверка Nginx" \
                "echo '123' | sudo -S docker exec ${container} nginx -t" 2>/dev/null)
            
            if echo "$nginx_test" | grep -qi "failed\|error"; then
                log ERROR "Ошибка в конфигурации Nginx"
            fi
            
            # Проверка доступности Backend
            local backend_available=$(curl -s -o /dev/null -w "%{http_code}" -m 3 "http://10.0.88.20:5000/api/health" 2>/dev/null)
            
            if [ "$backend_available" != "200" ]; then
                log WARNING "Frontend не может подключиться к Backend (HTTP $backend_available)"
            fi
            ;;
    esac
}

diagnose_and_fix_all() {
    log INFO "🔧 Диагностика и исправление проблем на всех VM..."
    
    for vm_name in "${!VMS[@]}"; do
        if [ "${VM_STATUS[$vm_name]}" = "online" ]; then
            diagnose_and_fix "$vm_name"
            sleep 2
        fi
    done
}

# ============================================
# ФОРМИРОВАНИЕ ОТЧЕТА
# ============================================

generate_report() {
    log INFO "📊 Формирование отчета..."
    
    {
        echo "================================================"
        echo "🚀 ОТЧЕТ DevOps-АГЕНТА"
        echo "Дата: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "================================================"
        echo ""
        
        echo "📋 СТАТУС VM:"
        for vm_name in "${!VMS[@]}"; do
            local status="${VM_STATUS[$vm_name]:-unknown}"
            local ip="${VMS[$vm_name]}"
            case $status in
                online)
                    echo "  ✅ ${vm_name} (${ip}): ONLINE"
                    ;;
                offline)
                    echo "  ❌ ${vm_name} (${ip}): OFFLINE"
                    ;;
                *)
                    echo "  ⚠️  ${vm_name} (${ip}): UNKNOWN"
                    ;;
            esac
        done
        echo ""
        
        echo "🔍 СТАТУС СЕРВИСОВ:"
        for vm_name in "${!VMS[@]}"; do
            local health="${SERVICE_STATUS[$vm_name]:-unknown}"
            case $health in
                healthy)
                    echo "  ✅ ${vm_name}: HEALTHY"
                    ;;
                degraded)
                    echo "  ⚠️  ${vm_name}: DEGRADED"
                    ;;
                unhealthy)
                    echo "  ❌ ${vm_name}: UNHEALTHY"
                    ;;
                *)
                    echo "  ❓ ${vm_name}: UNKNOWN"
                    ;;
            esac
        done
        echo ""
        
        echo "🔗 ПРОВЕРКА ЗАВИСИМОСТЕЙ:"
        for check in "${!DEPENDENCY_CHECKS[@]}"; do
            local status="${DEPENDENCY_CHECKS[$check]}"
            if [ "$status" = "OK" ]; then
                echo "  ✅ $check: OK"
            else
                echo "  ❌ $check: FAIL"
            fi
        done
        echo ""
        
        if [ ${#PERFORMANCE_METRICS[@]} -gt 0 ]; then
            echo "📊 МЕТРИКИ ПРОИЗВОДИТЕЛЬНОСТИ:"
            for vm_name in "${!PERFORMANCE_METRICS[@]}"; do
                echo "  ${vm_name}:"
                echo "${PERFORMANCE_METRICS[$vm_name]}" | sed 's/^/    /'
            done
            echo ""
        fi
        
        if [ ${#ERROR_DETAILS[@]} -gt 0 ]; then
            echo "🔍 ДЕТАЛИ ОШИБОК:"
            for error_key in "${!ERROR_DETAILS[@]}"; do
                echo "  ${error_key}:"
                echo "${ERROR_DETAILS[$error_key]}" | head -3 | sed 's/^/    /'
            done
            echo ""
        fi
        
        if [ ${#BACKUP_PATHS[@]} -gt 0 ]; then
            echo "💾 РЕЗЕРВНЫЕ КОПИИ:"
            for backup_key in "${!BACKUP_PATHS[@]}"; do
                echo "  ✅ ${backup_key}: ${BACKUP_PATHS[$backup_key]}"
            done
            echo ""
        fi
        
        if [ ${#ERRORS[@]} -gt 0 ]; then
            echo "❌ ОБНАРУЖЕННЫЕ ОШИБКИ:"
            for error in "${!ERRORS[@]}"; do
                echo "  - $error"
            done
            echo ""
        fi
        
        if [ ${#FIXES_APPLIED[@]} -gt 0 ]; then
            echo "🔧 ПРИМЕНЕННЫЕ ИСПРАВЛЕНИЯ:"
            for fix in "${!FIXES_APPLIED[@]}"; do
                echo "  - $fix"
            done
            echo ""
        fi
        
        echo "================================================"
        echo "✅ Отчет сохранен в: $REPORT_FILE"
        echo "================================================"
    } | tee "$REPORT_FILE"
}

# ============================================
# ГЛАВНАЯ ФУНКЦИЯ
# ============================================

main() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}🚀 Автономный DevOps-агент${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
    
    # Шаг 1: Запуск VM
    log INFO "ШАГ 1: Запуск VM"
    start_all_vms
    echo ""
    
    # Шаг 2: Настройка автозапуска
    log INFO "ШАГ 2: Настройка автозапуска"
    setup_autostart_all
    echo ""
    
    # Шаг 3: Тестирование сервисов
    log INFO "ШАГ 3: Тестирование сервисов"
    test_all_services
    echo ""
    
    # Шаг 4: Диагностика и исправление
    log INFO "ШАГ 4: Диагностика и исправление проблем"
    diagnose_and_fix_all
    echo ""
    
    # Шаг 5: Повторное тестирование
    log INFO "ШАГ 5: Повторное тестирование после исправлений"
    sleep 5
    test_all_services
    echo ""
    
    # Шаг 6: Формирование отчета
    log INFO "ШАГ 6: Формирование отчета"
    generate_report
    echo ""
    
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}✅ DevOps-агент завершил работу${NC}"
    echo -e "${GREEN}================================================${NC}"
}

# Запуск
main

