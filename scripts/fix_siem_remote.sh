#!/bin/bash
# Скрипт для удаленного исправления SIEM VM
# Использование: ./fix_siem_remote.sh [user@10.0.88.41]

VM="${1:-user@10.0.88.41}"

echo "🔧 Удаленное исправление SIEM VM: $VM"
echo "=============================================="
echo ""

# Копируем скрипт на VM
echo "📤 Копирование скрипта на VM..."
cat > /tmp/fix_siem_local.sh << 'FIXSCRIPT'
#!/bin/bash
set -e

echo "🔧 Исправление SIEM VM..."

# Отключение файрвола
echo "1. Отключение файрвола..."
sudo ufw --force disable 2>/dev/null || true
sudo ufw --force reset 2>/dev/null || true

# Очистка iptables
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

# Запуск SSH
echo "3. Проверка SSH..."
sudo systemctl start ssh 2>/dev/null || true
sudo systemctl enable ssh 2>/dev/null || true

# Запуск Docker
echo "4. Проверка Docker..."
sudo systemctl start docker 2>/dev/null || true
sudo systemctl enable docker 2>/dev/null || true

# Запуск SIEM сервисов
echo "5. Запуск SIEM сервисов..."
if [ -d ~/monitoring/monitoring-stack ]; then
    cd ~/monitoring/monitoring-stack
    
    if [ -d "loki" ]; then
        echo "   Запуск Loki..."
        cd loki
        docker compose up -d 2>/dev/null || docker-compose up -d 2>/dev/null || true
        cd ..
    fi
    
    if [ -d "prometheus" ]; then
        echo "   Запуск Prometheus..."
        cd prometheus
        docker compose up -d 2>/dev/null || docker-compose up -d 2>/dev/null || true
        cd ..
    fi
    
    if [ -d "grafana" ]; then
        echo "   Запуск Grafana..."
        cd grafana
        docker compose up -d 2>/dev/null || docker-compose up -d 2>/dev/null || true
        cd ..
    fi
fi

# Проверка
echo "6. Проверка контейнеров..."
docker ps 2>/dev/null || true

echo ""
echo "✅ Исправление завершено!"
FIXSCRIPT

# Пытаемся скопировать через разные методы
if command -v sshpass &> /dev/null; then
    sshpass -p "123" scp -o StrictHostKeyChecking=no /tmp/fix_siem_local.sh "$VM:/tmp/fix_siem.sh" 2>/dev/null && \
    sshpass -p "123" ssh -o StrictHostKeyChecking=no "$VM" "chmod +x /tmp/fix_siem.sh && /tmp/fix_siem.sh" 2>/dev/null && \
    echo "✅ Скрипт выполнен успешно" || echo "❌ Не удалось выполнить скрипт"
else
    scp -o StrictHostKeyChecking=no /tmp/fix_siem_local.sh "$VM:/tmp/fix_siem.sh" 2>/dev/null && \
    ssh -o StrictHostKeyChecking=no "$VM" "chmod +x /tmp/fix_siem.sh && /tmp/fix_siem.sh" 2>/dev/null && \
    echo "✅ Скрипт выполнен успешно" || echo "❌ Не удалось выполнить скрипт. Проверьте SSH доступ."
fi

rm -f /tmp/fix_siem_local.sh

