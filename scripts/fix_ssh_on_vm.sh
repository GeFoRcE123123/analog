#!/bin/bash
# Скрипт для выполнения на SIEM VM через консоль
# Копируйте этот скрипт на VM и выполняйте: sudo bash fix_ssh_on_vm.sh

set -e

echo "🔧 Исправление SSH на SIEM VM (10.0.88.41)..."
echo "=============================================="
echo ""

# Отключить файрвол
echo "1. Отключение файрвола UFW..."
sudo ufw --force disable 2>/dev/null || echo "   UFW не установлен"
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

# Проверить и установить SSH (если нужно)
echo "3. Проверка SSH..."
if ! command -v sshd &> /dev/null; then
    echo "   Установка SSH сервера..."
    sudo apt update
    sudo apt install -y openssh-server
fi

# Запустить SSH
echo "4. Запуск SSH сервиса..."
sudo systemctl start ssh 2>/dev/null || sudo systemctl start sshd 2>/dev/null || true
sudo systemctl enable ssh 2>/dev/null || sudo systemctl enable sshd 2>/dev/null || true

# Проверить статус
echo "5. Проверка статуса SSH..."
if sudo systemctl is-active --quiet ssh || sudo systemctl is-active --quiet sshd; then
    echo "   ✅ SSH сервис активен"
else
    echo "   ⚠️  SSH сервис не активен, проверяю..."
    sudo systemctl status ssh --no-pager -l 10 || sudo systemctl status sshd --no-pager -l 10
fi

# Проверить порт
echo "6. Проверка порта 22..."
if sudo netstat -tlnp 2>/dev/null | grep -q ":22 " || sudo ss -tlnp 2>/dev/null | grep -q ":22 "; then
    echo "   ✅ Порт 22 слушается"
else
    echo "   ⚠️  Порт 22 не слушается"
fi

echo ""
echo "✅ Исправление завершено!"
echo ""
echo "Проверьте SSH подключение с другой машины:"
echo "  ssh user@10.0.88.41"
echo ""
echo "Если SSH все еще не работает, проверьте:"
echo "  sudo systemctl status ssh"
echo "  sudo journalctl -u ssh -n 50"
echo "  sudo cat /etc/ssh/sshd_config | grep -E '^Port|^PermitRootLogin|^PasswordAuthentication'"

