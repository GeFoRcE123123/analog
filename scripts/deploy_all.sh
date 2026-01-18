#!/bin/bash
# Скрипт для развертывания на всех VM с новой структурой проекта
# Использование: ./deploy_all.sh

set -e

FRONTEND_IP="10.0.88.10"
BACKEND_IP="10.0.88.20"
DATABASE_IP="10.0.88.11"
PARSERS_IP="10.0.88.23"

USER="user"
PASSWORD="123"

echo "🚀 Развертывание Vulnerability Manager на все VM"
echo "=================================================="
echo ""

# Проверка sshpass
if ! command -v sshpass &> /dev/null; then
    echo "⚠️  sshpass не найден. Установите: brew install hudochenkov/sshpass/sshpass"
    exit 1
fi

# Функция выполнения команды на VM
run_remote() {
    local ip=$1
    local cmd=$2
    sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no "$USER@$ip" "$cmd"
}

# Функция копирования файлов
copy_to_vm() {
    local ip=$1
    local src=$2
    local dst=$3
    sshpass -p "$PASSWORD" scp -r -o StrictHostKeyChecking=no "$src" "$USER@$ip:$dst"
}

echo "📦 1. Database VM ($DATABASE_IP)"
echo "-----------------------------------"
if ping -c 1 -W 2 "$DATABASE_IP" >/dev/null 2>&1; then
    echo "✅ VM доступна"
    echo "📦 Копирование файлов..."
    copy_to_vm "$DATABASE_IP" "services/database/" "~/vulnerability_manager/database/"
    echo "🔧 Перезапуск контейнера..."
    run_remote "$DATABASE_IP" "cd ~/vulnerability_manager/database && echo '$PASSWORD' | sudo -S docker compose down --remove-orphans 2>/dev/null || true"
    run_remote "$DATABASE_IP" "cd ~/vulnerability_manager/database && echo '$PASSWORD' | sudo -S docker compose up -d --build"
    echo "✅ Database развернута"
else
    echo "❌ VM недоступна"
fi
echo ""

echo "🔌 2. Backend VM ($BACKEND_IP)"
echo "-----------------------------------"
if ping -c 1 -W 2 "$BACKEND_IP" >/dev/null 2>&1; then
    echo "✅ VM доступна"
    echo "📦 Копирование файлов..."
    copy_to_vm "$BACKEND_IP" "services/backend/" "~/vulnerability_manager/backend/"
    copy_to_vm "$BACKEND_IP" "services/legacy_parsers/" "~/vulnerability_manager/backend/services/legacy_parsers/" 2>/dev/null || true
    copy_to_vm "$BACKEND_IP" "config.py" "~/vulnerability_manager/"
    copy_to_vm "$BACKEND_IP" "requirements.txt" "~/vulnerability_manager/"
    echo "🔧 Перезапуск контейнера..."
    run_remote "$BACKEND_IP" "cd ~/vulnerability_manager/backend && echo '$PASSWORD' | sudo -S docker compose down --remove-orphans 2>/dev/null || true"
    run_remote "$BACKEND_IP" "cd ~/vulnerability_manager/backend && echo '$PASSWORD' | sudo -S docker compose up -d --build"
    echo "✅ Backend развернут"
else
    echo "❌ VM недоступна"
fi
echo ""

echo "🌐 3. Frontend VM ($FRONTEND_IP)"
echo "-----------------------------------"
if ping -c 1 -W 2 "$FRONTEND_IP" >/dev/null 2>&1; then
    echo "✅ VM доступна"
    echo "📦 Копирование файлов..."
    copy_to_vm "$FRONTEND_IP" "services/frontend/" "~/vulnerability_manager/frontend/"
    copy_to_vm "$FRONTEND_IP" "templates/" "~/vulnerability_manager/frontend/templates/" 2>/dev/null || true
    echo "🔧 Перезапуск контейнера..."
    run_remote "$FRONTEND_IP" "cd ~/vulnerability_manager/frontend && echo '$PASSWORD' | sudo -S docker compose down --remove-orphans 2>/dev/null || true"
    run_remote "$FRONTEND_IP" "cd ~/vulnerability_manager/frontend && echo '$PASSWORD' | sudo -S docker compose up -d --build"
    echo "✅ Frontend развернут"
else
    echo "❌ VM недоступна"
fi
echo ""

echo "📡 4. Parsers VM ($PARSERS_IP)"
echo "-----------------------------------"
if ping -c 1 -W 2 "$PARSERS_IP" >/dev/null 2>&1; then
    echo "✅ VM доступна"
    echo "📦 Копирование файлов..."
    copy_to_vm "$PARSERS_IP" "services/parsers/" "~/vulnerability_manager/parsers/"
    copy_to_vm "$PARSERS_IP" "services/legacy_parsers/" "~/vulnerability_manager/parsers/services/legacy_parsers/" 2>/dev/null || true
    copy_to_vm "$PARSERS_IP" "config.py" "~/vulnerability_manager/"
    copy_to_vm "$PARSERS_IP" "requirements.txt" "~/vulnerability_manager/"
    echo "🔧 Перезапуск контейнера..."
    run_remote "$PARSERS_IP" "cd ~/vulnerability_manager/parsers && echo '$PASSWORD' | sudo -S docker compose down --remove-orphans 2>/dev/null || true"
    run_remote "$PARSERS_IP" "cd ~/vulnerability_manager/parsers && echo '$PASSWORD' | sudo -S docker compose up -d --build"
    echo "✅ Parsers развернуты"
else
    echo "❌ VM недоступна"
fi
echo ""

echo "✅ Развертывание завершено!"
echo ""
echo "📊 Статус сервисов:"
echo "  Database: http://$DATABASE_IP:5432"
echo "  Backend:  http://$BACKEND_IP:5000"
echo "  Frontend: http://$FRONTEND_IP"
