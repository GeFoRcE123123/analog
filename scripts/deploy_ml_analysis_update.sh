#!/bin/bash
# Деплой обновления для анализа большого количества уязвимостей

BACKEND_VM="10.0.88.20"
BACKEND_USER="user"
PASSWORD="123"

export SSHPASS="$PASSWORD"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🚀 ДЕПЛОЙ ОБНОВЛЕНИЯ ML АНАЛИЗА                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "1️⃣  Копирование обновленных файлов..."
sshpass -e scp -o StrictHostKeyChecking=no services/ml_platform_client.py $BACKEND_USER@$BACKEND_VM:/home/user/vulnerability_manager/services/ 2>&1 && echo "   ✅ ml_platform_client.py"
sshpass -e scp -o StrictHostKeyChecking=no config.py $BACKEND_USER@$BACKEND_VM:/home/user/vulnerability_manager/ 2>&1 && echo "   ✅ config.py"

echo ""
echo "2️⃣  Перезапуск gunicorn..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "echo '$PASSWORD' | sudo -S pkill -HUP gunicorn 2>&1" || echo "⚠️  Перезапуск через HUP"

echo ""
echo "3️⃣  Проверка изменений..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    cd /home/user/vulnerability_manager
    python3 << 'PYTHON'
from config import Config
print('ML_ANALYSIS_MAX_BATCH:', Config.ML_ANALYSIS_MAX_BATCH)
print('ML_ANALYSIS_TIMEOUT:', Config.ML_ANALYSIS_TIMEOUT)
PYTHON
" 2>&1

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ ДЕПЛОЙ ЗАВЕРШЕН!                                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Теперь система может анализировать до ${ML_ANALYSIS_MAX_BATCH:-50000} уязвимостей за раз"

unset SSHPASS
