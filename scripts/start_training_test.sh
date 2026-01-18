#!/bin/bash
# Тестовый запуск обучения

BACKEND_VM="10.0.88.20"
BACKEND_USER="user"
PASSWORD="123"

export SSHPASS="$PASSWORD"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🚀 ТЕСТОВЫЙ ЗАПУСК ОБУЧЕНИЯ                                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "1️⃣  Проверка ML платформы..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    curl -s http://10.0.88.25:8000/health 2>&1 | head -3
" 2>&1

echo ""
echo "2️⃣  Запуск обучения (быстрый сценарий - 50 эпох)..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "
    curl -s -X POST http://10.0.88.25:8000/training/start \
         -H 'Content-Type: application/json' \
         -d '{
             \"epochs\": 50,
             \"batch_size\": 32,
             \"learning_rate\": 0.01,
             \"data_path\": \"/home/k8s-worker/ml_platform/data/cve_data\",
             \"target_column\": \"is_ai_related\"
         }' 2>&1 | python3 -m json.tool 2>/dev/null || cat
" 2>&1

echo ""
echo "✅ Запрос отправлен. Проверьте статус через веб-интерфейс!"

unset SSHPASS
