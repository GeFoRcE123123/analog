#!/bin/bash
# Деплой изменений в обучении модели

BACKEND_VM="10.0.88.20"
BACKEND_USER="user"
BACKEND_PASS="123"
BACKEND_PATH="/home/user/vulnerability_manager"

ML_VM="10.0.88.25"
ML_USER="k8s-worker"
ML_PASS="k8s-worker"
ML_PATH="~/ml_platform"

export SSHPASS="$BACKEND_PASS"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🚀 ДЕПЛОЙ ИЗМЕНЕНИЙ В ОБУЧЕНИИ МОДЕЛИ                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "1️⃣  Копирование на Backend VM (${BACKEND_USER}@${BACKEND_VM})..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Frontend изменения
echo "  📄 templates/ai/training.html..."
sshpass -e scp -o StrictHostKeyChecking=no \
    templates/ai/training.html \
    ${BACKEND_USER}@${BACKEND_VM}:${BACKEND_PATH}/templates/ai/ 2>&1 | grep -v "Warning: Permanently added"

# Backend изменения
echo "  📄 services/ml_platform_client.py..."
sshpass -e scp -o StrictHostKeyChecking=no \
    services/ml_platform_client.py \
    ${BACKEND_USER}@${BACKEND_VM}:${BACKEND_PATH}/services/ 2>&1 | grep -v "Warning: Permanently added"

echo ""
echo "2️⃣  Копирование на ML Platform VM (${ML_USER}@${ML_VM})..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

export SSHPASS="$ML_PASS"

# ML Platform core изменения
echo "  📄 ml_platform/core/visualization.py..."
sshpass -e scp -o StrictHostKeyChecking=no \
    ml_platform/core/visualization.py \
    ${ML_USER}@${ML_VM}:${ML_PATH}/core/ 2>&1 | grep -v "Warning: Permanently added" || \
    sshpass -e ssh -o StrictHostKeyChecking=no ${ML_USER}@${ML_VM} \
    "mkdir -p ${ML_PATH}/core && cat > ${ML_PATH}/core/visualization.py" < ml_platform/core/visualization.py 2>&1

echo "  📄 ml_platform/core/model_trainer.py..."
sshpass -e scp -o StrictHostKeyChecking=no \
    ml_platform/core/model_trainer.py \
    ${ML_USER}@${ML_VM}:${ML_PATH}/core/ 2>&1 | grep -v "Warning: Permanently added" || \
    sshpass -e ssh -o StrictHostKeyChecking=no ${ML_USER}@${ML_VM} \
    "mkdir -p ${ML_PATH}/core && cat > ${ML_PATH}/core/model_trainer.py" < ml_platform/core/model_trainer.py 2>&1

# Viz server (если нужно)
echo "  📦 ml_platform/viz_server/..."
sshpass -e ssh -o StrictHostKeyChecking=no ${ML_USER}@${ML_VM} \
    "mkdir -p ${ML_PATH}/viz_server/templates ${ML_PATH}/viz_server/static/js" 2>&1

sshpass -e scp -o StrictHostKeyChecking=no \
    ml_platform/viz_server/app.py \
    ${ML_USER}@${ML_VM}:${ML_PATH}/viz_server/ 2>&1 | grep -v "Warning: Permanently added"

sshpass -e scp -o StrictHostKeyChecking=no \
    ml_platform/viz_server/templates/index.html \
    ${ML_USER}@${ML_VM}:${ML_PATH}/viz_server/templates/ 2>&1 | grep -v "Warning: Permanently added"

sshpass -e scp -o StrictHostKeyChecking=no \
    ml_platform/viz_server/static/js/three-d3-graph.js \
    ${ML_USER}@${ML_VM}:${ML_PATH}/viz_server/static/js/ 2>&1 | grep -v "Warning: Permanently added"

sshpass -e scp -o StrictHostKeyChecking=no \
    ml_platform/viz_server/requirements.txt \
    ${ML_USER}@${ML_VM}:${ML_PATH}/viz_server/ 2>&1 | grep -v "Warning: Permanently added"

echo ""
echo "3️⃣  Перезапуск сервисов..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Backend
export SSHPASS="$BACKEND_PASS"
echo "  🔄 Перезапуск gunicorn на Backend..."
sshpass -e ssh -o StrictHostKeyChecking=no ${BACKEND_USER}@${BACKEND_VM} \
    "echo '$BACKEND_PASS' | sudo -S pkill -HUP gunicorn 2>&1" | grep -v "password"

echo ""
echo "✅ Деплой завершен!"
echo ""
echo "📋 ПРОВЕРКА:"
echo "  • Backend: http://10.0.88.10/ai/training"
echo "  • ML Platform: проверьте логи на ${ML_USER}@${ML_VM}"

unset SSHPASS
