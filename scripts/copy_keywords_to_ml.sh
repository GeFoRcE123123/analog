#!/bin/bash
# Копирование обновленных ключевых слов на ML платформу

ML_VM="10.0.88.25"
ML_USER="k8s-worker"
PASSWORD="k8s-worker"

export SSHPASS="$PASSWORD"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  📋 КОПИРОВАНИЕ КЛЮЧЕВЫХ СЛОВ НА ML ПЛАТФОРМУ                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "🔍 Поиск пути к ML платформе..."
ML_PATH=$(sshpass -e ssh -o StrictHostKeyChecking=no $ML_USER@$ML_VM "
    # Пробуем разные варианты
    if [ -f ~/ai_service_server.py ]; then
        dirname \$(grep -l 'ai_classifier\|AIClassifier' ~/ai_service_server.py 2>/dev/null | head -1)
    fi
    if [ -d ~/ml_platform ]; then
        echo ~/ml_platform
    elif [ -d ~/security ]; then
        echo ~/security
    else
        find ~ -type d -name 'ml_platform' -o -name 'security' 2>/dev/null | head -1
    fi
" 2>&1 | grep -v 'Permission denied' | head -1)

if [ -z "$ML_PATH" ]; then
    echo "⚠️  Путь не найден автоматически, пробуем стандартные..."
    ML_PATH="~/ml_platform"
fi

echo "Путь: $ML_PATH"

echo ""
echo "📦 Копирование файла..."
sshpass -e scp -o StrictHostKeyChecking=no \
    ml_platform/security/ai_analysis/ai_classifier.py \
    $ML_USER@$ML_VM:$ML_PATH/security/ai_analysis/ 2>&1 || \
sshpass -e scp -o StrictHostKeyChecking=no \
    ml_platform/security/ai_analysis/ai_classifier.py \
    $ML_USER@$ML_VM:~/ 2>&1

if [ $? -eq 0 ]; then
    echo "✅ Файл скопирован"
else
    echo "⚠️  Не удалось скопировать автоматически"
    echo "   Скопируйте вручную: ml_platform/security/ai_analysis/ai_classifier.py"
fi

unset SSHPASS
