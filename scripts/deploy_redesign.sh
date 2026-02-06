#!/bin/bash
# Деплой редизайна с анимациями

BACKEND_VM="10.0.88.20"
PASSWORD="123"
BACKEND_USER="user"

export SSHPASS="$PASSWORD"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🎨 ДЕПЛОЙ РЕДИЗАЙНА С АНИМАЦИЯМИ                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo "Пользователь: $BACKEND_USER@$BACKEND_VM"
echo ""

# Находим директорию проекта на сервере
echo "1️⃣  Поиск директории проекта на сервере..."
PROJECT_PATH=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "find /home -name 'app.py' -path '*/vulnerability_manager/*' 2>/dev/null | head -1 | xargs dirname" 2>&1)

if [ -z "$PROJECT_PATH" ]; then
    # Пробуем другие пути
    PROJECT_PATH=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ls -d ~/vulnerability_manager 2>/dev/null || ls -d /home/*/vulnerability_manager 2>/dev/null" 2>&1 | head -1)
fi

if [ -z "$PROJECT_PATH" ]; then
    echo "❌ Не удалось найти директорию проекта на сервере"
    exit 1
fi

echo "   ✅ Найдена директория: $PROJECT_PATH"

echo ""
echo "2️⃣  Создание директорий для новых файлов..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "mkdir -p $PROJECT_PATH/static/css $PROJECT_PATH/static/js $PROJECT_PATH/templates $PROJECT_PATH/docs" 2>&1

echo ""
echo "3️⃣  Копирование CSS анимаций..."
sshpass -e scp -o StrictHostKeyChecking=no static/css/animations-enhanced.css $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/static/css/ 2>&1 && echo "   ✅ animations-enhanced.css"

echo ""
echo "4️⃣  Копирование JavaScript модулей..."
sshpass -e scp -o StrictHostKeyChecking=no static/js/react-bits-vanilla.js $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/static/js/ 2>&1 && echo "   ✅ react-bits-vanilla.js"
sshpass -e scp -o StrictHostKeyChecking=no static/js/gsap-animations.js $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/static/js/ 2>&1 && echo "   ✅ gsap-animations.js"
sshpass -e scp -o StrictHostKeyChecking=no static/js/particles-config.js $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/static/js/ 2>&1 && echo "   ✅ particles-config.js"

echo ""
echo "5️⃣  Копирование обновленных HTML шаблонов..."
sshpass -e scp -o StrictHostKeyChecking=no templates/base.html $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/templates/ 2>&1 && echo "   ✅ base.html"
sshpass -e scp -o StrictHostKeyChecking=no templates/dashboard.html $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/templates/ 2>&1 && echo "   ✅ dashboard.html"

echo ""
echo "6️⃣  Копирование документации..."
sshpass -e scp -o StrictHostKeyChecking=no ANIMATION_REDESIGN_README.md $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/ 2>&1 && echo "   ✅ ANIMATION_REDESIGN_README.md"
sshpass -e scp -o StrictHostKeyChecking=no docs/REDESIGN_*.md $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/docs/ 2>&1 && echo "   ✅ Документация (5 файлов)"

echo ""
echo "7️⃣  Проверка прав доступа..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "chmod -R 755 $PROJECT_PATH/static $PROJECT_PATH/templates 2>&1"

echo ""
echo "8️⃣  Перезапуск веб-сервера (если нужен)..."
# Проверяем, есть ли systemd сервис
SERVICE_EXISTS=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "systemctl list-unit-files | grep vulnerability-manager | wc -l" 2>&1)

if [ "$SERVICE_EXISTS" -gt "0" ]; then
    echo "   Найден systemd сервис, перезапускаем..."
    sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "echo '$PASSWORD' | sudo -S systemctl restart vulnerability-manager-backend 2>&1 || sudo -S systemctl restart vulnerability-manager 2>&1" && echo "   ✅ Сервис перезапущен" || echo "   ⚠️  Не удалось перезапустить (возможно, требуется ручной перезапуск)"
else
    echo "   ⚠️  Systemd сервис не найден. Flask может работать в screen/tmux."
    echo "   Проверьте вручную: ps aux | grep app.py"
fi

echo ""
echo "9️⃣  Проверка установленных файлов..."
echo ""
echo "CSS файлы:"
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ls -lh $PROJECT_PATH/static/css/*.css 2>&1" | grep -v "total"
echo ""
echo "JS файлы:"
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ls -lh $PROJECT_PATH/static/js/*.js 2>&1" | grep -v "total"
echo ""
echo "HTML шаблоны:"
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ls -lh $PROJECT_PATH/templates/{base,dashboard}.html 2>&1"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ РЕДИЗАЙН УСПЕШНО ЗАДЕПЛОЕН!                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "🎨 Новые файлы:"
echo "   - animations-enhanced.css (700+ строк анимаций)"
echo "   - react-bits-vanilla.js (React-Bits компоненты)"
echo "   - gsap-animations.js (GSAP контроллер)"
echo "   - particles-config.js (Particles.js конфиг)"
echo "   - base.html (обновлен с подключением библиотек)"
echo "   - dashboard.html (Hero section + анимации)"
echo ""
echo "📝 Изменения:"
echo "   - Убрана плашка 'Управление командой' для обычных пользователей"
echo "   - Добавлены анимации из 7 библиотек (Animate.css, AOS, GSAP и др.)"
echo "   - Hero section с particles и text reveal"
echo "   - Spotlight cards, magnetic buttons, counters"
echo ""
echo "🌐 Откройте в браузере: http://$BACKEND_VM:5000"
echo ""

unset SSHPASS

