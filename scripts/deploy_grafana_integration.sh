#!/bin/bash
# Деплой Grafana Integration

BACKEND_VM="10.0.88.20"
PASSWORD="123"
BACKEND_USER="user"

export SSHPASS="$PASSWORD"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  🟠 ДЕПЛОЙ GRAFANA INTEGRATION                               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo "Пользователь: $BACKEND_USER@$BACKEND_VM"
echo ""

# Находим директорию проекта на сервере
echo "1️⃣  Поиск директории проекта на сервере..."
PROJECT_PATH=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "find /home -name 'app.py' -path '*/vulnerability_manager/*' 2>/dev/null | head -1 | xargs dirname" 2>&1)

if [ -z "$PROJECT_PATH" ]; then
    PROJECT_PATH=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ls -d ~/vulnerability_manager 2>/dev/null || ls -d /home/*/vulnerability_manager 2>/dev/null" 2>&1 | head -1)
fi

if [ -z "$PROJECT_PATH" ]; then
    echo "❌ Не удалось найти директорию проекта на сервере"
    exit 1
fi

echo "   ✅ Найдена директория: $PROJECT_PATH"

echo ""
echo "2️⃣  Создание необходимых директорий..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "mkdir -p $PROJECT_PATH/services/parsers $PROJECT_PATH/templates/fragments $PROJECT_PATH/scripts $PROJECT_PATH/docs/grafana_parser $PROJECT_PATH/cache" 2>&1
echo "   ✅ Директории созданы"

echo ""
echo "3️⃣  Копирование парсеров Grafana..."
sshpass -e scp -o StrictHostKeyChecking=no services/parsers/grafana_parser.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/parsers/ 2>&1 && echo "   ✅ grafana_parser.py"
sshpass -e scp -o StrictHostKeyChecking=no services/parsers/grafana_mapper.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/parsers/ 2>&1 && echo "   ✅ grafana_mapper.py"
sshpass -e scp -o StrictHostKeyChecking=no services/parsers/grafana_cache.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/parsers/ 2>&1 && echo "   ✅ grafana_cache.py"

echo ""
echo "4️⃣  Копирование скрипта импорта..."
sshpass -e scp -o StrictHostKeyChecking=no scripts/import_grafana_advisories.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/scripts/ 2>&1 && echo "   ✅ import_grafana_advisories.py"
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "chmod +x $PROJECT_PATH/scripts/import_grafana_advisories.py" 2>&1

echo ""
echo "5️⃣  Копирование обновленных backend файлов..."
sshpass -e scp -o StrictHostKeyChecking=no app.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/ 2>&1 && echo "   ✅ app.py (БДУ + Grafana фильтры)"
sshpass -e scp -o StrictHostKeyChecking=no services/vulnerability_service.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/ 2>&1 && echo "   ✅ vulnerability_service.py"
sshpass -e scp -o StrictHostKeyChecking=no models/legacy_repositories.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/models/ 2>&1 && echo "   ✅ legacy_repositories.py"

echo ""
echo "6️⃣  Копирование обновленных шаблонов..."
sshpass -e scp -o StrictHostKeyChecking=no templates/vulnerabilities_list.html $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/templates/ 2>&1 && echo "   ✅ vulnerabilities_list.html (БДУ паспорт + Grafana бейджи)"
sshpass -e scp -o StrictHostKeyChecking=no templates/parsers.html $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/templates/ 2>&1 && echo "   ✅ parsers.html (Grafana секция)"
sshpass -e scp -o StrictHostKeyChecking=no templates/fragments/source_badge.html $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/templates/fragments/ 2>&1 && echo "   ✅ fragments/source_badge.html"

echo ""
echo "7️⃣  Копирование документации..."
sshpass -e scp -o StrictHostKeyChecking=no GRAFANA_INTEGRATION_READY.md $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/ 2>&1 && echo "   ✅ GRAFANA_INTEGRATION_READY.md"
sshpass -e scp -o StrictHostKeyChecking=no GRAFANA_INTEGRATION_SUMMARY.txt $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/ 2>&1 && echo "   ✅ GRAFANA_INTEGRATION_SUMMARY.txt"
sshpass -e scp -r -o StrictHostKeyChecking=no docs/grafana_parser/* $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/docs/grafana_parser/ 2>&1 && echo "   ✅ docs/grafana_parser/ (9 файлов)"

echo ""
echo "8️⃣  Проверка прав доступа..."
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "chmod -R 755 $PROJECT_PATH/services $PROJECT_PATH/templates $PROJECT_PATH/scripts $PROJECT_PATH/cache 2>&1"
echo "   ✅ Права установлены"

echo ""
echo "9️⃣  Перезапуск веб-сервера..."
SERVICE_EXISTS=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "systemctl list-unit-files | grep vulnerability-manager | wc -l" 2>&1)

if [ "$SERVICE_EXISTS" -gt "0" ]; then
    echo "   Перезапуск systemd сервиса..."
    sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "echo '$PASSWORD' | sudo -S systemctl restart vulnerability-manager-backend 2>&1 || sudo -S systemctl restart vulnerability-manager 2>&1"
    
    # Ждем 3 секунды
    sleep 3
    
    # Проверяем статус
    STATUS=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "systemctl is-active vulnerability-manager-backend 2>&1 || systemctl is-active vulnerability-manager 2>&1")
    
    if [ "$STATUS" == "active" ]; then
        echo "   ✅ Сервис успешно перезапущен и работает"
    else
        echo "   ⚠️  Сервис перезапущен, но статус: $STATUS"
        echo "   Проверьте логи: sudo journalctl -u vulnerability-manager-backend -n 50"
    fi
else
    echo "   ⚠️  Systemd сервис не найден"
    echo "   Ищем Flask процесс..."
    FLASK_PID=$(sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ps aux | grep '[a]pp.py' | awk '{print \$2}'" 2>&1)
    
    if [ -n "$FLASK_PID" ]; then
        echo "   Найден Flask процесс (PID: $FLASK_PID)"
        echo "   ⚠️  Требуется ручной перезапуск Flask приложения"
        echo "   Команды:"
        echo "     kill $FLASK_PID"
        echo "     cd $PROJECT_PATH && nohup python3 app.py &"
    else
        echo "   ❌ Flask процесс не найден"
    fi
fi

echo ""
echo "🔟 Проверка установленных файлов..."
echo ""
echo "Парсеры Grafana:"
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ls -lh $PROJECT_PATH/services/parsers/grafana*.py 2>&1" | tail -3
echo ""
echo "Шаблоны:"
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ls -lh $PROJECT_PATH/templates/vulnerabilities_list.html $PROJECT_PATH/templates/parsers.html 2>&1" | tail -2
echo ""
echo "Документация:"
sshpass -e ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "ls $PROJECT_PATH/docs/grafana_parser/ 2>&1 | wc -l"
echo " файлов в docs/grafana_parser/"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ GRAFANA INTEGRATION УСПЕШНО ЗАДЕПЛОЕНА!                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "🟠 Что добавлено:"
echo "   1. Парсеры Grafana (parser, mapper, cache)"
echo "   2. Фильтр по источнику в UI"
echo "   3. Цветные бейджи источников (🟠 Grafana, 🔵 БДУ, 🟣 NVD)"
echo "   4. БДУ ФСТЭК паспорт в модальном окне"
echo "   5. БДУ фильтры (vendor, product, exploit)"
echo "   6. Секция Grafana на странице парсеров"
echo ""
echo "📝 Протестируйте:"
echo "   1. Откройте: http://$BACKEND_VM:5000/vulnerabilities"
echo "   2. Используйте фильтр 'Источник' → выберите 'Grafana Labs'"
echo "   3. Проверьте отображение бейджей источников"
echo "   4. Проверьте БДУ паспорт в модальном окне"
echo "   5. Запустите импорт: python3 $PROJECT_PATH/scripts/import_grafana_advisories.py --dry-run --limit 5"
echo ""
echo "📚 Документация: $PROJECT_PATH/GRAFANA_INTEGRATION_READY.md"
echo ""

unset SSHPASS

