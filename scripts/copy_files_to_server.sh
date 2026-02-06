#!/bin/bash
# Копирование файлов Grafana на сервер

SERVER="10.0.88.20"
USER="user"
PASS="123"

echo "🔧 Копирование файлов на сервер $SERVER..."

# Используем sshpass для копирования через SCP
export SSHPASS="$PASS"

# Копируем парсеры
echo "1. Копируем парсеры Grafana..."
sshpass -e scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  services/parsers/grafana_parser.py \
  services/parsers/grafana_mapper.py \
  services/parsers/grafana_cache.py \
  $USER@$SERVER:/tmp/ || echo "❌ Ошибка копирования парсеров"

# Копируем скрипты
echo "2. Копируем скрипты..."
sshpass -e scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  scripts/import_grafana_advisories.py \
  $USER@$SERVER:/tmp/ || echo "❌ Ошибка копирования скриптов"

# Копируем backend файлы
echo "3. Копируем backend файлы..."
sshpass -e scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  app.py \
  $USER@$SERVER:/tmp/app_new.py || echo "❌ Ошибка копирования app.py"

sshpass -e scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  services/vulnerability_service.py \
  $USER@$SERVER:/tmp/ || echo "❌ Ошибка копирования vulnerability_service.py"

sshpass -e scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  models/legacy_repositories.py \
  $USER@$SERVER:/tmp/ || echo "❌ Ошибка копирования legacy_repositories.py"

# Копируем шаблоны
echo "4. Копируем шаблоны..."
sshpass -e scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  templates/vulnerabilities_list.html \
  templates/parsers.html \
  $USER@$SERVER:/tmp/ || echo "❌ Ошибка копирования шаблонов"

sshpass -e scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  templates/fragments/source_badge.html \
  $USER@$SERVER:/tmp/source_badge.html || echo "❌ Ошибка копирования source_badge.html"

# Перемещаем файлы на сервере
echo "5. Перемещаем файлы в /app..."
sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $USER@$SERVER << 'ENDSSH'
echo "123" | sudo -S bash << 'EOF'
mkdir -p /app/services/parsers /app/scripts /app/models /app/services /app/templates/fragments

# Перемещаем файлы
mv /tmp/grafana_parser.py /app/services/parsers/ 2>/dev/null
mv /tmp/grafana_mapper.py /app/services/parsers/ 2>/dev/null
mv /tmp/grafana_cache.py /app/services/parsers/ 2>/dev/null
mv /tmp/import_grafana_advisories.py /app/scripts/ 2>/dev/null
chmod +x /app/scripts/import_grafana_advisories.py 2>/dev/null
mv /tmp/app_new.py /app/app.py 2>/dev/null
mv /tmp/vulnerability_service.py /app/services/ 2>/dev/null
mv /tmp/legacy_repositories.py /app/models/ 2>/dev/null
mv /tmp/vulnerabilities_list.html /app/templates/ 2>/dev/null
mv /tmp/parsers.html /app/templates/ 2>/dev/null
mv /tmp/source_badge.html /app/templates/fragments/ 2>/dev/null

echo "✅ Файлы перемещены"

# Проверяем
ls -lh /app/services/parsers/grafana*.py
ls -lh /app/app.py
ls -lh /app/templates/vulnerabilities_list.html

EOF
ENDSSH

echo ""
echo "6. Перезапуск gunicorn..."
sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $USER@$SERVER << 'ENDSSH'
echo "123" | sudo -S pkill -HUP gunicorn
sleep 2
echo "✅ Gunicorn перезапущен (HUP signal)"
ps aux | grep gunicorn | head -2
ENDSSH

echo ""
echo "╔═══════════════════════════════════════╗"
echo "║  ✅ ДЕПЛОЙ ЗАВЕРШЕН!                  ║"
echo "╚═══════════════════════════════════════╝"
echo ""
echo "Проверьте: http://$SERVER:5000/vulnerabilities"

unset SSHPASS

