#!/usr/bin/expect -f
# Деплой с использованием expect и паролем 123

set timeout 30
set BACKEND_VM "10.0.88.20"
set BACKEND_USER "admin"
set BACKEND_PASSWORD "123"
set PROJECT_PATH "/opt/vulnerability_manager"

puts "╔══════════════════════════════════════════════════════════════╗"
puts "║  🚀 ДЕПЛОЙ ИНТЕГРАЦИИ ML ПЛАТФОРМЫ                            ║"
puts "╚══════════════════════════════════════════════════════════════╝"
puts ""

# Остановка сервиса
puts "1️⃣  Остановка сервиса..."
spawn ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "echo '$BACKEND_PASSWORD' | sudo -S systemctl stop vulnerability-manager-backend"
expect {
    "password:" {
        send "$BACKEND_PASSWORD\r"
        exp_continue
    }
    eof
}

# Создание директорий
puts "\n2️⃣  Создание директорий..."
spawn ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "mkdir -p $PROJECT_PATH/services $PROJECT_PATH/services/backend $PROJECT_PATH/templates/ai"
expect {
    "password:" {
        send "$BACKEND_PASSWORD\r"
        exp_continue
    }
    eof
}

# Копирование файлов
puts "\n3️⃣  Копирование файлов..."
spawn scp -o StrictHostKeyChecking=no services/ml_platform_client.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/
expect {
    "password:" {
        send "$BACKEND_PASSWORD\r"
        exp_continue
    }
    eof
}
puts "   ✅ ml_platform_client.py"

spawn scp -o StrictHostKeyChecking=no services/backend/app.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/backend/
expect {
    "password:" {
        send "$BACKEND_PASSWORD\r"
        exp_continue
    }
    eof
}
puts "   ✅ app.py"

spawn scp -o StrictHostKeyChecking=no requirements.txt $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/
expect {
    "password:" {
        send "$BACKEND_PASSWORD\r"
        exp_continue
    }
    eof
}
puts "   ✅ requirements.txt"

spawn scp -o StrictHostKeyChecking=no templates/ai/*.html $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/templates/ai/
expect {
    "password:" {
        send "$BACKEND_PASSWORD\r"
        exp_continue
    }
    eof
}
puts "   ✅ HTML шаблоны (5 файлов)"

# Установка зависимостей
puts "\n4️⃣  Установка зависимостей..."
spawn ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "cd $PROJECT_PATH && pip3 install paramiko --break-system-packages"
expect {
    "password:" {
        send "$BACKEND_PASSWORD\r"
        exp_continue
    }
    eof
}

# Запуск сервиса
puts "\n5️⃣  Запуск сервиса..."
spawn ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "echo '$BACKEND_PASSWORD' | sudo -S systemctl start vulnerability-manager-backend"
expect {
    "password:" {
        send "$BACKEND_PASSWORD\r"
        exp_continue
    }
    eof
}

# Проверка статуса
puts "\n6️⃣  Проверка статуса..."
spawn ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM "sudo systemctl status vulnerability-manager-backend --no-pager -l"
expect {
    "password:" {
        send "$BACKEND_PASSWORD\r"
        exp_continue
    }
    eof
}

puts "\n╔══════════════════════════════════════════════════════════════╗"
puts "║  ✅ ДЕПЛОЙ ЗАВЕРШЕН!                                         ║"
puts "╚══════════════════════════════════════════════════════════════╝"
