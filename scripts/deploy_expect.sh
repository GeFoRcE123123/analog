#!/usr/bin/expect -f
# Деплой с использованием expect

set timeout 30
set BACKEND_VM "10.0.88.20"
set BACKEND_USER "admin"
set PROJECT_PATH "/opt/vulnerability_manager"

puts "🚀 Деплой интеграции ML платформы"
puts "=================================="
puts ""

# Запрос пароля
stty -echo
send_user "Введите пароль для $BACKEND_USER@$BACKEND_VM: "
expect_user -re "(.*)\n"
set PASSWORD $expect_out(1,string)
stty echo
puts ""

spawn ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM
expect {
    "password:" {
        send "$PASSWORD\r"
        exp_continue
    }
    "$ " {
        send "sudo systemctl stop vulnerability-manager-backend\r"
        expect "password for"
        send "$PASSWORD\r"
        expect "$ "
        
        send "mkdir -p $PROJECT_PATH/services $PROJECT_PATH/services/backend $PROJECT_PATH/templates/ai\r"
        expect "$ "
        
        send "exit\r"
    }
    timeout {
        puts "Ошибка: таймаут подключения"
        exit 1
    }
}

# Копирование файлов через scp
spawn scp -o StrictHostKeyChecking=no services/ml_platform_client.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/
expect {
    "password:" {
        send "$PASSWORD\r"
        exp_continue
    }
    eof
}

spawn scp -o StrictHostKeyChecking=no services/backend/app.py $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/services/backend/
expect {
    "password:" {
        send "$PASSWORD\r"
        exp_continue
    }
    eof
}

spawn scp -o StrictHostKeyChecking=no requirements.txt $BACKEND_USER@$BACKEND_VM:$PROJECT_PATH/
expect {
    "password:" {
        send "$PASSWORD\r"
        exp_continue
    }
    eof
}

# Установка и запуск
spawn ssh -o StrictHostKeyChecking=no $BACKEND_USER@$BACKEND_VM
expect {
    "password:" {
        send "$PASSWORD\r"
        exp_continue
    }
    "$ " {
        send "cd $PROJECT_PATH && pip3 install paramiko --break-system-packages\r"
        expect "$ "
        
        send "sudo systemctl start vulnerability-manager-backend\r"
        expect "password for"
        send "$PASSWORD\r"
        expect "$ "
        
        send "sudo systemctl status vulnerability-manager-backend --no-pager\r"
        expect "$ "
        
        send "exit\r"
    }
}

puts "\n✅ Деплой завершен!"
