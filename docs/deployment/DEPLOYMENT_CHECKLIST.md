# ✅ Чеклист для развертывания

## 🔍 Что нужно проверить перед развертыванием:

### 1. Сетевая доступность
```bash
# Проверить доступность всех VM
ping -c 1 10.0.88.10
ping -c 1 10.0.88.11
ping -c 1 10.0.88.20
ping -c 1 10.0.88.23
```

### 2. SSH доступ
```bash
# Проверить SSH подключение к каждой VM
ssh user@10.0.88.10 "echo 'OK'"
ssh user@10.0.88.11 "echo 'OK'"
ssh user@10.0.88.20 "echo 'OK'"
ssh user@10.0.88.23 "echo 'OK'"
```

### 3. Docker на всех VM
```bash
# Проверить Docker на каждой VM
ssh user@10.0.88.10 "docker --version"
ssh user@10.0.88.11 "docker --version"
ssh user@10.0.88.20 "docker --version"
ssh user@10.0.88.23 "docker --version"
```

### 4. Docker Compose на всех VM
```bash
# Проверить Docker Compose
ssh user@10.0.88.10 "docker-compose --version"
ssh user@10.0.88.11 "docker-compose --version"
ssh user@10.0.88.20 "docker-compose --version"
ssh user@10.0.88.23 "docker-compose --version"
```

### 5. Порты доступны
```bash
# Проверить, что порты не заняты
ssh user@10.0.88.10 "netstat -tuln | grep :80"
ssh user@10.0.88.11 "netstat -tuln | grep :5432"
ssh user@10.0.88.20 "netstat -tuln | grep :5000"
```

---

## 📋 Последовательность развертывания:

### 1. Database (10.0.88.11) - ПЕРВЫМ!
```bash
./deploy.sh database
```

**Проверка:**
```bash
ssh user@10.0.88.11 "docker ps | grep vulnerability_db"
ssh user@10.0.88.11 "docker logs vulnerability_db | tail -20"
```

### 2. Backend (10.0.88.20)
```bash
./deploy.sh backend
```

**Проверка:**
```bash
curl http://10.0.88.20:5000/api/health
ssh user@10.0.88.20 "docker logs vulnerability-backend | tail -20"
```

### 3. Frontend (10.0.88.10)
```bash
./deploy.sh frontend
```

**Проверка:**
```bash
curl http://10.0.88.10
curl http://10.0.88.10/api/health  # Должен проксировать на Backend
```

### 4. Parsers (10.0.88.23)
```bash
./deploy.sh parsers
```

**Проверка:**
```bash
ssh user@10.0.88.23 "docker logs vulnerability-parsers | tail -20"
```

---

## ⚠️ Возможные проблемы и решения:

### Проблема: "sshpass: command not found"
**Решение:** Скрипт автоматически переключится на обычный ssh (будет запрашивать пароль)

### Проблема: "scp: realpath failed"
**Решение:** Убедитесь, что родительская директория существует на удаленной машине

### Проблема: "Permission denied"
**Решение:** Проверьте права доступа пользователя на VM

### Проблема: "Docker daemon not running"
**Решение:** Запустите Docker на VM: `sudo systemctl start docker`

### Проблема: "Port already in use"
**Решение:** Остановите контейнер или измените порт в docker-compose.yml

---

## 🔧 Дополнительные настройки:

### Если нужен sshpass на macOS:
   ```bash
brew install hudochenkov/sshpass/sshpass
```

### Если нужно настроить SSH ключи (без паролей):
   ```bash
ssh-keygen -t rsa -b 4096
ssh-copy-id user@10.0.88.10
ssh-copy-id user@10.0.88.11
ssh-copy-id user@10.0.88.20
ssh-copy-id user@10.0.88.23
```

---

## ✅ После успешного развертывания:

1. Проверить работу Frontend: http://10.0.88.10
2. Проверить API Backend: http://10.0.88.20:5000/api/health
3. Проверить логи всех сервисов
4. Протестировать функционал приложения
