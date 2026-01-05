# 📋 Что нужно от вас для развертывания

## ✅ Минимальные требования:

### 1. Сетевая доступность
- ✅ Все 4 VM должны быть доступны по сети
- ✅ IP адреса: 10.0.88.10, 10.0.88.11, 10.0.88.20, 10.0.88.23

**Проверка:**
```bash
ping -c 1 10.0.88.10
ping -c 1 10.0.88.11
ping -c 1 10.0.88.20
ping -c 1 10.0.88.23
```

### 2. SSH доступ
- ✅ Учетные данные: `user` / `123` (или настроить SSH ключи)
- ✅ SSH доступ должен работать без пароля или с возможностью ввода пароля

**Проверка:**
```bash
ssh user@10.0.88.10 "echo 'OK'"
ssh user@10.0.88.11 "echo 'OK'"
ssh user@10.0.88.20 "echo 'OK'"
ssh user@10.0.88.23 "echo 'OK'"
```

### 3. Docker и Docker Compose на всех VM
- ✅ Docker должен быть установлен и запущен
- ✅ Docker Compose должен быть доступен

**Проверка на каждой VM:**
```bash
docker --version
docker-compose --version
sudo systemctl status docker  # Для Linux
```

### 4. Порты должны быть свободны
- ✅ 10.0.88.10:80 (Frontend - Nginx)
- ✅ 10.0.88.11:5432 (Database - PostgreSQL)
- ✅ 10.0.88.20:5000 (Backend - Flask API)
- ✅ 10.0.88.23: нет внешних портов (Parsers)

**Проверка (на каждой VM):**
```bash
netstat -tuln | grep :80    # Frontend
netstat -tuln | grep :5432  # Database
netstat -tuln | grep :5000  # Backend
```

---

## 🚀 Процесс развертывания:

### Шаг 1: Запустить скрипт
```bash
./deploy.sh all
```

**Если sshpass не установлен**, скрипт будет запрашивать пароль при каждом подключении (введите `123`).

### Шаг 2: Проверить работу

**Database:**
```bash
ssh user@10.0.88.11 "docker ps | grep vulnerability_db"
```

**Backend:**
```bash
curl http://10.0.88.20:5000/api/health
```

**Frontend:**
```bash
curl http://10.0.88.10
```

**Parsers:**
```bash
ssh user@10.0.88.23 "docker logs vulnerability-parsers"
```

---

## 🔧 Опционально (для удобства):

### Установить sshpass (чтобы не вводить пароль):
```bash
# macOS
brew install hudochenkov/sshpass/sshpass

# Linux
sudo apt install sshpass -y
```

### Или настроить SSH ключи:
```bash
ssh-keygen -t rsa -b 4096
ssh-copy-id user@10.0.88.10
ssh-copy-id user@10.0.88.11
ssh-copy-id user@10.0.88.20
ssh-copy-id user@10.0.88.23
```

---

## ❌ Если что-то пошло не так:

### Ошибка: "sshpass: command not found"
**Решение:** Это нормально, скрипт будет использовать обычный ssh (запросит пароль)

### Ошибка: "scp: realpath failed"
**Решение:** Скрипт исправлен, теперь создает директории автоматически

### Ошибка: "Permission denied"
**Решение:** Проверьте права пользователя на VM, убедитесь что пользователь в группе docker:
```bash
sudo usermod -aG docker $USER
```

### Ошибка: "Docker daemon not running"
**Решение:** Запустите Docker:
```bash
sudo systemctl start docker
```

### Ошибка: "Port already in use"
**Решение:** Остановите существующие контейнеры или измените порт

---

## ✅ Что уже готово:

- ✅ Все файлы подготовлены
- ✅ Dockerfile для каждого сервиса
- ✅ docker-compose.yml настроены
- ✅ config.py с правильными IP адресами
- ✅ Скрипт развертывания исправлен

**Всё что нужно - это запустить `./deploy.sh all`!** 🚀

