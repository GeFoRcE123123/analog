# ⚡ Быстрый старт развертывания

## 🎯 Минимальные команды для развертывания

### 1️⃣ Database (10.0.88.11)

```bash
ssh user@10.0.88.11
cd ~
mkdir -p vulnerability_manager/database
# Скопировать services/database/* в ~/vulnerability_manager/database/
cd vulnerability_manager/database
docker-compose up -d
```

### 2️⃣ Backend (10.0.88.20)

```bash
ssh user@10.0.88.20
cd ~
mkdir -p vulnerability_manager/backend
# Скопировать services/backend/*, models/, services/* (кроме парсеров) в ~/vulnerability_manager/backend/
cd vulnerability_manager/backend
docker-compose up -d
```

### 3️⃣ Frontend (10.0.88.10)

```bash
ssh user@10.0.88.10
cd ~
mkdir -p vulnerability_manager/frontend
# Скопировать services/frontend/*, templates/, static/ в ~/vulnerability_manager/frontend/
cd vulnerability_manager/frontend
docker-compose up -d
```

### 4️⃣ Parsers (10.0.88.23)

```bash
ssh user@10.0.88.23
cd ~
mkdir -p vulnerability_manager/parsers
# Скопировать services/parsers/*, models/, services/parsing*.py, services/nvd*.py, services/redhat*.py, services/osv*.py в ~/vulnerability_manager/parsers/
cd vulnerability_manager/parsers
docker-compose up -d
```

---

## ✅ Проверка

```bash
# Backend
curl http://10.0.88.20:5000/api/health

# Frontend
curl http://10.0.88.10

# Parsers (логи)
ssh user@10.0.88.23 "docker logs vulnerability-parsers"
```

---

## 🔧 Использование автоматического скрипта

```bash
# Установить sshpass (если нет)
sudo apt install sshpass -y

# Запустить развертывание
./deploy.sh all

# Или по отдельности
./deploy.sh database
./deploy.sh backend
./deploy.sh frontend
./deploy.sh parsers
```

