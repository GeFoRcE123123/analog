# 🚀 Быстрый старт всех сервисов

## Автоматический запуск всех сервисов

### Вариант 1: Один скрипт (рекомендуется)

```bash
./start_all_services.sh
```

Этот скрипт:
- ✅ Проверяет доступность всех VM
- ✅ Запускает Database (10.0.88.11)
- ✅ Запускает Backend (10.0.88.20)
- ✅ Запускает Frontend (10.0.88.10)
- ✅ Запускает Parsers (10.0.88.23) - если доступна
- ✅ Проверяет статус всех сервисов

### Вариант 2: Проверка статуса

```bash
./check_services.sh
```

Проверяет, какие сервисы запущены и работают.

---

## Ручной запуск (если скрипт не работает)

### 1. Database (10.0.88.11)

```bash
ssh user@10.0.88.11
cd ~/vulnerability_manager/database
echo '123' | sudo -S docker compose up -d
exit
```

### 2. Backend (10.0.88.20)

```bash
ssh user@10.0.88.20
cd ~/vulnerability_manager/backend
echo '123' | sudo -S docker compose up -d
exit
```

### 3. Frontend (10.0.88.10)

```bash
ssh user@10.0.88.10
cd ~/vulnerability_manager/frontend
echo '123' | sudo -S docker compose up -d
exit
```

### 4. Parsers (10.0.88.23) - опционально

```bash
ssh user@10.0.88.23
cd ~/vulnerability_manager/parsers
echo '123' | sudo -S docker compose up -d
exit
```

---

## Проверка работы

После запуска проверьте:

1. **Frontend**: http://10.0.88.10
2. **Backend API**: http://10.0.88.20:5000/api/health
3. **Database**: `ssh user@10.0.88.11` → `docker exec -it vulnerability-db pg_isready -U postgres`

---

## Автозапуск при загрузке VM

Если нужно, чтобы сервисы запускались автоматически при загрузке VM, добавьте в `/etc/rc.local` на каждой VM:

```bash
# На Database VM (10.0.88.11)
cd /home/user/vulnerability_manager/database && docker compose up -d

# На Backend VM (10.0.88.20)
cd /home/user/vulnerability_manager/backend && docker compose up -d

# На Frontend VM (10.0.88.10)
cd /home/user/vulnerability_manager/frontend && docker compose up -d
```

Или создайте systemd сервисы для каждого компонента.

