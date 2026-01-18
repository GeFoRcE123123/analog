# ⚡ Быстрое исправление SIEM VM (10.0.88.41)

## 🎯 Проблема
- Файрвол блокирует все порты
- SIEM сервисы не запущены
- SSH недоступен

## 🚀 Решение (выполнить на VM через консоль)

```bash
# 1. Отключить файрвол
sudo ufw disable
sudo ufw --force reset
sudo iptables -F && sudo iptables -X

# 2. Запустить SSH
sudo systemctl start ssh

# 3. Запустить Docker
sudo systemctl start docker

# 4. Запустить SIEM сервисы
cd ~/monitoring/monitoring-stack
cd loki && docker compose up -d && cd ..
cd prometheus && docker compose up -d && cd ..
cd grafana && docker compose up -d && cd ..

# 5. Проверить
docker ps
curl http://localhost:3000
```

## ✅ Проверка
```bash
# С локальной машины
curl http://10.0.88.41:3000   # Grafana
curl http://10.0.88.41:9090   # Prometheus
curl http://10.0.88.41:3100/ready  # Loki
```

📖 **Подробнее:** [SIEM_VM_FIX.md](./SIEM_VM_FIX.md)

