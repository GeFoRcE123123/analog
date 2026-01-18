# ⚡ Быстрое исправление SSH и Grafana

## 🎯 Что нужно исправить

- ❌ SSH (порт 22) - для удаленного доступа
- ❌ Grafana (порт 3000) - для визуализации

## 🚀 Решение (выполнить на VM через консоль)

```bash
# 1. Войти на VM через консоль провайдера
# login: test
# Password: 123

# 2. Отключить файрвол
sudo ufw --force disable
sudo ufw --force reset
sudo iptables -F && sudo iptables -X
sudo iptables -P INPUT ACCEPT

# 3. Запустить SSH
sudo systemctl start ssh
sudo systemctl enable ssh

# 4. Запустить Grafana
cd ~/monitoring/monitoring-stack
cd grafana && docker compose up -d && cd ..
# или если Grafana в общем compose:
# docker compose up -d grafana
```

**Пароль sudo:** 123

## ✅ Проверка

```bash
# SSH
ssh test@10.0.88.41
# Password: 123

# Grafana
curl http://10.0.88.41:3000
# Браузер: http://10.0.88.41:3000
# Login: admin / Password: admin123
```

📖 **Подробнее:** [FIX_SSH_AND_GRAFANA.md](./FIX_SSH_AND_GRAFANA.md)

