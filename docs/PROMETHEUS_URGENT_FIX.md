# 🚨 СРОЧНОЕ ИСПРАВЛЕНИЕ: Prometheus недоступен извне

**Проблема:** Prometheus работает на VM, но недоступен извне  
**Статус:** Prometheus работает локально, но порт 9090 заблокирован для внешнего доступа

---

## ✅ Что работает

- ✅ Prometheus запущен на VM
- ✅ API работает: `curl http://localhost:9090/api/v1/status/config` ✅
- ✅ Порт 9090 слушается на VM
- ❌ Недоступен извне: http://10.0.88.41:9090

---

## 🔧 СРОЧНОЕ ИСПРАВЛЕНИЕ

### Выполните на VM через SSH:

```bash
# Подключиться к VM
ssh test@10.0.88.41
# Password: 123

# Открыть порт 9090 в файрволе
echo '123' | sudo -S iptables -I INPUT -p tcp --dport 9090 -j ACCEPT

# Или отключить файрвол полностью (как было запрошено ранее)
echo '123' | sudo -S ufw --force disable
echo '123' | sudo -S iptables -F
echo '123' | sudo -S iptables -P INPUT ACCEPT
echo '123' | sudo -S iptables -P FORWARD ACCEPT
echo '123' | sudo -S iptables -P OUTPUT ACCEPT

# Проверить
curl http://localhost:9090
```

**Пароль для sudo:** 123

---

## 🔍 Альтернативное решение

Если проблема в том, что Prometheus слушает только localhost:

```bash
# На VM проверить конфигурацию
ssh test@10.0.88.41
cd ~/monitoring/monitoring-stack/prometheus

# Проверить docker-compose.yml
cat docker-compose.yml

# Убедиться, что используется host network mode
# или порты проброшены правильно: "9090:9090"
```

---

## ✅ После исправления

Проверьте:
```bash
curl http://10.0.88.41:9090
```

Должен вернуть HTML страницу Prometheus.

---

**⚠️ ВЫПОЛНИТЕ КОМАНДЫ НА VM ПРЯМО СЕЙЧАС!**

