# ⚡ Быстрое развертывание ИИ-системы

## 🎯 Для доступа к VM 10.0.88.25

**Вам нужно:**
1. **Пользователь:** `k8s-worker` (из ваших данных: "10.0.88.25 k8s-worker k8s-worker")
2. **Пароль:** `k8s-worker` (или уточните ваш реальный пароль)
3. **Команда подключения:**
   ```bash
   ssh k8s-worker@10.0.88.25
   # или
   sshpass -p 'k8s-worker' ssh k8s-worker@10.0.88.25 "whoami"
   ```

---

## 🚀 Быстрое развертывание (3 шага)

### Шаг 1: Установите переменные окружения

```bash
export AI_VM_USER="k8s-worker"
export AI_VM_PASS="k8s-worker"  # Замените на ваш реальный пароль
```

### Шаг 2: Запустите развертывание

```bash
# Автоматическое развертывание на все VM
./deploy.sh all
```

### Шаг 3: Проверьте работу

```bash
# Откройте в браузере
http://10.0.88.10/ai/dashboard
```

---

## 🔒 Настройка безопасности (опционально)

```bash
# 1. Firewall на всех VM
for vm in 10.0.88.10 10.0.88.20 10.0.88.11 10.0.88.23; do
    ssh user@$vm "sudo bash security_configs/firewall_rules.sh"
done

# 2. Fail2ban (защита от брутфорса)
for vm in 10.0.88.10 10.0.88.20 10.0.88.11 10.0.88.23; do
    ssh user@$vm "sudo apt-get install -y fail2ban && sudo systemctl enable fail2ban"
done
```

---

## ✅ Проверка

```bash
# API работает?
curl http://10.0.88.20:5000/api/ai/statistics

# Frontend работает?
curl http://10.0.88.10/ai/dashboard

# Логи без ошибок?
ssh user@10.0.88.20 "docker logs vulnerability-backend --tail 50 | grep -i error"
```

---

## 📞 Если что-то не работает

1. **VM 10.0.88.25 недоступна:**
   - Проверьте, запущена ли VM
   - Проверьте сетевые настройки
   - Попробуйте подключиться вручную: `ssh k8s-worker@10.0.88.25`

2. **ИИ-интерфейс не открывается:**
   - Проверьте логи Frontend: `ssh user@10.0.88.10 "docker logs vulnerability-frontend"`
   - Перезапустите: `ssh user@10.0.88.10 "docker compose restart frontend"`

3. **API не работает:**
   - Проверьте логи Backend: `ssh user@10.0.88.20 "docker logs vulnerability-backend"`
   - Проверьте БД: `ssh user@10.0.88.11 "docker exec vulnerability-db psql -U admin -d vuln_db -c '\dt ai_*'"`

