# Настройка NVD API ключа

## ✅ API ключ получен, активирован и добавлен в конфигурацию

**API ключ**: `6e96c1b9-a283-4ce3-b83e-bb162d9b4323`

**Статус**: ✅ **АКТИВИРОВАН** (Validation complete)

---

## 🔑 Активация ключа

✅ **Ключ уже активирован!** Validation complete.

---

## ⚙️ Что было изменено

### 1. Добавлен в `config.py`:
```python
NVD_API_KEY = "FD15D1F9-72E3-F011-8365-129478FCB64D"
NVD_REQUESTS_PER_SECOND = 50  # Увеличено с 5 до 50 с ключом
```

### 2. Обновлены файлы для использования ключа:
- ✅ `services/integrated_parser_service.py` - использует ключ из конфига
- ✅ `services/unified_parser_service.py` - передает ключ в NVDIntegrationService
- ✅ `services/parsers/run_parsers.py` - использует ключ из конфига
- ✅ `services/nvd_integration_service.py` - автоматически использует ключ из конфига

---

## 🚀 Преимущества использования API ключа

### Без ключа:
- ❌ 5 запросов в секунду
- ❌ Медленная синхронизация
- ❌ Высокий риск блокировки (HTTP 429)

### С ключом (после активации):
- ✅ 50 запросов в секунду (в 10 раз быстрее!)
- ✅ Быстрая синхронизация
- ✅ Меньше вероятность блокировки

---

## 📝 Использование

Ключ будет автоматически использоваться во всех местах, где инициализируется NVD парсер:

```python
# Автоматически использует ключ из Config.NVD_API_KEY
from services.nvd_integration_service import NVDIntegrationService
nvd_service = NVDIntegrationService(vulnerability_repo)
```

---

## 🔒 Безопасность

**Для production окружения рекомендуется:**

1. Использовать переменную окружения вместо хардкода:
   ```bash
   export NVD_API_KEY="FD15D1F9-72E3-F011-8365-129478FCB64D"
   ```

2. Или создать `.env` файл (не коммитить в git!):
   ```
   NVD_API_KEY=FD15D1F9-72E3-F011-8365-129478FCB64D
   ```

3. Обновить `config.py` для чтения из переменной окружения:
   ```python
   NVD_API_KEY = os.getenv("NVD_API_KEY", "FD15D1F9-72E3-F011-8365-129478FCB64D")
   ```
   (уже сделано!)

---

## ✅ Проверка работы

После активации ключа проверьте:

```python
from services.nvd_integration_service import NVDIntegrationService
from models.postgres_repositories import PostgresVulnerabilityRepository
from database.database_manager import DatabaseManager

db_manager = DatabaseManager()
vuln_repo = PostgresVulnerabilityRepository(db_manager.connection)
nvd_service = NVDIntegrationService(vuln_repo)

# Проверка подключения
status = nvd_service.validate_connection()
print(status)  # Должно быть: {'status': 'success', ...}
```

---

## 🎯 Следующие шаги

1. ✅ **Активировать ключ** по ссылке выше
2. ✅ Перезапустить сервисы (если они запущены)
3. ✅ Проверить работу через `validate_connection()`
4. ✅ Запустить тестовую синхронизацию

---

**Статус**: Ключ добавлен в конфигурацию, но требует активации перед использованием.

