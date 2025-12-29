# Отладка парсинга NVD

## Проблема
Парсинг завершается с результатом: "Спарсено: 0 | Сохранено: 0"

## Причины и решения

### 1. ✅ Исправлено: Пустой результат не возвращает правильные поля
- **Проблема**: В `incremental_sync` при пустом результате не устанавливались `total_parsed` и `saved_count`
- **Решение**: Добавлены эти поля в `stats` при пустом результате

### 2. ✅ Исправлено: Использование asdict вместо to_dict()
- **Проблема**: `asdict()` может некорректно обрабатывать вложенные dataclasses и datetime
- **Решение**: Используется метод `to_dict()` из `NVDVulnerability`, который правильно конвертирует все поля

### 3. Проверка: Включен ли NVD парсинг
Убедитесь, что при запуске парсинга установлен `enable_nvd=True`:
```javascript
{
  "enable_nvd": true,
  "nvd_days": 7  // Количество дней для парсинга
}
```

### 4. Проверка: Работает ли NVD API
Проверьте подключение к NVD API:
- API ключ активирован: `6e96c1b9-a283-4ce3-b83e-bb162d9b4323`
- Лимит запросов: 50 req/s с ключом
- Проверьте логи на наличие ошибок 403 или 429

### 5. Проверка: Есть ли уязвимости за указанный период
Метод `get_recent_vulnerabilities(days=7)` может вернуть пустой список, если:
- За последние 7 дней не было новых уязвимостей
- Увеличен период парсинга (например, `days=30`)

## Команды для проверки

### Проверка логов
```bash
# На Backend VM
ssh user@10.0.88.20
tail -100 ~/vulnerability_manager/backend/logs/app.log | grep -i nvd

# На Parsers VM
ssh user@10.0.88.23
tail -100 ~/vulnerability_manager/parsers/logs/*.log | grep -i nvd
```

### Тестовый запуск парсинга
```python
from services.nvd_parser import MultiThreadedNVDParser
from config import Config

parser = MultiThreadedNVDParser(
    api_key=Config.NVD_API_KEY,
    max_workers=2,
    requests_per_second=5
)

all_vulns, ai_vulns = parser.get_recent_vulnerabilities(days=30)
print(f"Найдено уязвимостей: {len(all_vulns)}")
```

### Проверка сохранения
```python
from services.nvd_integration_service import NVDIntegrationService
from models.legacy_repositories import LegacyVulnerabilityRepository
from models.database import DatabaseManager
from config import Config

db_manager = DatabaseManager()
db_manager.connect()
vuln_repo = LegacyVulnerabilityRepository(db_manager.connection)

nvd_service = NVDIntegrationService(vuln_repo, api_key=Config.NVD_API_KEY)
result = nvd_service.incremental_sync(days=7)
print(f"Результат: {result}")
```

## Следующие шаги

1. ✅ Исправлен возврат пустого результата
2. ✅ Исправлена конвертация в словари
3. ⏭️ Проверить логи парсинга на ошибки
4. ⏭️ Проверить, включен ли `enable_nvd=True` при запуске
5. ⏭️ Попробовать увеличить период парсинга (например, `days=30`)

