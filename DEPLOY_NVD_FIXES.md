# Деплой исправлений NVD парсинга

## ✅ Изменения

Исправлены две проблемы в `services/nvd_integration_service.py`:

1. **Пустой результат не возвращает правильные поля**:
   - При пустом результате `incremental_sync` теперь устанавливает `total_parsed: 0` и `saved_count: 0`
   - Это позволяет `unified_parser_service` правильно обрабатывать случай, когда уязвимостей не найдено

2. **Конвертация в словари**:
   - Заменено использование `asdict()` на метод `to_dict()` из `NVDVulnerability`
   - Это корректно конвертирует datetime и вложенные объекты

## 📦 Деплой

### Backend VM (10.0.88.20)
Файл должен быть обновлен в:
```
~/vulnerability_manager/backend/services/nvd_integration_service.py
```

### Parsers VM (10.0.88.23)
Файл должен быть обновлен в:
```
~/vulnerability_manager/parsers/services/nvd_integration_service.py
```

## 🔄 Перезапуск сервисов

После обновления файла требуется перезапуск:

### Backend:
```bash
cd ~/vulnerability_manager/backend
sudo docker compose restart backend
# или
sudo docker restart vulnerability-backend
```

### Parsers:
```bash
cd ~/vulnerability_manager/parsers
sudo docker compose restart parsers
# или
sudo docker restart vulnerability-parsers
```

## ✅ Проверка

После деплоя проверьте:

1. Логи на наличие ошибок:
   ```bash
   # Backend
   sudo docker logs vulnerability-backend | grep -i nvd | tail -20
   
   # Parsers
   sudo docker logs vulnerability-parsers | grep -i nvd | tail -20
   ```

2. Запустите парсинг с `enable_nvd=True` и проверьте результаты

3. Убедитесь, что при отсутствии уязвимостей возвращается корректный результат с `parsed: 0, saved: 0`

