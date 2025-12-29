# Перезапуск сервисов

## ✅ Статус перезапуска

### Backend VM (10.0.88.20)
- **Файл обновлен**: ✅
- **Перезапуск**: Выполнен через docker restart
- **Статус**: Контейнер перезапущен

### Parsers VM (10.0.88.23)
- **Файл обновлен**: ✅
- **Перезапуск**: Выполнен через docker restart
- **Статус**: Контейнер перезапущен

## 🔄 Ручной перезапуск (если требуется)

Если автоматический перезапуск не сработал, выполните вручную:

### Backend VM:
```bash
ssh user@10.0.88.20
cd ~/vulnerability_manager/backend
docker compose restart backend
# или
docker restart $(docker ps -q --filter 'name=backend')
```

### Parsers VM:
```bash
ssh user@10.0.88.23
cd ~/vulnerability_manager/parsers
docker compose restart parsers
# или
docker restart $(docker ps -q --filter 'name=parsers')
```

## ✅ Проверка статуса

Проверьте, что сервисы запущены:

```bash
# Backend
ssh user@10.0.88.20
docker ps | grep backend

# Parsers
ssh user@10.0.88.23
docker ps | grep parsers
```

## 📝 Проверка логов

После перезапуска проверьте логи на наличие ошибок:

```bash
# Backend
ssh user@10.0.88.20
docker logs vulnerability-backend | tail -20

# Parsers
ssh user@10.0.88.23
docker logs vulnerability-parsers | tail -20
```

## 🎯 Готово к использованию

После перезапуска исправления применены:
- ✅ Пустой результат возвращает правильные поля (`total_parsed: 0`, `saved_count: 0`)
- ✅ Конвертация в словари использует метод `to_dict()`

Теперь можно запускать парсинг с `enable_nvd=True` и проверять результаты.

