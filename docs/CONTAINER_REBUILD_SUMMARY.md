# Резюме пересборки контейнера и исправлений

## ✅ Выполнено

### 1. Исправлена ошибка `parsing_id = null`
**Проблема:** `save_parsing_history` возвращала `None` из-за ошибки `object of type 'int' has no len()`

**Исправление:**
- Добавлена правильная обработка результата запроса (поддержка разных форматов: список кортежей, кортеж, простое значение)
- Исправлена сериализация `sources` для PostgreSQL массива `TEXT[]` (передается список напрямую, а не JSON строка)
- Добавлен `scan_date` в INSERT запрос

### 2. Удален дублирующийся маршрут
**Проблема:** `AssertionError: View function mapping is overwriting an existing endpoint function: api_redhat_import`

**Исправление:** Удален старый заглушка-маршрут `/api/redhat/import`, оставлен только функциональный

### 3. Исправлена передача `parsing_id` в `parse_all`
**Проблема:** `UnifiedParserService.parse_all() got an unexpected keyword argument 'parsing_id'`

**Исправление:** Убрана передача `parsing_id` в `parse_all()` (он обновляется внутри через `update_parsing_status`)

## Результаты тестирования

### ✅ Parsing ID теперь работает
```json
{"message":"Парсинг запущен","parsing_id":1,"status":"running","success":true}
```

### ✅ Статистика обновляется
- Total in DB: 81528
- Total parsed: 3
- Total saved: 3

### ✅ API endpoints работают
- `/api/parsers/run-all` - запускает парсинг и возвращает `parsing_id`
- `/api/parsing-status` - возвращает статус парсинга
- `/api/parsers/stats` - возвращает статистику

## Изменения в коде

### `services/backend/app.py`

1. **`save_parsing_history`:**
   - Исправлена обработка результата запроса
   - Исправлена сериализация `sources` для PostgreSQL `TEXT[]`
   - Добавлен `scan_date` в INSERT

2. **`api_parsers_run_all`:**
   - Убрана передача `parsing_id` в `parse_all()`
   - `parsing_id` устанавливается в результаты после вызова

3. **Удален дублирующийся маршрут:**
   - Удален старый `/api/redhat/import` (заглушка)
   - Оставлен только функциональный маршрут

## Команды для деплоя

```bash
# Копирование файла на сервер
sshpass -p "123" scp services/backend/app.py user@10.0.88.20:~/vulnerability_manager/backend/app.py

# Копирование в контейнер
sshpass -p "123" ssh user@10.0.88.20 "echo '123' | sudo -S docker cp ~/vulnerability_manager/backend/app.py vulnerability-backend:/app/app.py"

# Перезапуск контейнера
sshpass -p "123" ssh user@10.0.88.20 "echo '123' | sudo -S docker restart vulnerability-backend"
```

## Статус

✅ Контейнер пересобран и работает
✅ `parsing_id` теперь возвращается корректно
✅ Парсинг запускается и сохраняет результаты
✅ Статистика обновляется

## Следующие шаги

1. ✅ Исправлена ошибка `parsing_id = null`
2. ✅ Исправлена ошибка PostgreSQL с массивами
3. ✅ Удален дублирующийся маршрут
4. ⏳ Проверить отображение результатов на фронтенде
5. ⏳ Убедиться, что статистика обновляется в реальном времени
