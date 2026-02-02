# OSINT Neural Network

Проект для обучения и использования OSINT-специализированной нейросети с интеграциями для популярных инструментов разведки.

## Быстрый старт

1. Создайте виртуальное окружение:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```
2. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```
3. Подготовьте данные:
   ```bash
   python src/data_preparation.py
   ```
4. Запустите обучение:
   ```bash
   python src/training.py
   # или
   bash train.sh
   ```
5. Проверьте инференс:
   ```bash
   python src/inference.py
   ```

## Структура

- `data/` — сырые и обработанные данные, JSONL датасеты.
- `models/` — базовая модель, чекпойнты и финальная модель.
- `src/` — подготовка данных, обучение, оценка, инференс и интеграции.
- `configs/` — конфигурации модели и инструментов.

## Замена недоступных сервисов

Если Censys/SecurityTrails недоступны, используйте встроенные альтернативы:
- `src/integrations/cert_search.py` — поиск доменов через `crt.sh`.
- `src/integrations/dns_intel.py` — DNS/WHOIS и поддомены без ключей.

## Запуск OSINT API (ML VM или локально)

### 1. Запуск FastAPI сервера

```bash
export OSINT_API_HOST=0.0.0.0
export OSINT_API_PORT=8010
python src/api_server.py
```

### 2. Проверка API

```bash
curl http://127.0.0.1:8010/health
```

### 3. Запрос в нейросеть

```bash
curl -X POST http://127.0.0.1:8010/osint/query \
  -H "Content-Type: application/json" \
  -d '{"query":"Проведи OSINT разведку example.com","include_tools":true,"use_cyberintel":true}'
```

### 4. Запрос + BDU формат

```bash
curl -X POST http://127.0.0.1:8010/osint/query-with-bdu \
  -H "Content-Type: application/json" \
  -d '{"query":"Сформируй краткий отчет","vulnerability_id":1,"include_tools":true}'
```

## Демонстрация

```bash
python scripts/demo_osint.py
```

## Переменные окружения

- `OSINT_API_HOST`, `OSINT_API_PORT` — адрес API.
- `OSINT_MODEL_PATH` — путь к модели (по умолчанию `models/final_model`).
- `OSINT_BASE_MODEL` — базовая модель (по умолчанию `mistralai/Mistral-7B-v0.1`).
- `OSINT_USE_LORA` — использовать LoRA (`true/false`).
- `OSINT_DB_HOST`, `OSINT_DB_PORT`, `OSINT_DB_NAME`, `OSINT_DB_USER`, `OSINT_DB_PASSWORD` — параметры БД (если не используются из `config.py`).
