# Интеграция AI анализа уязвимостей

Интеграция функциональности анализа уязвимостей на предмет связи с ИИ/ML технологиями согласно руководству `AI_MODEL_INTEGRATION_GUIDE.md`.

## Реализованные компоненты

### 1. AI Classifier (`security/ai_analysis/ai_classifier.py`)

**AIClassifier** - локальный классификатор на основе ключевых слов:
- Определение ИИ-связанных уязвимостей
- Классификация по категориям (frameworks, models, techniques, etc.)
- OWASP Top 10 классификация
- Оценка zero-day потенциала

**ExternalAIClassifier** - классификатор через внешний API:
- Поддержка внешнего API (например, `http://10.0.88.25:8000`)
- Автоматическая проверка доступности
- Обработка ошибок и таймаутов

**HybridAIClassifier** - гибридный подход (рекомендуется):
- Приоритет внешнему API
- Fallback на локальный классификатор
- Автоматическое переключение

### 2. Расширение паспортов CVE

Добавлено поле `ai_classification` в `CVEPassport`:
- Сохранение результатов AI анализа
- Интеграция с существующей структурой
- Сериализация в JSON

### 3. API Endpoints (`security/api/ai_security_api.py`)

- `POST /security/ai/analyze` - анализ уязвимости
- `POST /security/ai/classify/{cve_id}` - классификация CVE
- `POST /security/ai/batch-analyze` - пакетный анализ
- `GET /security/ai/stats` - статистика по AI-связанным уязвимостям

## Использование

### Через Python API

```python
from ml_platform.security.ai_analysis.ai_classifier import HybridAIClassifier
from ml_platform.security.cve_passport import CVEPassportManager

# Получение паспорта
manager = CVEPassportManager()
passport = manager.get_passport("CVE-2024-1234")

# AI классификация
classifier = HybridAIClassifier(
    external_api_url="http://10.0.88.25:8000",  # Опционально
    use_external=True,
    use_local=True
)
classification = classifier.classify(passport)

# Результат
print(f"ИИ-связана: {classification.is_ai_related}")
print(f"Уверенность: {classification.confidence}")
print(f"Категории: {classification.ai_categories}")
```

### Через REST API

```bash
# Анализ уязвимости
curl -X POST http://localhost:8000/security/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "cve_id": "CVE-2024-1234",
    "description": "TensorFlow remote code execution",
    "cwe_ids": ["CWE-79"],
    "cvss_score": 9.8
  }'

# Ответ:
{
  "success": true,
  "is_ai_related": true,
  "confidence": 0.95,
  "categories": ["frameworks", "core_ai"],
  "reasoning": "[Local Classifier] Найдены ключевые слова ИИ/ML: tensorflow, remote code execution",
  "matched_keywords": ["tensorflow", "remote code execution"],
  "owasp_categories": ["A03"],
  "zero_day_assessment": {
    "has_zero_day_potential": true,
    "exploit_available": false,
    "poc_available": false,
    "risk_score": 0.98
  },
  "model_version": "hybrid-v1.0"
}
```

## Интеграция с внешним API

Для использования внешнего AI API (например, GPT-4, Claude, или fine-tuned модель):

1. **Создайте API сервер** согласно `AI_MODEL_INTEGRATION_GUIDE.md`
2. **Настройте URL** в `HybridAIClassifier`:
   ```python
   classifier = HybridAIClassifier(
       external_api_url="http://your-ai-server:8000"
   )
   ```
3. **Или через переменные окружения**:
   ```bash
   export AI_API_URL="http://10.0.88.25:8000"
   ```

### Требования к внешнему API

API должен отвечать на `POST /api/analyze`:

**Request:**
```json
{
  "title": "CVE-2024-1234",
  "description": "Vulnerability description...",
  "cve_id": "CVE-2024-1234",
  "cwe_ids": ["CWE-79"],
  "cvss_score": 7.5
}
```

**Response:**
```json
{
  "success": true,
  "is_ai_related": true,
  "confidence": 0.95,
  "categories": ["frameworks", "models"],
  "reasoning": "Detected TensorFlow framework...",
  "keywords": ["tensorflow"],
  "owasp_categories": ["A03"],
  "zero_day_assessment": {
    "has_zero_day_potential": true,
    "risk_score": 0.9
  },
  "model_version": "gpt-4-v1.0"
}
```

## Категории ИИ-связанных уязвимостей

- **core_ai** - Основные ИИ концепции (machine learning, neural networks)
- **frameworks** - ИИ фреймворки (TensorFlow, PyTorch, HuggingFace)
- **models** - ИИ модели (GPT, BERT, LLM, Stable Diffusion)
- **techniques** - ИИ техники (NLP, Computer Vision, Reinforcement Learning)
- **domains** - Применение ИИ (autonomous vehicles, robotics)
- **threats** - ИИ-специфичные угрозы (adversarial attacks, prompt injection)

## Примеры

См. `examples/ai_security_analysis.py` для полного примера использования.

## Совместимость

Интеграция полностью совместима с:
- Существующими паспортами CVE
- API endpoints безопасности
- ML моделями классификации
- Движком расчета рисков

## Конфигурация

Настройки через переменные окружения:

```bash
# Внешний AI API
export AI_API_URL="http://10.0.88.25:8000"
export AI_API_TIMEOUT=30

# Использование внешнего API
export AI_USE_EXTERNAL=true

# Использование локального классификатора
export AI_USE_LOCAL=true
```

## Мониторинг

AI классификация логируется через `PlatformLogger`:
- Успешные классификации
- Ошибки внешнего API
- Переключение на fallback
- Статистика использования

## Дальнейшее развитие

- Интеграция с существующим `AIIntegrationService` проекта
- Поддержка дополнительных внешних API
- Кэширование результатов
- Метрики производительности
- A/B тестирование моделей
