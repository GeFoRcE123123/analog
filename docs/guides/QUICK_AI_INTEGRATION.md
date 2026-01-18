# 🚀 Быстрая инструкция: Как подключить сложную ИИ-модель

## 📌 Суть задачи

**Текущая ситуация:**
- Проект использует простой анализатор на основе ключевых слов (`AIAnalyzer`)
- Нужно заменить его на более сложную модель (LLM, fine-tuned модель, etc.)

**Решение:**
- Используйте существующий интеграционный слой `AIIntegrationService`
- Он уже поддерживает внешний API и fallback механизм

---

## 🎯 Самый простой способ (5 минут)

### Шаг 1: Создайте API сервер с вашей моделью

```python
# ai_model_api.py
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class AnalyzeRequest(BaseModel):
    title: str
    description: str
    cve_id: str

@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest):
    # Здесь ваша модель
    result = your_model.analyze(request.title, request.description)
    
    return {
        "success": True,
        "is_ai_related": result.is_ai_related,
        "confidence": result.confidence,
        "categories": result.categories,
        "reasoning": result.reasoning,
        "model_version": "your-model-v1.0"
    }
```

### Шаг 2: Обновите URL в проекте

**Файл:** `services/ai_integration_service.py`

**Строка ~66:**
```python
# Было:
self.ai_api_url = "http://10.0.88.25:8000"

# Стало:
self.ai_api_url = "http://ВАШ_СЕРВЕР:ПОРТ"
```

**Готово!** Система автоматически будет использовать вашу модель.

---

## 🔧 Альтернативный способ: Прямая замена класса

Если хотите интегрировать модель напрямую в проект:

### Шаг 1: Создайте новый класс

**Файл:** `services/parsers/advanced_ai_analyzer.py`

```python
from services.parsers.ai_analyzer import AIClassification
import your_ai_library

class AdvancedAIAnalyzer:
    def __init__(self):
        self.model = your_ai_library.load_model()
    
    def analyze_vulnerability(self, vulnerability_data: dict) -> AIClassification:
        text = f"{vulnerability_data.get('title')} {vulnerability_data.get('description')}"
        result = self.model.predict(text)
        
        return AIClassification(
            is_ai_related=result.is_ai_related,
            confidence=result.confidence,
            ai_categories=result.categories,
            reasoning=result.explanation
        )
```

### Шаг 2: Замените импорт

**Файл:** `services/ai_integration_service.py`

**Строка ~12:**
```python
# Было:
from services.parsers.ai_analyzer import ai_analyzer

# Стало:
from services.parsers.advanced_ai_analyzer import AdvancedAIAnalyzer
ai_analyzer = AdvancedAIAnalyzer()
```

---

## 📋 Что нужно знать

### Формат входных данных

```python
vulnerability_data = {
    'cve_id': 'CVE-2024-1234',
    'title': 'Vulnerability title',
    'description': 'Full description...',
    'affected_products': [...],
    'references': [...],
    'cwe_ids': [...],
    'cvss_score': 7.5
}
```

### Формат выходных данных

```python
{
    'is_ai_related': bool,      # True/False
    'confidence': float,         # 0.0 - 1.0
    'categories': List[str],     # ['machine_learning', 'llm']
    'reasoning': str,            # "Explanation..."
    'source': str                # 'external_ai_api' или 'local'
}
```

---

## ✅ Чеклист

- [ ] Модель работает и возвращает правильный формат
- [ ] API доступен по указанному URL
- [ ] Обновлен URL в `AIIntegrationService`
- [ ] Протестировано через `/api/ai/analyze` endpoint
- [ ] Fallback работает (если API недоступен)

---

## 📚 Полная документация

См. `docs/guides/AI_MODEL_INTEGRATION_GUIDE.md` для детальной инструкции.

---

## 💡 Важные моменты

1. **Сохраните fallback** - система автоматически переключится на простой анализатор, если ваша модель недоступна
2. **Формат ответа** - должен соответствовать ожидаемому формату (см. выше)
3. **Таймауты** - настройте разумные таймауты (по умолчанию 10 секунд)
4. **Версионирование** - указывайте версию модели в ответе для отслеживания

---

**Готово!** Ваша модель интегрирована. 🎉

