# 🤖 Руководство по интеграции сложной ИИ-модели

## 📋 Оглавление
1. [Обзор текущей архитектуры](#обзор-текущей-архитектуры)
2. [Точки интеграции](#точки-интеграции)
3. [Интерфейсы и контракты](#интерфейсы-и-контракты)
4. [Варианты интеграции](#варианты-интеграции)
5. [Пошаговая инструкция](#пошаговая-инструкция)
6. [Примеры кода](#примеры-кода)
7. [Тестирование](#тестирование)

---

## 🏗️ Обзор текущей архитектуры

### Текущая реализация

Проект использует **простую систему анализа на основе ключевых слов**:

- **`services/parsers/ai_analyzer.py`** - основной анализатор (ключевые слова + правила)
- **`services/ai_tagger_service.py`** - сервис тегирования (расширенный набор ключевых слов)
- **`services/ai_integration_service.py`** - интеграционный слой (может использовать внешний API)

### Архитектура системы

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend (10.0.88.10)                    │
│              /ai/dashboard, /ai/statistics, etc.             │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP/API
┌──────────────────────────▼──────────────────────────────────┐
│              Backend API (10.0.88.20)                       │
│  /api/ai/analyze, /api/ai/classify, /api/ai/batch-analyze   │
└──────────────────────────┬──────────────────────────────────┘
                           │
        ┌──────────────────┴──────────────────┐
        │                                     │
┌───────▼────────┐                  ┌────────▼────────┐
│ AIIntegration  │                  │  External AI    │
│    Service     │◄─────────────────┤  API (optional) │
│                │   HTTP requests  │  10.0.88.25:8000 │
└───────┬────────┘                  └─────────────────┘
        │
        ├──────────────────┬──────────────────┐
        │                  │                  │
┌───────▼────────┐ ┌───────▼────────┐ ┌───────▼────────┐
│  AIAnalyzer    │ │  AITagger      │ │  Database      │
│  (keywords)    │ │  Service       │ │  (PostgreSQL)  │
└────────────────┘ └────────────────┘ └────────────────┘
```

---

## 🔌 Точки интеграции

### 1. **AIIntegrationService** (Рекомендуется)
**Файл:** `services/ai_integration_service.py`

Этот сервис уже поддерживает:
- ✅ Использование внешнего API (VM 10.0.88.25:8000)
- ✅ Fallback на локальные анализаторы
- ✅ Единый интерфейс для всех компонентов

**Методы для замены:**
- `analyze_vulnerability()` - основной метод анализа
- `classify_vulnerability()` - классификация уязвимости
- `batch_analyze()` - пакетный анализ

### 2. **AIAnalyzer** (Прямая замена)
**Файл:** `services/parsers/ai_analyzer.py`

Текущий класс можно заменить полностью или расширить:
- `analyze_vulnerability()` - возвращает `AIClassification`
- `analyze_all()` - полный анализ (AI + OWASP + Zero-day)

### 3. **API Endpoints** (Backend)
**Файл:** `services/backend/app.py`

Маршруты, которые используют AI:
- `/api/ai/analyze` (POST)
- `/api/ai/classify/<id>` (POST)
- `/api/ai/batch-analyze` (POST)

---

## 📐 Интерфейсы и контракты

### Входные данные (Input)

Все методы принимают словарь `vulnerability_data`:

```python
vulnerability_data = {
    'cve_id': str,              # "CVE-2024-1234"
    'title': str,               # "Vulnerability title"
    'description': str,          # "Full description..."
    'summary': str,              # Optional: краткое описание
    'affected_products': List[Dict],  # [{'vendor': '...', 'product': '...'}]
    'references': List[Dict],    # [{'url': '...', 'name': '...'}]
    'cwe_ids': List[str],        # ["CWE-79", "CWE-89"]
    'cvss_score': float,         # 7.5
    'epss_score': float,         # Optional: 0.85
    'has_exploit': bool,         # Optional: True
    'has_poc': bool,             # Optional: False
    'kev_status': bool,          # Optional: True
    'tags': List[str]            # Optional: ["ai", "ml"]
}
```

### Выходные данные (Output)

#### Вариант 1: AIClassification (текущий формат)
```python
@dataclass
class AIClassification:
    is_ai_related: bool          # True/False
    confidence: float             # 0.0 - 1.0
    ai_categories: List[str]      # ['machine_learning', 'llm', ...]
    reasoning: str                # "Найдены ключевые слова: ..."
```

#### Вариант 2: Расширенный формат (рекомендуется)
```python
{
    'ai_classification': {
        'is_ai_related': bool,
        'confidence': float,
        'categories': List[str],
        'reasoning': str
    },
    'owasp_classification': List[str],  # ['A03', 'A07']
    'zero_day_assessment': {
        'has_zero_day_potential': bool,
        'exploit_available': bool,
        'poc_available': bool,
        'risk_score': float,
        'factors': Dict
    },
    'overall_risk': float
}
```

---

## 🎯 Варианты интеграции

### Вариант 1: Внешний API (Рекомендуется)

**Преимущества:**
- ✅ Не требует изменений в основном коде
- ✅ Легко масштабируется
- ✅ Можно использовать GPU/TPU на отдельном сервере
- ✅ Легко переключаться между моделями

**Как работает:**
1. Создаете API сервер на VM 10.0.88.25 (или другой)
2. Реализуете endpoint `/api/analyze`
3. Обновляете URL в `AIIntegrationService`

**Требования к API:**

```python
# POST http://10.0.88.25:8000/api/analyze
# Request Body:
{
    "title": "CVE-2024-1234: TensorFlow vulnerability",
    "description": "Remote code execution in TensorFlow...",
    "cve_id": "CVE-2024-1234"
}

# Response:
{
    "success": true,
    "is_ai_related": true,
    "confidence": 0.95,
    "categories": ["machine_learning", "tensorflow"],
    "reasoning": "Detected TensorFlow framework...",
    "model_version": "gpt-4-v1.0"
}
```

### Вариант 2: Прямая замена класса

**Преимущества:**
- ✅ Полный контроль над логикой
- ✅ Нет зависимости от сети
- ✅ Быстрее (нет HTTP overhead)

**Недостатки:**
- ❌ Требует изменений в коде
- ❌ Сложнее масштабировать
- ❌ Нужно управлять моделью в основном приложении

### Вариант 3: Гибридный подход (Рекомендуется)

**Как работает:**
1. Сложная модель используется через API
2. Простая модель остается как fallback
3. Автоматическое переключение при недоступности API

---

## 📝 Пошаговая инструкция

### Шаг 1: Подготовка новой ИИ-модели

#### 1.1. Выбор модели

Поддерживаемые типы:
- **LLM** (GPT-4, Claude, Llama, etc.)
- **Fine-tuned модели** (обученные на CVE данных)
- **Ensemble модели** (комбинация нескольких моделей)
- **Специализированные модели** (BERT для security, etc.)

#### 1.2. Создание API сервера (если используете внешний API)

**Пример структуры:**

```python
# ai_api_server.py
from fastapi import FastAPI
from pydantic import BaseModel
import your_ai_model  # Ваша модель

app = FastAPI()

class AnalyzeRequest(BaseModel):
    title: str
    description: str
    cve_id: str

class AnalyzeResponse(BaseModel):
    success: bool
    is_ai_related: bool
    confidence: float
    categories: List[str]
    reasoning: str
    model_version: str

@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze_vulnerability(request: AnalyzeRequest):
    # Ваша логика анализа
    result = your_ai_model.analyze(
        title=request.title,
        description=request.description,
        cve_id=request.cve_id
    )
    
    return AnalyzeResponse(
        success=True,
        is_ai_related=result.is_ai_related,
        confidence=result.confidence,
        categories=result.categories,
        reasoning=result.reasoning,
        model_version="your-model-v1.0"
    )
```

#### 1.3. Развертывание API

```bash
# На VM 10.0.88.25 или другой
cd /path/to/ai_api
pip install fastapi uvicorn your-ai-library
uvicorn ai_api_server:app --host 0.0.0.0 --port 8000
```

### Шаг 2: Интеграция в проект

#### 2.1. Обновление AIIntegrationService

**Файл:** `services/ai_integration_service.py`

**Найдите метод `analyze_vulnerability()` (строка ~89):**

```python
def analyze_vulnerability(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        # Пробуем использовать внешнюю ИИ-систему на VM 10.0.88.25
        if self.ai_api_available:
            try:
                # Формируем запрос для внешней ИИ-системы
                api_data = {
                    'title': vulnerability_data.get('title', ''),
                    'description': vulnerability_data.get('description', ''),
                    'cve_id': vulnerability_data.get('cve_id', '')
                }
                response = requests.post(
                    f"{self.ai_api_url}/api/analyze",
                    json=api_data,
                    timeout=10
                )
                # ... остальной код
```

**Что нужно изменить:**

1. **Обновить URL** (если модель на другом сервере):
```python
# Строка ~66
self.ai_api_url = "http://YOUR_AI_SERVER:PORT"  # Например: "http://10.0.88.25:8000"
```

2. **Расширить запрос** (если модель требует больше данных):
```python
api_data = {
    'title': vulnerability_data.get('title', ''),
    'description': vulnerability_data.get('description', ''),
    'cve_id': vulnerability_data.get('cve_id', ''),
    # Добавьте дополнительные поля:
    'affected_products': vulnerability_data.get('affected_products', []),
    'references': vulnerability_data.get('references', []),
    'cwe_ids': vulnerability_data.get('cwe_ids', []),
    'cvss_score': vulnerability_data.get('cvss_score', 0.0)
}
```

3. **Обработать расширенный ответ** (если модель возвращает больше данных):
```python
if response.status_code == 200:
    api_result = response.json()
    if api_result.get('success'):
        return {
            'is_ai_related': api_result.get('is_ai_related', False),
            'confidence': api_result.get('confidence', 0.0),
            'cve_id': api_result.get('cve_id', ''),
            'source': 'external_ai_api',
            'ai_categories': api_result.get('categories', []),
            'matched_keywords': api_result.get('keywords', []),
            'reasoning': api_result.get('reasoning', ''),
            # Добавьте дополнительные поля:
            'owasp_categories': api_result.get('owasp_categories', []),
            'zero_day_assessment': api_result.get('zero_day_assessment', {}),
            'model_version': api_result.get('model_version', 'unknown')
        }
```

#### 2.2. Альтернатива: Создание нового класса-обертки

**Создайте файл:** `services/parsers/advanced_ai_analyzer.py`

```python
"""
Продвинутый AI анализатор с использованием сложной модели
"""
import logging
import requests
from typing import Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AdvancedAIClassification:
    """Расширенный результат AI анализа"""
    is_ai_related: bool
    confidence: float
    ai_categories: list
    reasoning: str
    # Дополнительные поля
    owasp_categories: list = None
    zero_day_assessment: dict = None
    model_version: str = "unknown"


class AdvancedAIAnalyzer:
    """
    Продвинутый AI анализатор с использованием сложной модели
    
    Поддерживает:
    - LLM модели (GPT-4, Claude, etc.)
    - Fine-tuned модели
    - Ensemble подходы
    """
    
    def __init__(self, api_url: str = "http://10.0.88.25:8000", timeout: int = 30):
        self.api_url = api_url
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self._cache = {}  # Кэш для результатов
    
    def analyze_vulnerability(self, vulnerability_data: Dict[str, Any]) -> AdvancedAIClassification:
        """
        Анализ уязвимости с помощью продвинутой модели
        
        Args:
            vulnerability_data: Данные уязвимости
            
        Returns:
            AdvancedAIClassification объект
        """
        cve_id = vulnerability_data.get('cve_id') or vulnerability_data.get('id', '')
        
        # Проверка кэша
        if cve_id in self._cache:
            return self._cache[cve_id]
        
        try:
            # Формируем запрос к API
            api_data = {
                'title': vulnerability_data.get('title', ''),
                'description': vulnerability_data.get('description', ''),
                'cve_id': cve_id,
                'affected_products': vulnerability_data.get('affected_products', []),
                'references': vulnerability_data.get('references', []),
                'cwe_ids': vulnerability_data.get('cwe_ids', []),
                'cvss_score': vulnerability_data.get('cvss_score', 0.0)
            }
            
            # Вызов API
            response = requests.post(
                f"{self.api_url}/api/analyze",
                json=api_data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                
                classification = AdvancedAIClassification(
                    is_ai_related=result.get('is_ai_related', False),
                    confidence=result.get('confidence', 0.0),
                    ai_categories=result.get('categories', []),
                    reasoning=result.get('reasoning', ''),
                    owasp_categories=result.get('owasp_categories', []),
                    zero_day_assessment=result.get('zero_day_assessment', {}),
                    model_version=result.get('model_version', 'unknown')
                )
                
                # Кэширование
                if cve_id:
                    self._cache[cve_id] = classification
                
                return classification
            else:
                raise Exception(f"API returned {response.status_code}: {response.text}")
                
        except requests.exceptions.Timeout:
            self.logger.error(f"Timeout при обращении к AI API для {cve_id}")
            raise
        except Exception as e:
            self.logger.error(f"Ошибка анализа {cve_id}: {e}", exc_info=True)
            raise
    
    def analyze_all(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Полный анализ (совместимость с текущим интерфейсом)
        """
        classification = self.analyze_vulnerability(vulnerability_data)
        
        return {
            'ai_classification': {
                'is_ai_related': classification.is_ai_related,
                'confidence': classification.confidence,
                'categories': classification.ai_categories,
                'reasoning': classification.reasoning
            },
            'owasp_classification': classification.owasp_categories or [],
            'zero_day_assessment': classification.zero_day_assessment or {},
            'overall_risk': classification.zero_day_assessment.get('risk_score', 0.0) if classification.zero_day_assessment else 0.0,
            'model_version': classification.model_version
        }


# Глобальный экземпляр
advanced_ai_analyzer = AdvancedAIAnalyzer()
```

**Затем обновите `AIIntegrationService`:**

```python
# В services/ai_integration_service.py
try:
    from services.parsers.advanced_ai_analyzer import advanced_ai_analyzer
    ADVANCED_AI_AVAILABLE = True
except ImportError:
    ADVANCED_AI_AVAILABLE = False
    advanced_ai_analyzer = None

# В методе analyze_vulnerability():
# 1. Сначала пробуем продвинутую модель
if ADVANCED_AI_AVAILABLE and advanced_ai_analyzer:
    try:
        result = advanced_ai_analyzer.analyze_all(vulnerability_data)
        return {
            'is_ai_related': result['ai_classification']['is_ai_related'],
            'confidence': result['ai_classification']['confidence'],
            'source': 'advanced_ai_model',
            'model_version': result.get('model_version', 'unknown'),
            # ... остальные поля
        }
    except Exception as e:
        logger.warning(f"Продвинутая модель недоступна: {e}, используем fallback")

# 2. Затем внешний API (если доступен)
# ... существующий код ...

# 3. Затем локальные анализаторы (fallback)
# ... существующий код ...
```

### Шаг 3: Конфигурация

**Файл:** `config.py`

Добавьте настройки для новой модели:

```python
class Config:
    # ... существующие настройки ...
    
    # AI Model Configuration
    AI_MODEL_ENABLED = os.getenv('AI_MODEL_ENABLED', 'true').lower() == 'true'
    AI_MODEL_API_URL = os.getenv('AI_MODEL_API_URL', 'http://10.0.88.25:8000')
    AI_MODEL_TIMEOUT = int(os.getenv('AI_MODEL_TIMEOUT', '30'))
    AI_MODEL_VERSION = os.getenv('AI_MODEL_VERSION', 'v1.0')
    
    # Fallback configuration
    AI_USE_FALLBACK = os.getenv('AI_USE_FALLBACK', 'true').lower() == 'true'
```

### Шаг 4: Обновление импортов

**Файл:** `services/parsers/__init__.py`

```python
# Добавьте новый анализатор
try:
    from .advanced_ai_analyzer import AdvancedAIAnalyzer, advanced_ai_analyzer
    ADVANCED_AI_AVAILABLE = True
except ImportError:
    ADVANCED_AI_AVAILABLE = False
    AdvancedAIAnalyzer = None
    advanced_ai_analyzer = None

__all__ = [
    # ... существующие экспорты ...
    'AdvancedAIAnalyzer',
    'advanced_ai_analyzer',
    'ADVANCED_AI_AVAILABLE'
]
```

---

## 💻 Примеры кода

### Пример 1: Простая интеграция через API

```python
# В вашем AI API сервере (FastAPI/Flask)
from transformers import pipeline
import torch

# Загрузка модели (пример с BERT)
classifier = pipeline(
    "text-classification",
    model="bert-base-uncased",
    device=0 if torch.cuda.is_available() else -1
)

@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest):
    # Объединяем текст
    text = f"{request.title} {request.description}"
    
    # Классификация
    result = classifier(text)
    
    # Определяем is_ai_related на основе результата
    is_ai_related = result[0]['label'] == 'AI_RELATED'
    confidence = result[0]['score']
    
    return {
        "success": True,
        "is_ai_related": is_ai_related,
        "confidence": confidence,
        "categories": ["machine_learning"] if is_ai_related else [],
        "reasoning": f"Model prediction: {result[0]['label']}",
        "model_version": "bert-base-v1.0"
    }
```

### Пример 2: Использование LLM (GPT-4, Claude)

```python
from openai import OpenAI
# или
from anthropic import Anthropic

client = OpenAI(api_key="your-key")
# или
client = Anthropic(api_key="your-key")

@app.post("/api/analyze")
async def analyze_with_llm(request: AnalyzeRequest):
    prompt = f"""
    Analyze this vulnerability and determine if it's AI-related:
    
    Title: {request.title}
    Description: {request.description}
    CVE: {request.cve_id}
    
    Respond in JSON format:
    {{
        "is_ai_related": true/false,
        "confidence": 0.0-1.0,
        "categories": ["category1", "category2"],
        "reasoning": "explanation"
    }}
    """
    
    # GPT-4
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"}
    )
    
    result = json.loads(response.choices[0].message.content)
    
    return {
        "success": True,
        **result,
        "model_version": "gpt-4-v1.0"
    }
```

### Пример 3: Fine-tuned модель

```python
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Загрузка обученной модели
model_path = "/path/to/fine-tuned-model"
tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForSequenceClassification.from_pretrained(model_path)

@app.post("/api/analyze")
async def analyze_with_finetuned(request: AnalyzeRequest):
    text = f"{request.title} {request.description}"
    
    # Токенизация
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
    
    # Предсказание
    with torch.no_grad():
        outputs = model(**inputs)
        predictions = torch.nn.functional.softmax(outputs.logits, dim=-1)
    
    is_ai_related = predictions[0][1].item() > 0.5  # Предполагаем класс 1 = AI-related
    confidence = predictions[0][1].item()
    
    return {
        "success": True,
        "is_ai_related": is_ai_related,
        "confidence": confidence,
        "categories": ["machine_learning"] if is_ai_related else [],
        "reasoning": f"Fine-tuned model prediction: {confidence:.2f}",
        "model_version": "finetuned-bert-v1.0"
    }
```

---

## 🧪 Тестирование

### Тест 1: Проверка подключения

```python
# test_ai_integration.py
import requests

def test_ai_api_connection():
    """Проверка доступности AI API"""
    try:
        response = requests.get("http://10.0.88.25:8000/health", timeout=5)
        assert response.status_code == 200
        print("✅ AI API доступен")
    except Exception as e:
        print(f"❌ AI API недоступен: {e}")

def test_ai_analysis():
    """Тест анализа уязвимости"""
    test_data = {
        "title": "CVE-2024-1234: TensorFlow RCE",
        "description": "Remote code execution vulnerability in TensorFlow machine learning framework",
        "cve_id": "CVE-2024-1234"
    }
    
    response = requests.post(
        "http://10.0.88.25:8000/api/analyze",
        json=test_data,
        timeout=10
    )
    
    assert response.status_code == 200
    result = response.json()
    
    assert result['success'] == True
    assert 'is_ai_related' in result
    assert 'confidence' in result
    assert result['is_ai_related'] == True  # TensorFlow должен быть AI-related
    
    print(f"✅ Анализ работает: confidence={result['confidence']:.2f}")
```

### Тест 2: Интеграция с проектом

```python
# test_integration.py
from services.ai_integration_service import ai_integration_service

def test_integration_service():
    """Тест интеграционного сервиса"""
    test_vuln = {
        'cve_id': 'CVE-2024-1234',
        'title': 'TensorFlow RCE',
        'description': 'Remote code execution in TensorFlow',
        'affected_products': [{'vendor': 'Google', 'product': 'TensorFlow'}]
    }
    
    result = ai_integration_service.analyze_vulnerability(test_vuln)
    
    assert 'is_ai_related' in result
    assert 'confidence' in result
    assert result['source'] in ['external_ai_api', 'advanced_ai_model', 'local']
    
    print(f"✅ Интеграция работает: source={result['source']}")
```

---

## 📊 Мониторинг и логирование

### Добавление метрик

```python
# В AIIntegrationService
import time
from collections import defaultdict

class AIIntegrationService:
    def __init__(self):
        # ... существующий код ...
        self.metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'avg_response_time': 0.0,
            'model_usage': defaultdict(int)
        }
    
    def analyze_vulnerability(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        start_time = time.time()
        self.metrics['total_requests'] += 1
        
        try:
            result = self._do_analysis(vulnerability_data)
            self.metrics['successful_requests'] += 1
            
            # Логирование модели
            model_source = result.get('source', 'unknown')
            self.metrics['model_usage'][model_source] += 1
            
            return result
        except Exception as e:
            self.metrics['failed_requests'] += 1
            raise
        finally:
            response_time = time.time() - start_time
            # Обновление среднего времени ответа
            total = self.metrics['total_requests']
            current_avg = self.metrics['avg_response_time']
            self.metrics['avg_response_time'] = (current_avg * (total - 1) + response_time) / total
```

---

## 🔧 Устранение неполадок

### Проблема 1: API недоступен

**Симптомы:**
- `ConnectionError` или `Timeout`
- Fallback на локальные анализаторы

**Решение:**
1. Проверьте доступность API: `curl http://10.0.88.25:8000/health`
2. Проверьте firewall правила
3. Увеличьте timeout в конфигурации

### Проблема 2: Неправильный формат ответа

**Симптомы:**
- `KeyError` при обращении к полям ответа
- Некорректные результаты анализа

**Решение:**
1. Проверьте формат ответа API
2. Добавьте валидацию ответа
3. Используйте try-except для обработки ошибок

### Проблема 3: Медленная работа

**Симптомы:**
- Долгие ответы API (>10 секунд)
- Таймауты

**Решение:**
1. Оптимизируйте модель (квантизация, pruning)
2. Используйте кэширование
3. Увеличьте timeout или используйте асинхронные запросы

---

## 📚 Дополнительные ресурсы

### Структура проекта

```
services/
├── parsers/
│   ├── ai_analyzer.py          # Текущий простой анализатор
│   ├── advanced_ai_analyzer.py  # НОВЫЙ: Продвинутый анализатор
│   └── __init__.py              # Экспорты
├── ai_integration_service.py    # Интеграционный слой
├── ai_tagger_service.py         # Сервис тегирования
└── backend/
    └── app.py                   # API endpoints
```

### Ключевые файлы для изменения

1. **`services/ai_integration_service.py`** - основная точка интеграции
2. **`services/parsers/advanced_ai_analyzer.py`** - новый класс (создать)
3. **`config.py`** - конфигурация
4. **`services/backend/app.py`** - API endpoints (если нужно расширить)

---

## ✅ Чеклист интеграции

- [ ] Создан API сервер с новой моделью
- [ ] API отвечает на `/api/analyze` endpoint
- [ ] Формат ответа соответствует ожидаемому
- [ ] Обновлен `AIIntegrationService` для использования нового API
- [ ] Добавлена обработка ошибок и fallback
- [ ] Добавлены тесты
- [ ] Обновлена конфигурация (`config.py`)
- [ ] Проверена работа через `/api/ai/analyze` endpoint
- [ ] Проверена работа через UI (`/ai/dashboard`)
- [ ] Добавлено логирование и мониторинг
- [ ] Документация обновлена

---

## 💡 Рекомендации

1. **Начните с внешнего API** - это самый безопасный способ интеграции
2. **Сохраните fallback** - всегда оставляйте простой анализатор как резерв
3. **Используйте кэширование** - для ускорения повторных запросов
4. **Мониторьте производительность** - отслеживайте время ответа и ошибки
5. **Версионируйте модель** - сохраняйте версию модели в результатах
6. **Тестируйте постепенно** - сначала на тестовых данных, затем в production

---

## 🎓 Пример полной интеграции

См. файл `docs/examples/ADVANCED_AI_INTEGRATION_EXAMPLE.md` для полного примера интеграции GPT-4 или другой LLM модели.

---

**Вопросы?** Обратитесь к разработчикам или создайте issue в репозитории.

