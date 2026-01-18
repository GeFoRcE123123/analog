"""
Классификатор уязвимостей на предмет связи с ИИ/ML технологиями
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

from ml_platform.core.logger import PlatformLogger
from ml_platform.security.cve_passport import CVEPassport


class AICategory(Enum):
    """Категории ИИ-связанных уязвимостей"""
    CORE_AI = "core_ai"
    FRAMEWORKS = "frameworks"
    MODELS = "models"
    TECHNIQUES = "techniques"
    DOMAINS = "domains"
    THREATS = "threats"


@dataclass
class AIClassification:
    """Результат классификации на ИИ-связанность"""
    is_ai_related: bool
    confidence: float  # 0.0 - 1.0
    ai_categories: List[str]
    reasoning: str
    matched_keywords: List[str] = None
    owasp_categories: List[str] = None
    zero_day_assessment: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.matched_keywords is None:
            self.matched_keywords = []
        if self.owasp_categories is None:
            self.owasp_categories = []


class AIClassifier:
    """Классификатор уязвимостей на предмет связи с ИИ"""
    
    # Ключевые слова для ИИ-связанных уязвимостей
    AI_KEYWORDS = {
        AICategory.CORE_AI: [
            'artificial intelligence', 'machine learning', 'deep learning',
            'neural network', 'ai model', 'ml model', 'ai system',
            'artificial neural network', 'ann', 'ml algorithm',
            'artificial general intelligence', 'agi', 'narrow ai',
            'supervised learning', 'unsupervised learning', 'semi-supervised learning',
            'ensemble learning', 'meta-learning', 'few-shot learning',
            'zero-shot learning', 'multi-task learning', 'continual learning'
        ],
        AICategory.FRAMEWORKS: [
            'tensorflow', 'pytorch', 'keras', 'scikit-learn', 'scikit learn',
            'huggingface', 'hugging face', 'transformers', 'openai',
            'anthropic', 'deepmind', 'deep mind', 'jax', 'mxnet',
            'caffe', 'theano', 'chainer', 'paddlepaddle',
            'onnx', 'tensorrt', 'openvino', 'coreml', 'mlflow',
            'wandb', 'weights and biases', 'tensorboard', 'comet',
            'ray', 'ray tune', 'optuna', 'hyperopt', 'neptune',
            'dask', 'spark ml', 'mllib', 'flink ml', 'kubeflow'
        ],
        AICategory.MODELS: [
            'llm', 'large language model', 'gpt', 'bert', 'transformer',
            'generative ai', 'generative artificial intelligence',
            'stable diffusion', 'midjourney', 'dall-e', 'dalle',
            'chatgpt', 'claude', 'bard', 'gemini', 'palm', 'llama',
            'mistral', 'falcon', 'bloom', 't5', 'roberta', 'xlnet',
            'gpt-3', 'gpt-4', 'gpt-3.5', 'chatgpt-4', 'claude-2', 'claude-3',
            'llama-2', 'llama-3', 'codellama', 'mistral-7b', 'mixtral',
            'vicuna', 'alpaca', 'orca', 'wizard', 'zephyr',
            'yolo', 'resnet', 'vgg', 'inception', 'efficientnet',
            'mobilenet', 'densenet', 'unet', 'segnet', 'deeplab',
            'stylegan', 'progressive gan', 'cyclegan', 'pix2pix',
            'vae', 'variational autoencoder', 'diffusion model', 'ddpm',
            'ddim', 'latent diffusion', 'controlnet', 'lora', 'qlora'
        ],
        AICategory.TECHNIQUES: [
            'computer vision', 'cv', 'nlp', 'natural language processing',
            'reinforcement learning', 'rl', 'convolutional', 'recurrent',
            'lstm', 'gan', 'generative adversarial network', 'autoencoder',
            'rnn', 'cnn', 'attention mechanism', 'self-attention',
            'transfer learning', 'fine-tuning', 'fine tuning',
            'multi-head attention', 'transformer architecture', 'encoder-decoder',
            'seq2seq', 'sequence to sequence', 'word2vec', 'glove', 'fasttext',
            'elmo', 'ulmfit', 'albert', 'electra', 'deberta',
            'swin transformer', 'vision transformer', 'vit', 'detr',
            'yolo v5', 'yolo v8', 'yolox', 'retinanet', 'faster r-cnn',
            'mask r-cnn', 'fcos', 'centernet', 'efficientdet',
            'gradient boosting', 'xgboost', 'lightgbm', 'catboost',
            'random forest', 'svm', 'support vector machine', 'k-means',
            'dbscan', 'hierarchical clustering', 'pca', 't-sne', 'umap',
            'active learning', 'curriculum learning', 'self-supervised learning',
            'contrastive learning', 'simclr', 'moco', 'swav', 'byol'
        ],
        AICategory.DOMAINS: [
            'autonomous vehicle', 'self-driving', 'robotics', 'robot',
            'recommendation system', 'fraud detection', 'anomaly detection',
            'predictive analytics', 'speech recognition', 'image recognition',
            'facial recognition', 'object detection', 'semantic segmentation',
            'autonomous driving', 'adas', 'advanced driver assistance',
            'medical ai', 'healthcare ai', 'diagnostic ai', 'radiology ai',
            'drug discovery', 'protein folding', 'alphafold', 'cryo-em',
            'financial ai', 'algorithmic trading', 'risk assessment', 'credit scoring',
            'cybersecurity ai', 'threat detection', 'malware detection', 'intrusion detection',
            'network security', 'endpoint protection', 'siem', 'soar',
            'iot security', 'edge ai', 'federated learning', 'edge computing',
            'smart city', 'smart grid', 'industrial ai', 'predictive maintenance',
            'supply chain optimization', 'demand forecasting', 'inventory management',
            'customer service ai', 'chatbot', 'virtual assistant', 'conversational ai',
            'content moderation', 'sentiment analysis', 'text classification',
            'named entity recognition', 'ner', 'question answering', 'qa system',
            'machine translation', 'text summarization', 'text generation',
            'code generation', 'copilot', 'github copilot', 'code completion',
            'automated testing', 'test generation', 'bug detection', 'code review ai'
        ],
        AICategory.THREATS: [
            'adversarial attack', 'adversarial example', 'model poisoning',
            'data poisoning', 'membership inference', 'model inversion',
            'backdoor attack', 'prompt injection', 'jailbreak', 'ai jailbreak',
            'ai hallucination', 'model extraction', 'model stealing',
            'training data extraction', 'privacy attack', 'model evasion',
            'adversarial robustness', 'adversarial training', 'defensive distillation',
            'gradient masking', 'obfuscated gradients', 'transfer attack',
            'black-box attack', 'white-box attack', 'query-based attack',
            'model extraction attack', 'model cloning', 'api extraction',
            'membership inference attack', 'attribute inference', 'model inversion attack',
            'training data extraction attack', 'model memorization', 'overfitting attack',
            'data reconstruction', 'privacy leakage', 'differential privacy violation',
            'federated learning attack', 'byzantine attack', 'sybil attack',
            'gradient leakage', 'gradient inversion', 'model update leakage',
            'prompt injection attack', 'prompt hacking', 'prompt engineering attack',
            'jailbreak attack', 'ai safety bypass', 'alignment attack',
            'red team attack', 'adversarial prompt', 'injection prompt',
            'ai bias', 'algorithmic bias', 'fairness violation', 'discrimination',
            'model drift', 'concept drift', 'data drift', 'distribution shift',
            'model degradation', 'performance degradation', 'accuracy drop',
            'ai safety', 'ai alignment', 'ai ethics', 'responsible ai',
            'ai governance', 'ai regulation', 'ai compliance', 'ai audit'
        ]
    }
    
    # Веса для разных категорий
    CATEGORY_WEIGHTS = {
        AICategory.CORE_AI: 1.0,
        AICategory.FRAMEWORKS: 0.9,
        AICategory.MODELS: 0.95,
        AICategory.TECHNIQUES: 0.8,
        AICategory.DOMAINS: 0.7,
        AICategory.THREATS: 1.0
    }
    
    # CWE коды, связанные с ИИ
    AI_RELATED_CWE = [
        'CWE-79',  # XSS (может быть в веб-интерфейсах ИИ)
        'CWE-89',  # SQL Injection
        'CWE-20',  # Improper Input Validation
        'CWE-434', # Unrestricted Upload
        'CWE-502', # Deserialization
        'CWE-918', # SSRF
        'CWE-352', # CSRF
    ]
    
    # OWASP Top 10 для ИИ
    OWASP_AI_CATEGORIES = {
        'A01': 'Broken Access Control',
        'A03': 'Injection',
        'A04': 'Insecure Design',
        'A05': 'Security Misconfiguration',
        'A07': 'Identification and Authentication Failures',
        'A08': 'Software and Data Integrity Failures'
    }
    
    def __init__(self):
        """Инициализация классификатора"""
        self.logger = PlatformLogger.get_logger()
        self._cache: Dict[str, AIClassification] = {}
    
    def classify_passport(self, passport: CVEPassport) -> AIClassification:
        """
        Классификация паспорта CVE на ИИ-связанность
        
        Args:
            passport: Паспорт CVE
            
        Returns:
            AIClassification объект
        """
        # Проверка кэша
        if passport.cve_id in self._cache:
            return self._cache[passport.cve_id]
        
        # Извлечение текста для анализа
        text_fields = [
            passport.description,
            ' '.join(passport.cwe_ids),
            ' '.join([p.cpe for p in passport.affected_products])
        ]
        
        combined_text = ' '.join([str(field) for field in text_fields]).lower()
        
        # Анализ на ИИ-связанность
        ai_categories = []
        total_score = 0.0
        matches = []
        
        for category, keywords in self.AI_KEYWORDS.items():
            category_matches = []
            weight = self.CATEGORY_WEIGHTS[category]
            
            for keyword in keywords:
                # Поиск ключевых слов (с учетом границ слов)
                pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
                if re.search(pattern, combined_text, re.IGNORECASE):
                    category_matches.append(keyword)
                    total_score += weight
                    matches.append(keyword)
            
            if category_matches:
                ai_categories.append(category.value)
        
        # Проверка CWE
        for cwe_id in passport.cwe_ids:
            if cwe_id in self.AI_RELATED_CWE:
                total_score += 0.5
        
        # Нормализация confidence (0.0 - 1.0)
        # Базовый порог: 2.0 для is_ai_related = True
        is_ai_related = total_score >= 2.0
        confidence = min(1.0, total_score / 10.0)  # Максимум при score >= 10.0
        
        # Формирование reasoning
        if matches:
            reasoning = f"Найдены ключевые слова ИИ/ML: {', '.join(matches[:5])}"
            if len(matches) > 5:
                reasoning += f" и еще {len(matches) - 5}"
        else:
            reasoning = "ИИ-связанные ключевые слова не обнаружены"
        
        # OWASP классификация
        owasp_categories = self._classify_owasp(passport, combined_text)
        
        # Zero-day оценка
        zero_day_assessment = self._assess_zero_day(passport)
        
        classification = AIClassification(
            is_ai_related=is_ai_related,
            confidence=confidence,
            ai_categories=ai_categories,
            reasoning=reasoning,
            matched_keywords=matches,
            owasp_categories=owasp_categories,
            zero_day_assessment=zero_day_assessment
        )
        
        # Кэширование
        self._cache[passport.cve_id] = classification
        
        return classification
    
    def _classify_owasp(self, passport: CVEPassport, text: str) -> List[str]:
        """
        Классификация по OWASP Top 10
        
        Args:
            passport: Паспорт CVE
            text: Текст для анализа
            
        Returns:
            Список OWASP категорий
        """
        categories = []
        
        # A03: Injection
        injection_keywords = ['injection', 'sql injection', 'command injection', 'code injection']
        if any(kw in text for kw in injection_keywords):
            categories.append('A03')
        
        # A07: Identification and Authentication Failures
        auth_keywords = ['authentication', 'authorization', 'access control', 'privilege']
        if any(kw in text for kw in auth_keywords):
            categories.append('A07')
        
        # A08: Software and Data Integrity Failures
        integrity_keywords = ['integrity', 'tampering', 'modification', 'unauthorized change']
        if any(kw in text for kw in integrity_keywords):
            categories.append('A08')
        
        # Проверка CVSS для других категорий
        if passport.scoring.cvss_v3:
            cvss_score = passport.scoring.cvss_v3.get("base_score", 0)
            vector = passport.scoring.cvss_v3.get("vector_string", "")
            
            # A01: Broken Access Control (высокий CVSS + сетевой доступ)
            if cvss_score >= 7.0 and "AV:N" in vector:
                categories.append('A01')
        
        return list(set(categories))
    
    def _assess_zero_day(self, passport: CVEPassport) -> Dict[str, Any]:
        """
        Оценка zero-day потенциала
        
        Args:
            passport: Паспорт CVE
            
        Returns:
            Словарь с оценкой zero-day
        """
        cvss_score = 0.0
        if passport.scoring.cvss_v3:
            cvss_score = passport.scoring.cvss_v3.get("base_score", 0.0)
        
        has_exploit = passport.exploitability.known_exploited
        has_poc = passport.exploitability.proof_of_concept is not None
        
        # Расчет risk score
        risk_score = 0.0
        risk_score += min(cvss_score / 10.0, 0.4)  # До 40% от CVSS
        if has_exploit:
            risk_score += 0.3
        if has_poc:
            risk_score += 0.2
        if passport.exploitability.exploited_in_wild:
            risk_score += 0.1
        
        # Zero-day потенциал
        has_zero_day_potential = (
            cvss_score >= 7.0 and (
                has_exploit or
                has_poc or
                passport.exploitability.known_exploited
            )
        )
        
        return {
            'has_zero_day_potential': has_zero_day_potential,
            'exploit_available': has_exploit,
            'poc_available': has_poc,
            'risk_score': min(1.0, risk_score),
            'factors': {
                'high_cvss': cvss_score >= 7.0,
                'has_exploit': has_exploit,
                'has_poc': has_poc,
                'exploited_in_wild': passport.exploitability.exploited_in_wild is not None
            }
        }
    
    def classify_from_dict(self, vulnerability_data: Dict[str, Any]) -> AIClassification:
        """
        Классификация из словаря данных (совместимость с существующим API)
        
        Args:
            vulnerability_data: Словарь с данными уязвимости
            
        Returns:
            AIClassification объект
        """
        # Создание временного паспорта из данных
        from ml_platform.security.cve_passport import CVEPassport
        
        passport = CVEPassport(vulnerability_data.get('cve_id', 'UNKNOWN'))
        passport.description = vulnerability_data.get('description', '')
        passport.cwe_ids = vulnerability_data.get('cwe_ids', [])
        
        # CVSS
        if vulnerability_data.get('cvss_score'):
            passport.scoring.cvss_v3 = {
                'base_score': vulnerability_data.get('cvss_score', 0.0)
            }
        
        # Эксплуатируемость
        passport.exploitability.known_exploited = vulnerability_data.get('has_exploit', False)
        passport.exploitability.proof_of_concept = vulnerability_data.get('has_poc', False)
        
        return self.classify_passport(passport)


class ExternalAIClassifier:
    """Классификатор через внешний API (согласно руководству)"""
    
    def __init__(self, api_url: str = "http://10.0.88.25:8000", timeout: int = 30):
        """
        Инициализация внешнего классификатора
        
        Args:
            api_url: URL внешнего API
            timeout: Таймаут запроса в секундах
        """
        self.api_url = api_url
        self.timeout = timeout
        self.logger = PlatformLogger.get_logger()
        self._available = None
    
    def _check_availability(self) -> bool:
        """Проверка доступности API"""
        if self._available is not None:
            return self._available
        
        try:
            import requests
            response = requests.get(f"{self.api_url}/health", timeout=5)
            self._available = response.status_code == 200
        except Exception:
            self._available = False
        
        return self._available
    
    def classify(self, passport: CVEPassport) -> Optional[AIClassification]:
        """
        Классификация через внешний API
        
        Args:
            passport: Паспорт CVE
            
        Returns:
            AIClassification или None при ошибке
        """
        if not self._check_availability():
            return None
        
        try:
            import requests
            
            # Формирование запроса
            api_data = {
                'title': passport.cve_id,
                'description': passport.description,
                'cve_id': passport.cve_id,
                'cwe_ids': passport.cwe_ids,
                'cvss_score': passport.scoring.cvss_v3.get('base_score', 0.0) if passport.scoring.cvss_v3 else 0.0
            }
            
            # Запрос к API
            response = requests.post(
                f"{self.api_url}/api/analyze",
                json=api_data,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('success'):
                    return AIClassification(
                        is_ai_related=result.get('is_ai_related', False),
                        confidence=result.get('confidence', 0.0),
                        ai_categories=result.get('categories', []),
                        reasoning=result.get('reasoning', ''),
                        matched_keywords=result.get('keywords', []),
                        owasp_categories=result.get('owasp_categories', []),
                        zero_day_assessment=result.get('zero_day_assessment', {})
                    )
        
        except Exception as e:
            self.logger.warning(f"Ошибка обращения к внешнему AI API: {e}")
        
        return None


class HybridAIClassifier:
    """Гибридный классификатор (внешний API + локальный fallback)"""
    
    def __init__(
        self,
        external_api_url: Optional[str] = None,
        use_external: bool = True,
        use_local: bool = True
    ):
        """
        Инициализация гибридного классификатора
        
        Args:
            external_api_url: URL внешнего API
            use_external: Использовать внешний API
            use_local: Использовать локальный классификатор как fallback
        """
        self.local_classifier = AIClassifier()
        self.external_classifier = None
        
        if use_external and external_api_url:
            self.external_classifier = ExternalAIClassifier(external_api_url)
        
        self.use_external = use_external
        self.use_local = use_local
        self.logger = PlatformLogger.get_logger()
    
    def classify(self, passport: CVEPassport) -> AIClassification:
        """
        Классификация с использованием гибридного подхода
        
        Args:
            passport: Паспорт CVE
            
        Returns:
            AIClassification объект
        """
        # 1. Попытка использовать внешний API
        if self.use_external and self.external_classifier:
            try:
                result = self.external_classifier.classify(passport)
                if result:
                    result.reasoning = f"[External API] {result.reasoning}"
                    return result
            except Exception as e:
                self.logger.warning(f"Внешний API недоступен: {e}, используем локальный классификатор")
        
        # 2. Fallback на локальный классификатор
        if self.use_local:
            result = self.local_classifier.classify_passport(passport)
            result.reasoning = f"[Local Classifier] {result.reasoning}"
            return result
        
        # 3. Если оба недоступны
        return AIClassification(
            is_ai_related=False,
            confidence=0.0,
            ai_categories=[],
            reasoning="Классификаторы недоступны"
        )


# Глобальные экземпляры
ai_classifier = AIClassifier()
hybrid_ai_classifier = HybridAIClassifier()
