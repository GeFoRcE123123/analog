#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Service Server для работы с ИИ моделями на VM 10.0.88.25
Запускается локально на VM и предоставляет API для анализа уязвимостей
"""
import os
import sys
import pickle
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Пути к моделям (на VM 10.0.88.25)
MODEL_PATH = os.path.expanduser('~/mnist_visualization/ai_cve_detector.pkl')
VECTORIZER_PATH = os.path.expanduser('~/mnist_visualization/tfidf_vectorizer.pkl')

# Глобальные переменные для моделей
model = None
vectorizer = None


def load_models():
    """Загрузка ИИ моделей (поддержка pickle и joblib)"""
    global model, vectorizer
    try:
        # Пробуем загрузить через joblib (scikit-learn часто использует joblib)
        try:
            import joblib
            if os.path.exists(MODEL_PATH):
                model = joblib.load(MODEL_PATH)
                logger.info(f"✅ Модель загружена через joblib: {type(model).__name__}")
            else:
                logger.error(f"❌ Модель не найдена: {MODEL_PATH}")
                return False
            
            if os.path.exists(VECTORIZER_PATH):
                vectorizer = joblib.load(VECTORIZER_PATH)
                logger.info(f"✅ Векторизатор загружен через joblib: {type(vectorizer).__name__}")
            else:
                logger.error(f"❌ Векторизатор не найден: {VECTORIZER_PATH}")
                return False
        except ImportError:
            logger.warning("joblib не установлен, пробуем pickle")
            # Fallback на pickle
            if os.path.exists(MODEL_PATH):
                with open(MODEL_PATH, 'rb') as f:
                    model = pickle.load(f)
                logger.info(f"✅ Модель загружена через pickle: {type(model).__name__}")
            else:
                logger.error(f"❌ Модель не найдена: {MODEL_PATH}")
                return False
            
            if os.path.exists(VECTORIZER_PATH):
                with open(VECTORIZER_PATH, 'rb') as f:
                    vectorizer = pickle.load(f)
                logger.info(f"✅ Векторизатор загружен через pickle: {type(vectorizer).__name__}")
            else:
                logger.error(f"❌ Векторизатор не найден: {VECTORIZER_PATH}")
                return False
        
        return True
    except Exception as e:
        logger.error(f"❌ Ошибка загрузки моделей: {e}", exc_info=True)
        return False


@app.route('/health', methods=['GET'])
def health():
    """Проверка здоровья сервиса"""
    return jsonify({
        'status': 'healthy' if model and vectorizer else 'unhealthy',
        'model_loaded': model is not None,
        'vectorizer_loaded': vectorizer is not None
    })


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Анализ уязвимости с помощью ИИ"""
    try:
        data = request.get_json()
        
        # Извлекаем текст для анализа
        title = data.get('title', '')
        description = data.get('description', '')
        cve_id = data.get('cve_id', '')
        
        # Объединяем текст
        text = f"{title} {description}".strip()
        
        if not text:
            return jsonify({
                'success': False,
                'error': 'Требуется title или description'
            }), 400
        
        if not model or not vectorizer:
            return jsonify({
                'success': False,
                'error': 'Модели не загружены'
            }), 503
        
        # Векторизация текста
        try:
            text_vector = vectorizer.transform([text])
        except Exception as e:
            logger.error(f"Ошибка векторизации: {e}")
            return jsonify({
                'success': False,
                'error': f'Ошибка векторизации: {str(e)}'
            }), 500
        
        # Предсказание
        try:
            prediction = model.predict(text_vector)[0]
            
            # Если есть predict_proba, используем его для confidence
            confidence = 0.5
            if hasattr(model, 'predict_proba'):
                proba = model.predict_proba(text_vector)[0]
                # Берем максимальную вероятность
                confidence = float(max(proba))
            
            is_ai_related = bool(prediction)
            
            return jsonify({
                'success': True,
                'is_ai_related': is_ai_related,
                'confidence': confidence,
                'cve_id': cve_id,
                'prediction': int(prediction)
            })
            
        except Exception as e:
            logger.error(f"Ошибка предсказания: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': f'Ошибка предсказания: {str(e)}'
            }), 500
            
    except Exception as e:
        logger.error(f"Общая ошибка анализа: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/batch-analyze', methods=['POST'])
def batch_analyze():
    """Пакетный анализ уязвимостей"""
    try:
        data = request.get_json()
        vulnerabilities = data.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return jsonify({
                'success': False,
                'error': 'Требуется список vulnerabilities'
            }), 400
        
        if not model or not vectorizer:
            return jsonify({
                'success': False,
                'error': 'Модели не загружены'
            }), 503
        
        results = []
        texts = []
        
        # Подготовка текстов
        for vuln in vulnerabilities:
            title = vuln.get('title', '')
            description = vuln.get('description', '')
            text = f"{title} {description}".strip()
            texts.append(text)
        
        # Векторизация всех текстов
        try:
            text_vectors = vectorizer.transform(texts)
        except Exception as e:
            logger.error(f"Ошибка пакетной векторизации: {e}")
            return jsonify({
                'success': False,
                'error': f'Ошибка векторизации: {str(e)}'
            }), 500
        
        # Предсказания
        try:
            predictions = model.predict(text_vectors)
            probas = None
            if hasattr(model, 'predict_proba'):
                probas = model.predict_proba(text_vectors)
            
            # Формирование результатов
            for i, vuln in enumerate(vulnerabilities):
                prediction = predictions[i]
                confidence = 0.5
                if probas is not None:
                    confidence = float(max(probas[i]))
                
                results.append({
                    'cve_id': vuln.get('cve_id', ''),
                    'is_ai_related': bool(prediction),
                    'confidence': confidence
                })
            
            return jsonify({
                'success': True,
                'results': results,
                'total': len(results)
            })
            
        except Exception as e:
            logger.error(f"Ошибка пакетного предсказания: {e}", exc_info=True)
            return jsonify({
                'success': False,
                'error': f'Ошибка предсказания: {str(e)}'
            }), 500
            
    except Exception as e:
        logger.error(f"Общая ошибка пакетного анализа: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    logger.info("🚀 Запуск AI Service Server...")
    
    if not load_models():
        logger.error("❌ Не удалось загрузить модели. Сервер не запущен.")
        sys.exit(1)
    
    logger.info("✅ Модели загружены. Запуск Flask сервера...")
    logger.info("📡 API доступен на http://0.0.0.0:8000")
    
    app.run(host='0.0.0.0', port=8000, debug=False)

