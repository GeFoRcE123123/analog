#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI Service Server (k8s-worker)

Исторически на VM был поднят простой Flask-сервис, который поддерживает:
- /health
- /api/analyze
- /api/batch-analyze

Для интеграции с основным проектом (раздел "ИИ-Анализ") добавлены:
- алиасы под "ml_platform"-совместимые пути:
  - POST /security/ai/analyze
  - POST /security/ai/batch-analyze
  - GET  /security/ai/stats
- эндпоинты обучения (epoch-based) для графиков:
  - POST /training/start
  - GET  /training/status/<task_id>
  - GET  /training/history

Сервис тренирует простую модель на TF-IDF признаках с epoch-итерациями через SGDClassifier
и пишет историю в ~/ai_training_history.json.
"""

import os
import sys
import json
import time
import uuid
import pickle
import logging
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

from flask import Flask, request, jsonify
from flask_cors import CORS

import numpy as np

# sklearn (на VM уже есть)
from sklearn.model_selection import train_test_split
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import log_loss, accuracy_score
from sklearn.feature_extraction.text import TfidfVectorizer


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Paths (на VM 10.0.88.25)
MODEL_PATH = os.path.expanduser('~/mnist_visualization/ai_cve_detector.pkl')
VECTORIZER_PATH = os.path.expanduser('~/mnist_visualization/tfidf_vectorizer.pkl')
TRAINING_HISTORY_PATH = os.path.expanduser('~/ai_training_history.json')

model = None
vectorizer = None

# --- Context-aware AI vulnerability heuristics ---
# Цель: отличать уязвимости ИИ/ML (prompt injection, model poisoning, model extraction и т.д.)
# от обычных уязвимостей, даже если встречаются "похожие" слова.
AI_CONTEXT_KEYWORDS = {
    # core ML/AI
    "core": [
        "machine learning", "ml model", "neural network", "deep learning", "llm", "large language model",
        "training", "fine-tuning", "inference", "prompt", "embeddings", "vector database", "rag",
        "weights", "model weights", "checkpoint", "transformer", "token", "tokens",
    ],
    # attacks specific to ML/AI
    "attacks": [
        "prompt injection", "jailbreak", "data poisoning", "poisoning", "model poisoning",
        "model extraction", "model stealing", "membership inference", "model inversion",
        "adversarial example", "adversarial", "backdoor", "trojan", "supply chain for model",
    ],
    # popular frameworks/platforms
    "frameworks": [
        "pytorch", "tensorflow", "keras", "onnx", "hugging face", "transformers", "langchain", "llama",
        "openai", "anthropic", "gemini", "stable diffusion", "diffusion",
    ],
}

NON_AI_VULN_KEYWORDS = [
    # typical non-AI vuln classes (can still be AI-related if context says so, but usually not)
    "sql injection", "xss", "cross-site scripting", "csrf", "ssrf", "directory traversal",
    "buffer overflow", "use-after-free", "heap overflow", "stack overflow", "integer overflow",
    "race condition", "privilege escalation", "kernel", "openssl", "glibc",
]


def _keyword_context_score(text: str) -> Dict[str, Any]:
    t = (text or "").lower()
    hits: List[str] = []
    attack_hits: List[str] = []
    neg_hits: List[str] = []
    score = 0.0

    for group, kws in AI_CONTEXT_KEYWORDS.items():
        for kw in kws:
            if kw in t:
                hits.append(kw)
                if group == "attacks":
                    attack_hits.append(kw)
                    score += 1.0
                else:
                    score += 0.6

    for kw in NON_AI_VULN_KEYWORDS:
        if kw in t:
            neg_hits.append(kw)
            score -= 0.3

    # normalize to 0..1
    norm = max(0.0, min(1.0, score / 4.0))
    return {"score": norm, "hits": hits[:30], "neg_hits": neg_hits[:30], "attack_hits": attack_hits[:30]}

# Runtime stats (best-effort)
stats_lock = threading.Lock()
ai_stats: Dict[str, Any] = {
    "total_cves": 0,
    "ai_related_count": 0,
    "category_distribution": {},
    "last_updated": None,
    "confidence_sum": 0.0,
    "confidence_count": 0,
    # keyword frequency stats (real, from keyword_hits/attack_hits in analysis)
    "keyword_distribution": {},  # keyword -> count
    "attack_distribution": {},   # attack keyword -> count
}

# Training tasks
training_lock = threading.Lock()
active_trainings: Dict[str, Dict[str, Any]] = {}


def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _safe_backup(path: str) -> Optional[str]:
    if not os.path.exists(path):
        return None
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    backup_path = f"{path}.bak.{ts}"
    try:
        os.rename(path, backup_path)
        return backup_path
    except Exception:
        return None


def load_models() -> bool:
    """Загрузка ИИ моделей (поддержка pickle и joblib)."""
    global model, vectorizer
    try:
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
            if os.path.exists(MODEL_PATH):
                with open(MODEL_PATH, "rb") as f:
                    model = pickle.load(f)
                logger.info(f"✅ Модель загружена через pickle: {type(model).__name__}")
            else:
                logger.error(f"❌ Модель не найдена: {MODEL_PATH}")
                return False

            if os.path.exists(VECTORIZER_PATH):
                with open(VECTORIZER_PATH, "rb") as f:
                    vectorizer = pickle.load(f)
                logger.info(f"✅ Векторизатор загружен через pickle: {type(vectorizer).__name__}")
            else:
                logger.error(f"❌ Векторизатор не найден: {VECTORIZER_PATH}")
                return False

        return True
    except Exception as e:
        logger.error(f"❌ Ошибка загрузки моделей: {e}", exc_info=True)
        return False


def _ensure_vectorizer_fitted(texts: List[str]) -> TfidfVectorizer:
    """Ensure we have a fitted vectorizer; fall back to a new one if needed."""
    global vectorizer

    if vectorizer is None:
        vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
        vectorizer.fit(texts)
        return vectorizer

    # If it's a sklearn vectorizer but not fitted yet
    try:
        getattr(vectorizer, "vocabulary_")  # will raise if not fitted
        return vectorizer
    except Exception:
        try:
            if isinstance(vectorizer, TfidfVectorizer):
                vectorizer.fit(texts)
                return vectorizer
        except Exception:
            pass

    # Fallback: create a new fitted vectorizer
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    vectorizer.fit(texts)
    return vectorizer


def _save_artifacts(new_model: Any, new_vectorizer: Any) -> None:
    """Save model/vectorizer with a backup."""
    try:
        try:
            import joblib
            _safe_backup(MODEL_PATH)
            _safe_backup(VECTORIZER_PATH)
            joblib.dump(new_model, MODEL_PATH)
            joblib.dump(new_vectorizer, VECTORIZER_PATH)
            return
        except ImportError:
            pass

        _safe_backup(MODEL_PATH)
        _safe_backup(VECTORIZER_PATH)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(new_model, f)
        with open(VECTORIZER_PATH, "wb") as f:
            pickle.dump(new_vectorizer, f)
    except Exception as e:
        logger.error(f"❌ Ошибка сохранения артефактов: {e}", exc_info=True)


def _update_stats(results: List[Dict[str, Any]]) -> None:
    with stats_lock:
        ai_stats["total_cves"] += len(results)
        ai_stats["ai_related_count"] += sum(1 for r in results if r.get("is_ai_related"))
        ai_stats["category_distribution"].setdefault("AI_RELATED", 0)
        ai_stats["category_distribution"].setdefault("NON_AI", 0)
        ai_stats["category_distribution"]["AI_RELATED"] += sum(1 for r in results if r.get("is_ai_related"))
        ai_stats["category_distribution"]["NON_AI"] += sum(1 for r in results if not r.get("is_ai_related"))
        # avg confidence
        for r in results:
            c = r.get("confidence")
            try:
                if c is None:
                    continue
                cf = float(c)
                ai_stats["confidence_sum"] += cf
                ai_stats["confidence_count"] += 1
            except Exception:
                continue

        # keyword distributions
        for r in results:
            hits = r.get("keyword_hits") or []
            attacks = r.get("attack_hits") or []
            if isinstance(hits, str):
                hits = [hits]
            if isinstance(attacks, str):
                attacks = [attacks]
            for kw in hits:
                try:
                    k = str(kw).strip().lower()
                    if not k:
                        continue
                    ai_stats["keyword_distribution"][k] = int(ai_stats["keyword_distribution"].get(k, 0)) + 1
                except Exception:
                    continue
            for kw in attacks:
                try:
                    k = str(kw).strip().lower()
                    if not k:
                        continue
                    ai_stats["attack_distribution"][k] = int(ai_stats["attack_distribution"].get(k, 0)) + 1
                except Exception:
                    continue
        ai_stats["last_updated"] = _now_iso()


@app.route("/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "healthy" if model and vectorizer else "unhealthy",
            "model_loaded": model is not None,
            "vectorizer_loaded": vectorizer is not None,
            "training_endpoints": True,
        }
    )


def _analyze_single(payload: Dict[str, Any]) -> Dict[str, Any]:
    title = payload.get("title", "") or ""
    description = payload.get("description", "") or ""
    cve_id = payload.get("cve_id", "") or ""
    text = f"{title} {description}".strip()

    if not text:
        return {"success": False, "error": "Требуется title или description", "cve_id": cve_id}
    if not model or not vectorizer:
        return {"success": False, "error": "Модели не загружены", "cve_id": cve_id}

    text_vector = vectorizer.transform([text])

    # ML score (probability of class=1 if available)
    ml_score = 0.5
    pred = model.predict(text_vector)[0]
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(text_vector)[0]
        try:
            ml_score = float(proba[1])
        except Exception:
            ml_score = float(max(proba))
    elif hasattr(model, "decision_function"):
        # sigmoid(decision) as approximation
        try:
            dec = float(model.decision_function(text_vector)[0])
            ml_score = 1.0 / (1.0 + np.exp(-dec))
        except Exception:
            ml_score = 0.5

    ctx = _keyword_context_score(text)
    ctx_score = float(ctx["score"])

    # Combine ML + context (context is critical for "AI vulnerabilities")
    combined = 0.7 * ml_score + 0.3 * ctx_score
    # Если явно найдены AI-специфичные атаки (prompt injection, poisoning, extraction) — считаем AI-related даже при слабом ML скоре
    has_strong_ai_attack = bool(ctx.get("attack_hits")) and ctx_score >= 0.55
    is_ai_related = bool(has_strong_ai_attack or (combined >= 0.55 and (ctx_score >= 0.15 or ml_score >= 0.65)))

    reasoning_parts = []
    if ctx["hits"]:
        reasoning_parts.append(f"AI-контекст: {', '.join(ctx['hits'][:8])}")
    if ctx.get("attack_hits"):
        reasoning_parts.append(f"AI-атаки: {', '.join(ctx['attack_hits'][:6])}")
    if ctx["neg_hits"]:
        reasoning_parts.append(f"обычные классы: {', '.join(ctx['neg_hits'][:6])}")
    reasoning = " | ".join(reasoning_parts) if reasoning_parts else "контекстных признаков мало"

    return {
        "success": True,
        "is_ai_related": is_ai_related,
        "confidence": float(combined),
        "ml_score": float(ml_score),
        "ai_context_score": float(ctx_score),
        "keyword_hits": ctx["hits"],
        "negative_hits": ctx["neg_hits"],
        "reasoning": reasoning,
        "cve_id": cve_id,
        "prediction": int(pred),
    }


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    try:
        data = request.get_json(force=True, silent=True) or {}
        res = _analyze_single(data)
        code = 200 if res.get("success") else 400
        return jsonify(res), code
    except Exception as e:
        logger.error(f"Общая ошибка анализа: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/batch-analyze", methods=["POST"])
def api_batch_analyze():
    try:
        data = request.get_json(force=True, silent=True)
        # Совместимость: некоторые клиенты (FastAPI стиль) могут прислать list[str] вместо dict
        if isinstance(data, list):
            return jsonify(
                {
                    "success": False,
                    "error": "Invalid payload for Flask AI service. Expected {vulnerabilities:[{cve_id,title,description},...]}",
                    "hint": "Use POST /api/batch-analyze with JSON object containing vulnerabilities.",
                }
            ), 400
        data = data or {}
        vulnerabilities = (data.get("vulnerabilities") or []) if isinstance(data, dict) else []

        if not vulnerabilities:
            return jsonify({"success": False, "error": "Требуется список vulnerabilities"}), 400
        if not model or not vectorizer:
            return jsonify({"success": False, "error": "Модели не загружены"}), 503

        texts: List[str] = []
        for v in vulnerabilities:
            title = (v.get("title", "") or "")
            description = (v.get("description", "") or "")
            texts.append(f"{title} {description}".strip())

        text_vectors = vectorizer.transform(texts)
        predictions = model.predict(text_vectors)
        probas = model.predict_proba(text_vectors) if hasattr(model, "predict_proba") else None

        results: List[Dict[str, Any]] = []
        for i, v in enumerate(vulnerabilities):
            pred = predictions[i]
            cve_id = (v.get("cve_id") or "").strip()
            title = (v.get("title", "") or "")
            description = (v.get("description", "") or "")
            text = f"{title} {description}".strip()

            ml_score = 0.5
            if probas is not None:
                try:
                    ml_score = float(probas[i][1])
                except Exception:
                    ml_score = float(max(probas[i]))

            ctx = _keyword_context_score(text)
            ctx_score = float(ctx["score"])
            combined = 0.7 * ml_score + 0.3 * ctx_score
            is_ai_related = bool(combined >= 0.55 and (ctx_score >= 0.15 or ml_score >= 0.65))

            reasoning_parts = []
            if ctx.get("hits"):
                reasoning_parts.append(f"AI-контекст: {', '.join(ctx['hits'][:8])}")
            if ctx.get("attack_hits"):
                reasoning_parts.append(f"AI-атаки: {', '.join(ctx['attack_hits'][:6])}")
            if ctx.get("neg_hits"):
                reasoning_parts.append(f"обычные классы: {', '.join(ctx['neg_hits'][:6])}")
            reasoning = " | ".join(reasoning_parts) if reasoning_parts else "контекстных признаков мало"

            results.append(
                {
                    "cve_id": cve_id,
                    "is_ai_related": is_ai_related,
                    "confidence": float(combined),
                    "ml_score": float(ml_score),
                    "ai_context_score": float(ctx_score),
                    "keyword_hits": ctx["hits"],
                    "attack_hits": ctx.get("attack_hits", []),
                    "negative_hits": ctx["neg_hits"],
                    "prediction": int(pred),
                    "reasoning": reasoning,
                }
            )

        _update_stats(results)
        return jsonify({"success": True, "results": results, "total": len(results)})
    except Exception as e:
        logger.error(f"Общая ошибка пакетного анализа: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/passport", methods=["POST"])
def api_passport():
    """
    Generate an AI-assisted passport for a vulnerability (no external LLM; uses model + context rules).
    Input: {cve_id,title,description,cvss_score,epss_score,source,...}
    Output: structured JSON passport.
    """
    try:
        data = request.get_json(force=True, silent=True) or {}
        cve_id = (data.get("cve_id") or "").strip() or "UNKNOWN"
        title = (data.get("title") or "").strip()
        description = (data.get("description") or "").strip()
        cvss = data.get("cvss_score")
        epss = data.get("epss_score")

        analysis = _analyze_single({"cve_id": cve_id, "title": title, "description": description})
        if not analysis.get("success"):
            return jsonify({"success": False, "error": analysis.get("error", "analysis failed")}), 400

        # Build passport from real fields + classification outputs
        hits = analysis.get("keyword_hits") or []
        neg = analysis.get("negative_hits") or []
        is_ai = bool(analysis.get("is_ai_related"))

        mitigations = []
        t = f"{title} {description}".lower()
        if "prompt injection" in t or "jailbreak" in t:
            mitigations += [
                "Ввести строгую валидацию/санацию промптов и системных инструкций",
                "Разделить системные/пользовательские инструкции, запретить выполнение команд из контента",
                "Добавить контент‑фильтрацию и политики безопасности для инструментов/агентов",
            ]
        if "poison" in t or "data poisoning" in t or "backdoor" in t:
            mitigations += [
                "Контролировать источники и целостность датасетов (hash/подписи, provenance)",
                "Проводить детект аномалий/триггеров в обучающих данных",
                "Разделять пайплайны ingest/train и ограничивать права",
            ]
        if "model extraction" in t or "model stealing" in t:
            mitigations += [
                "Ограничить rate‑limit, добавить мониторинг/детект скрейпинга, watermarking",
                "Скрывать вероятности/логиты (return labels only) где возможно",
            ]
        if not mitigations:
            mitigations = ["Проверить тип уязвимости по описанию и применить стандартные меры (патч/обновление, hardening, контроль доступа)."]

        passport = {
            "success": True,
            "cve_id": cve_id,
            "title": title or cve_id,
            "summary": (description[:600] + "…") if len(description) > 600 else description,
            "ai_related": is_ai,
            "confidence": analysis.get("confidence"),
            "ai_context_score": analysis.get("ai_context_score"),
            "ml_score": analysis.get("ml_score"),
            "reasoning": analysis.get("reasoning"),
            "keywords": hits,
            "negative_signals": neg,
            "cvss_score": cvss,
            "epss_score": epss,
            "recommendations": mitigations,
            "generated_at": _now_iso(),
        }

        return jsonify(passport)
    except Exception as e:
        logger.error(f"passport error: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/security/passports/generate", methods=["POST"])
def passport_alias():
    return api_passport()


# --- Aliases for ml_platform-style endpoints ---

@app.route("/security/ai/analyze", methods=["POST"])
def security_ai_analyze_alias():
    # Accept same payload as /api/analyze
    return api_analyze()


@app.route("/security/ai/batch-analyze", methods=["POST"])
def security_ai_batch_alias():
    # Accept same payload as /api/batch-analyze
    return api_batch_analyze()


@app.route("/security/ai/stats", methods=["GET"])
def security_ai_stats():
    with stats_lock:
        cnt = int(ai_stats.get("confidence_count", 0) or 0)
        s = float(ai_stats.get("confidence_sum", 0.0) or 0.0)
        avg = (s / cnt) if cnt > 0 else 0.0  # 0..1
        kwd = ai_stats.get("keyword_distribution", {}) or {}
        atk = ai_stats.get("attack_distribution", {}) or {}
        # top lists
        top_keywords = sorted(kwd.items(), key=lambda x: x[1], reverse=True)[:30]
        top_attacks = sorted(atk.items(), key=lambda x: x[1], reverse=True)[:30]
        return jsonify(
            {
                "total_cves": ai_stats.get("total_cves", 0),
                "ai_related_count": ai_stats.get("ai_related_count", 0),
                "category_distribution": ai_stats.get("category_distribution", {}),
                # percent (0..100) for UI
                "avg_confidence": float(avg * 100.0),
                "total_keywords": int(len(kwd)),
                "keyword_distribution": kwd,
                "top_keywords": [{"keyword": k, "count": int(v)} for (k, v) in top_keywords],
                "attack_distribution": atk,
                "top_attacks": [{"keyword": k, "count": int(v)} for (k, v) in top_attacks],
                "last_updated": ai_stats.get("last_updated"),
            }
        )


def _load_training_history() -> List[Dict[str, Any]]:
    try:
        if not os.path.exists(TRAINING_HISTORY_PATH):
            return []
        with open(TRAINING_HISTORY_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        return []
    except Exception:
        return []


def _append_training_history(entry: Dict[str, Any]) -> None:
    try:
        history = _load_training_history()
        history.insert(0, entry)
        # keep last 100
        history = history[:100]
        with open(TRAINING_HISTORY_PATH, "w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"❌ Не удалось сохранить training history: {e}", exc_info=True)


def _train_task(task_id: str, req: Dict[str, Any]) -> None:
    global model, vectorizer
    try:
        with training_lock:
            active_trainings[task_id]["status"] = "running"

        training_data = req.get("training_data") or []
        target_column = req.get("target_column") or "is_ai_related"
        epochs = int(req.get("epochs") or 50)
        batch_size = int(req.get("batch_size") or 256)
        lr = float(req.get("learning_rate") or 0.01)

        # texts + labels
        texts: List[str] = []
        labels: List[int] = []
        for row in training_data:
            title = (row.get("title") or "")
            desc = (row.get("description") or "")
            text = f"{title} {desc}".strip()
            texts.append(text)
            lab = row.get(target_column)
            labels.append(1 if bool(lab) else 0)

        # If labels are degenerate, try weak supervision from keywords
        if len(set(labels)) <= 1:
            kw = ["ai", "ml", "llm", "model", "neural", "training", "pytorch", "tensorflow", "gpt", "bert", "transformer"]
            labels = [1 if any(k in t.lower() for k in kw) else 0 for t in texts]

        # stratify только если в каждом классе >= 2 примеров (иначе sklearn падает)
        def can_stratify(y: List[int]) -> bool:
            try:
                from collections import Counter
                c = Counter(y)
                if len(c) < 2:
                    return False
                return min(c.values()) >= 2
            except Exception:
                return False

        strat1 = labels if can_stratify(labels) else None
        X_train_txt, X_tmp_txt, y_train, y_tmp = train_test_split(
            texts, labels, test_size=0.3, random_state=42, stratify=strat1
        )
        strat2 = y_tmp if can_stratify(y_tmp) else None
        X_val_txt, X_test_txt, y_val, y_test = train_test_split(
            X_tmp_txt, y_tmp, test_size=0.5, random_state=42, stratify=strat2
        )

        vec = _ensure_vectorizer_fitted(X_train_txt)
        X_train = vec.transform(X_train_txt)
        X_val = vec.transform(X_val_txt)
        X_test = vec.transform(X_test_txt)

        # SGDClassifier supports partial_fit over sparse matrices
        clf = SGDClassifier(
            loss="log_loss",
            alpha=1e-5,
            learning_rate="constant",
            eta0=lr,
            random_state=42,
        )

        classes = np.array([0, 1], dtype=int)

        history: List[Dict[str, Any]] = []
        best_val_acc = 0.0

        # mini-batches
        n = X_train.shape[0]
        indices = np.arange(n)

        for epoch in range(1, epochs + 1):
            t0 = time.time()
            np.random.shuffle(indices)
            # partial_fit in chunks
            for start in range(0, n, batch_size):
                end = min(start + batch_size, n)
                batch_idx = indices[start:end]
                Xb = X_train[batch_idx]
                yb = np.array([y_train[i] for i in batch_idx], dtype=int)
                if epoch == 1 and start == 0:
                    clf.partial_fit(Xb, yb, classes=classes)
                else:
                    clf.partial_fit(Xb, yb)

            # metrics
            train_proba = clf.predict_proba(X_train)
            val_proba = clf.predict_proba(X_val)
            train_loss = float(log_loss(y_train, train_proba))
            val_loss = float(log_loss(y_val, val_proba))
            train_pred = (train_proba[:, 1] >= 0.5).astype(int)
            val_pred = (val_proba[:, 1] >= 0.5).astype(int)
            train_acc = float(accuracy_score(y_train, train_pred))
            val_acc = float(accuracy_score(y_val, val_pred))
            best_val_acc = max(best_val_acc, val_acc)

            entry = {
                "epoch": epoch,
                "train_loss": train_loss,
                "val_loss": val_loss,
                "train_accuracy": train_acc,
                "val_accuracy": val_acc,
                "duration_sec": round(time.time() - t0, 3),
            }
            history.append(entry)

            with training_lock:
                active_trainings[task_id]["progress"] = {
                    "history": history[-200:],  # cap
                    "epoch": epoch,
                    "current_epoch": epoch,
                    "total_epochs": epochs,
                    "train_loss": train_loss,
                    "val_loss": val_loss,
                    "train_accuracy": train_acc,
                    "val_accuracy": val_acc,
                    # legacy field used by UI for the big accuracy number
                    "accuracy": val_acc,
                    "best_accuracy": best_val_acc,
                }

        # final test metrics
        test_proba = clf.predict_proba(X_test)
        test_pred = (test_proba[:, 1] >= 0.5).astype(int)
        test_acc = float(accuracy_score(y_test, test_pred))
        test_loss = float(log_loss(y_test, test_proba))

        final_metrics = {
            "train_loss": history[-1]["train_loss"] if history else None,
            "val_loss": history[-1]["val_loss"] if history else None,
            "accuracy": history[-1]["val_accuracy"] if history else None,
            "test_accuracy": test_acc,
            "test_loss": test_loss,
        }

        # persist and swap globals
        _save_artifacts(clf, vec)
        model = clf
        vectorizer = vec

        with training_lock:
            active_trainings[task_id]["status"] = "completed"
            active_trainings[task_id]["end_time"] = _now_iso()
            active_trainings[task_id]["progress"] = (active_trainings[task_id].get("progress") or {})
            active_trainings[task_id]["progress"]["final_metrics"] = final_metrics

        _append_training_history(
            {
                "task_id": task_id,
                "status": "completed",
                "start_time": active_trainings[task_id].get("start_time"),
                "end_time": active_trainings[task_id].get("end_time"),
                "best_accuracy": best_val_acc,
                "final_metrics": final_metrics,
                # для графиков в UI (не хранить бесконечно)
                "history": history[-200:],
            }
        )
        logger.info(f"✅ Training completed task_id={task_id} best_val_acc={best_val_acc:.4f} test_acc={test_acc:.4f}")
    except Exception as e:
        logger.error(f"❌ Training failed task_id={task_id}: {e}", exc_info=True)
        with training_lock:
            active_trainings[task_id]["status"] = "failed"
            active_trainings[task_id]["error"] = str(e)
            active_trainings[task_id]["end_time"] = _now_iso()
        _append_training_history(
            {
                "task_id": task_id,
                "status": "failed",
                "start_time": active_trainings.get(task_id, {}).get("start_time"),
                "end_time": _now_iso(),
                "error": str(e),
                "history": (active_trainings.get(task_id, {}).get("progress") or {}).get("history", [])[-200:],
            }
        )


@app.route("/training/start", methods=["POST"])
def training_start():
    """
    Совместимый эндпоинт с ml_platform/api/server.py.
    Ожидает JSON:
    - training_data: list[dict]
    - target_column: str (default is_ai_related)
    - epochs/batch_size/learning_rate
    """
    try:
        req = request.get_json(force=True, silent=True) or {}
        training_data = req.get("training_data") or []
        if not training_data:
            return jsonify({"error": "training_data required"}), 400

        task_id = str(uuid.uuid4())
        with training_lock:
            active_trainings[task_id] = {
                "task_id": task_id,
                "status": "pending",
                "start_time": _now_iso(),
                "progress": None,
                "error": None,
                "request": {
                    "epochs": req.get("epochs"),
                    "batch_size": req.get("batch_size"),
                    "learning_rate": req.get("learning_rate"),
                    "target_column": req.get("target_column"),
                    "samples": len(training_data),
                },
            }

        t = threading.Thread(target=_train_task, args=(task_id, req), daemon=True)
        t.start()

        return jsonify({"task_id": task_id, "status": "pending"})
    except Exception as e:
        logger.error(f"❌ Ошибка запуска обучения: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/training/status/<task_id>", methods=["GET"])
def training_status(task_id: str):
    with training_lock:
        status = active_trainings.get(task_id)
        if not status:
            return jsonify({"task_id": task_id, "status": "unknown"}), 404
        return jsonify(
            {
                "task_id": task_id,
                "status": status.get("status"),
                "progress": status.get("progress"),
                "error": status.get("error"),
            }
        )


@app.route("/training/history", methods=["GET"])
def training_history():
    return jsonify(_load_training_history())


def main() -> int:
    logger.info("🚀 Запуск AI Service Server...")
    ok = load_models()
    if not ok:
        logger.error("❌ Не удалось загрузить модели. Сервер не запущен.")
        return 1
    logger.info("✅ Модели загружены. Запуск Flask сервера...")
    logger.info("📡 API доступен на http://0.0.0.0:8000")
    app.run(host="0.0.0.0", port=8000, debug=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


