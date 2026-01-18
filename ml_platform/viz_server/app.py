"""
Flask сервер для 3D force-directed визуализации графа обучения ML платформы
"""

import os
import json
import argparse
import random
import csv
from pathlib import Path
from flask import Flask, render_template, jsonify
from flask_cors import CORS

app = Flask(__name__, 
            template_folder=Path(__file__).parent / 'templates',
            static_folder=Path(__file__).parent / 'static')
# Отключаем кэширование шаблонов для разработки
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
CORS(app)

# Глобальные данные графа
graph_data = None


def load_graph_data():
    """Загрузка данных графа из файла или генерация демо данных"""
    global graph_data
    
    # Попытка загрузить из переменной окружения
    data_file = os.environ.get('GRAPH_DATA_FILE')
    if data_file and Path(data_file).exists():
        with open(data_file, 'r') as f:
            graph_data = json.load(f)
        return
    
    # Генерация демо данных
    graph_data = generate_project_graph_data()


def _safe_stat(path: Path) -> dict:
    try:
        st = path.stat()
        return {
            "path": str(path),
            "size_bytes": int(st.st_size),
            "size_kb": round(st.st_size / 1024, 2),
            "mtime": int(st.st_mtime),
        }
    except Exception:
        return {"path": str(path)}


def _read_text_excerpt(path: Path, max_chars: int = 800) -> str:
    try:
        txt = path.read_text(encoding="utf-8", errors="ignore")
        return txt[:max_chars].strip()
    except Exception:
        return ""


def _summarize_vulnerability_classifier(model_file: Path) -> dict:
    """
    Извлекаем описание архитектуры из исходника без импорта (важно для лёгкого окружения viz_server).
    """
    src = _read_text_excerpt(model_file, max_chars=5000)
    # defaults from file (best-effort, без regex-адa)
    hidden_sizes = [256, 128, 64]
    dropout = 0.3
    num_severity_classes = 5
    num_attack_types = 28
    complexity_classes = 3
    # Признаки (по коду extract_features): 3 + 10 + 3 + 2 + 1 + 4 = 23
    input_features = 23

    return {
        "name": "VulnerabilityClassifier",
        "framework": "PyTorch (nn.Module)",
        "type": "Multi-task MLP",
        "hidden_sizes": hidden_sizes,
        "dropout": dropout,
        "heads": {
            "severity": num_severity_classes,
            "attack_type": num_attack_types,
            "complexity": complexity_classes,
            "cvss_score": "regression",
        },
        "input_features": input_features,
        "features": [
            "CVSS v3 base/exploitability/impact",
            "Popular CWE one-hot (10)",
            "Known exploited, affected_products_count, has_patches",
            "Metadata quality: completeness, freshness",
            "Description length (normalized)",
            "Attack vector one-hot (NETWORK/ADJACENT/LOCAL/PHYSICAL)",
        ],
        "source_file": str(model_file),
        "source_excerpt": src[:900],
    }


def _summarize_training_csv(csv_path: Path) -> dict:
    """
    Парсим краткую сводку по epochs из training_results.csv (MNIST).
    """
    result = {"path": str(csv_path)}
    if not csv_path.exists():
        return result
    try:
        with csv_path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        if not rows:
            return result
        test_acc = [float(r.get("Test_Accuracy", "0") or 0) for r in rows]
        train_acc = [float(r.get("Train_Accuracy", "0") or 0) for r in rows]
        train_loss = [float(r.get("Train_Loss", "0") or 0) for r in rows]
        result.update({
            "epochs": len(rows),
            "final_test_accuracy": test_acc[-1],
            "best_test_accuracy": max(test_acc) if test_acc else None,
            "final_train_accuracy": train_acc[-1] if train_acc else None,
            "final_train_loss": train_loss[-1] if train_loss else None,
        })
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


def _extract_ai_cve_training_facts(notebook_path: Path) -> dict:
    """
    Извлекаем ключевые факты обучения/валидации из ноутбука Untitled_proj.ipynb.
    В ноутбуке используется sklearn, поэтому "эпохи" трактуем как итерации экспериментов (runs):
    - accuracy из classification_report
    - AUC-ROC из вывода
    """
    facts = {"path": str(notebook_path), "runs": []}
    if not notebook_path.exists():
        return facts
    try:
        import re
        text = notebook_path.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()

        auc_re = re.compile(r"AUC-ROC:\s*([0-9.]+)", re.IGNORECASE)
        acc_re = re.compile(r"accuracy\s+([0-9.]+)\s+(\d+)", re.IGNORECASE)

        recent_acc = None
        recent_support = None

        for i, line in enumerate(lines):
            m_acc = acc_re.search(line)
            if m_acc:
                try:
                    recent_acc = float(m_acc.group(1))
                    recent_support = int(m_acc.group(2))
                except Exception:
                    recent_acc = None
                    recent_support = None

            m_auc = auc_re.search(line)
            if m_auc:
                # Каждая печать AUC-ROC трактуется как один "эпохальный" прогон (run) эксперимента.
                try:
                    auc = float(m_auc.group(1))
                except Exception:
                    continue
                run_idx = len(facts["runs"]) + 1
                facts["runs"].append({
                    "epoch": run_idx,
                    "accuracy": recent_acc,
                    "support": recent_support,
                    "auc_roc": auc,
                    "source_line": i + 1,
                })

        # Ограничим до первых 12, чтобы не перегружать граф (но показать несколько прогонов)
        facts["runs"] = facts["runs"][:12]
        return facts
    except Exception as e:
        facts["error"] = str(e)
        return facts


def generate_project_graph_data():
    """
    Граф про реальную ML-платформу/модели из проекта и бэкапа (k8s-worker),
    без "демо эпох развития ИИ".
    """
    root = Path(__file__).resolve().parents[2]  # .../vulnerability_manager
    ml_platform_dir = root / "ml_platform"
    ml_backup_dir = root / "ml_backup"

    model_py = ml_platform_dir / "security" / "ml_models" / "vulnerability_classifier.py"
    training_csv = ml_backup_dir / "training_history" / "mnist_coursework" / "training_results.csv"
    mnist_report = ml_backup_dir / "training_history" / "mnist_coursework" / "report_template.txt"
    viz_report = ml_backup_dir / "training_history" / "mnist_visualization" / "visualization_report.txt"

    # артефакты (модели)
    model_ai_pkl = ml_backup_dir / "models" / "ai_cve_detector.pkl"
    model_tfidf_pkl = ml_backup_dir / "models" / "tfidf_vectorizer.pkl"
    model_mnist_pth = ml_backup_dir / "models" / "mnist_mlp_model.pth"
    dataset_redhat = ml_backup_dir / "data" / "cve_data" / "redhat_cve_365d.json"
    notebook_training = ml_backup_dir / "jupyter_notebooks" / "Untitled_proj.ipynb"

    vuln_cls = _summarize_vulnerability_classifier(model_py)
    mnist_training = _summarize_training_csv(training_csv)
    ai_training = _extract_ai_cve_training_facts(notebook_training)

    nodes = [
        {
            "id": "platform",
            "group": "platform",
            "label": "ML Platform (k8s-worker backup)",
            "description": "Платформа обучения/анализа из проекта + артефакты, сохранённые с VM k8s-worker.",
            "size": 2.4,
            "details": {
                "ml_platform": _safe_stat(ml_platform_dir),
                "ml_backup": _safe_stat(ml_backup_dir),
            },
        },
        {
            "id": "security_module",
            "group": "module",
            "label": "Security Analysis Module",
            "description": "Модуль паспортизации CVE и ML-классификации уязвимостей.",
            "size": 1.9,
            "details": {
                "readme_excerpt": _read_text_excerpt(ml_platform_dir / "README.md", 500),
                "security_doc": _safe_stat(ml_platform_dir / "SECURITY_PLATFORM.md"),
            },
        },
        {
            "id": "vulnerability_classifier",
            "group": "model",
            "label": "VulnerabilityClassifier (PyTorch)",
            "description": "Мультизадачная MLP модель: severity / attack type / complexity + регрессия CVSS.",
            "size": 2.1,
            "details": vuln_cls,
        },
        {
            "id": "feature_pipeline",
            "group": "pipeline",
            "label": "Feature Pipeline (CVEPassport → vector)",
            "description": "Извлечение признаков из паспорта CVE (CVSS/CWE/metadata/attack vector).",
            "size": 1.5,
            "details": {
                "input_features": vuln_cls.get("input_features"),
                "features": vuln_cls.get("features"),
            },
        },
        {
            "id": "dataset_redhat_365d",
            "group": "data",
            "label": "Dataset: Red Hat CVE (365d)",
            "description": "Бэкап данных CVE для обучения/анализа (Red Hat, 365 дней).",
            "size": 1.6,
            "details": _safe_stat(dataset_redhat),
        },
        {
            "id": "artifact_ai_cve_detector",
            "group": "artifact",
            "label": "ai_cve_detector.pkl",
            "description": "Артефакт модели детекции AI-уязвимостей (scikit-learn/pickle).",
            "size": 1.3,
            "details": {
                **_safe_stat(model_ai_pkl),
                "training_facts": ai_training,
            },
        },
        {
            "id": "artifact_tfidf_vectorizer",
            "group": "artifact",
            "label": "tfidf_vectorizer.pkl",
            "description": "TF-IDF векторизатор для текстовых признаков (pickle).",
            "size": 1.2,
            "details": _safe_stat(model_tfidf_pkl),
        },
        {
            "id": "mnist_training_run",
            "group": "training",
            "label": "Training Run: MNIST MLP",
            "description": "Пример обучения (из бэкапа): метрики по эпохам + отчёт.",
            "size": 1.7,
            "details": {
                "metrics": mnist_training,
                "report_excerpt": _read_text_excerpt(mnist_report, 500),
                "viz_excerpt": _read_text_excerpt(viz_report, 400),
            },
        },
        {
            "id": "artifact_mnist_model",
            "group": "artifact",
            "label": "mnist_mlp_model.pth",
            "description": "Сохранённая PyTorch модель (пример).",
            "size": 1.3,
            "details": _safe_stat(model_mnist_pth),
        },
    ]

    # Минимальные связи (ранний этап ИИ, без “лесенок” на сотни рёбер)
    links = [
        {"source": "platform", "target": "security_module", "type": "contains", "value": 1.0},
        {"source": "security_module", "target": "vulnerability_classifier", "type": "uses", "value": 0.9},
        {"source": "vulnerability_classifier", "target": "feature_pipeline", "type": "depends_on", "value": 0.7},
        {"source": "platform", "target": "dataset_redhat_365d", "type": "has_data", "value": 0.6},
        {"source": "platform", "target": "artifact_ai_cve_detector", "type": "has_artifact", "value": 0.4},
        {"source": "platform", "target": "artifact_tfidf_vectorizer", "type": "has_artifact", "value": 0.4},
        {"source": "mnist_training_run", "target": "artifact_mnist_model", "type": "produces", "value": 0.7},
        {"source": "platform", "target": "mnist_training_run", "type": "has_experiment", "value": 0.5},
        {"source": "dataset_redhat_365d", "target": "artifact_tfidf_vectorizer", "type": "feeds", "value": 0.3},
        {"source": "artifact_tfidf_vectorizer", "target": "artifact_ai_cve_detector", "type": "pipeline", "value": 0.3},
    ]

    # Добавим 1..N "эпох" (итераций эксперимента) из Jupyter (основные факты)
    for run in ai_training.get("runs", []) or []:
        run_id = f"ai_detector_epoch_{run.get('epoch')}"
        nodes.append({
            "id": run_id,
            "group": "training",
            "label": f"AI CVE Training — Epoch {run.get('epoch')}",
            "description": "Итерация эксперимента из Jupyter (sklearn).",
            "size": 1.0 + (float(run.get("accuracy") or 0.0) * 0.8),
            "details": run,
        })
        links.append({"source": "artifact_ai_cve_detector", "target": run_id, "type": "has_experiment", "value": 0.35})

    return {"nodes": nodes, "links": links}


@app.route('/')
def index():
    """Главная страница с 3D визуализацией"""
    return render_template('index.html')


@app.route('/data')
def get_graph_data():
    """API endpoint для получения данных графа"""
    if graph_data is None:
        load_graph_data()
    return jsonify(graph_data)


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'nodes': len(graph_data.get('nodes', [])) if graph_data else 0})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='3D Visualization Server for ML Platform')
    parser.add_argument('--port', type=int, default=5001, help='Port to run server on')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')
    
    args = parser.parse_args()
    
    # Загрузка данных
    load_graph_data()
    
    print(f"🚀 Starting 3D Visualization Server on http://{args.host}:{args.port}")
    print(f"📊 Graph data: {len(graph_data.get('nodes', []))} nodes, {len(graph_data.get('links', []))} links")
    
    app.run(host=args.host, port=args.port, debug=args.debug)

