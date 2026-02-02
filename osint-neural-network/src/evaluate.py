import json
import numpy as np
from pathlib import Path
from datetime import datetime
import sqlite3
from typing import Dict, List, Any, Optional
import wandb


class OSINTEvaluator:
    """
    Комплексная система оценки OSINT модели
    """

    def __init__(self, model_path: str, test_dataset_path: str):
        self.model = self.load_model(model_path)
        self.test_dataset = self.load_dataset(test_dataset_path)
        self.results_dir = Path("results/evaluation")
        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Инициализация WandB для мониторинга
        wandb.init(project="osint-model-evaluation")

    def load_model(self, model_path: str):
        """Загрузка модели для оценки"""
        from src.inference import OSINTInference
        return OSINTInference(model_path=model_path)

    def load_dataset(self, dataset_path: str) -> List[Dict]:
        """Загрузка тестового датасета"""
        with open(dataset_path, 'r') as f:
            return [json.loads(line) for line in f]

    def run_comprehensive_evaluation(self):
        """Запуск комплексной оценки"""
        print("=== Начало комплексной оценки OSINT модели ===")

        # 1. Базовые NLP метрики
        nlp_metrics = self.evaluate_nlp_metrics()

        # 2. Технические метрики
        technical_metrics = self.evaluate_technical_accuracy()

        # 3. Практические тесты
        practical_metrics = self.run_practical_tests()

        # 4. Этическая оценка
        ethical_metrics = self.evaluate_ethical_compliance()

        # 5. Red Team оценка
        red_team_metrics = self.run_red_team_evaluation()

        # Агрегация результатов
        final_results = {
            'timestamp': datetime.now().isoformat(),
            'nlp_metrics': nlp_metrics,
            'technical_metrics': technical_metrics,
            'practical_metrics': practical_metrics,
            'ethical_metrics': ethical_metrics,
            'red_team_metrics': red_team_metrics,
            'overall_score': self.calculate_overall_score(
                nlp_metrics, technical_metrics, practical_metrics,
                ethical_metrics, red_team_metrics
            ),
            'recommendations': self.generate_recommendations(
                nlp_metrics, technical_metrics, practical_metrics
            )
        }

        # Сохранение результатов
        self.save_results(final_results)

        # Логирование в WandB
        wandb.log(final_results)

        print("=== Оценка завершена ===")
        print(f"Общий балл: {final_results['overall_score']:.3f}")

        return final_results

    def calculate_overall_score(self, nlp, technical, practical, ethical, red_team):
        """Расчет общего балла с весами"""
        weights = {
            'technical': 0.35,
            'practical': 0.30,
            'ethical': 0.20,
            'nlp': 0.10,
            'red_team': 0.05
        }

        score = (
            weights['technical'] * technical['accuracy'] +
            weights['practical'] * practical['success_rate'] +
            weights['ethical'] * ethical['compliance_score'] +
            weights['nlp'] * nlp['bleu'] +
            weights['red_team'] * (1 - red_team['attack_effectiveness'])
        )

        return min(1.0, max(0.0, score))

    def save_results(self, results: Dict):
        """Сохранение результатов оценки"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.results_dir / f"evaluation_results_{timestamp}.json"

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        print(f"Результаты сохранены в {output_file}")

        # Также сохраняем в CSV для удобного анализа
        self._save_to_csv(results, timestamp)

    def _save_to_csv(self, results: Dict, timestamp: str):
        """Сохранение ключевых метрик в CSV"""
        import pandas as pd

        metrics_data = {
            'timestamp': [datetime.now().isoformat()],
            'overall_score': [results['overall_score']],
            'technical_accuracy': [results['technical_metrics']['accuracy']],
            'practical_success_rate': [results['practical_metrics']['success_rate']],
            'ethical_compliance': [results['ethical_metrics']['compliance_score']],
            'bleu_score': [results['nlp_metrics']['bleu']],
            'attack_effectiveness': [results['red_team_metrics']['attack_effectiveness']]
        }

        df = pd.DataFrame(metrics_data)
        csv_file = self.results_dir / f"metrics_summary_{timestamp}.csv"
        df.to_csv(csv_file, index=False)

        # Добавление в исторический файл
        history_file = self.results_dir / "evaluation_history.csv"
        if history_file.exists():
            history_df = pd.read_csv(history_file)
            history_df = pd.concat([history_df, df], ignore_index=True)
        else:
            history_df = df

        history_df.to_csv(history_file, index=False)

    def evaluate_nlp_metrics(self) -> Dict[str, float]:
        """Заглушка для базовых NLP метрик"""
        return {'bleu': 0.0, 'rougeL': 0.0, 'meteor': 0.0}

    def evaluate_technical_accuracy(self) -> Dict[str, float]:
        """Заглушка для технических метрик"""
        return {'accuracy': 0.0}

    def run_practical_tests(self) -> Dict[str, float]:
        """Заглушка для практических тестов"""
        return {'success_rate': 0.0}

    def evaluate_ethical_compliance(self) -> Dict[str, float]:
        """Заглушка для этической оценки"""
        return {'compliance_score': 1.0}

    def run_red_team_evaluation(self) -> Dict[str, float]:
        """Заглушка для Red Team оценки"""
        return {'attack_effectiveness': 0.0}

    def generate_recommendations(self, nlp, technical, practical) -> List[str]:
        """Генерация рекомендаций"""
        return [
            "Добавьте реальные эталонные ответы для оценки BLEU/ROUGE.",
            "Подготовьте практические сценарии OSINT для тестирования.",
            "Включите автоматические проверки этических ограничений."
        ]


def generate_evaluation_report(results: Dict[str, Any]):
    """Генерация текстового отчета оценки"""
    report_dir = Path("results/evaluation")
    report_dir.mkdir(parents=True, exist_ok=True)
    report_file = report_dir / "evaluation_report.txt"

    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("ОТЧЕТ ПО ОЦЕНКЕ OSINT МОДЕЛИ\n")
        f.write("=" * 40 + "\n")
        f.write(f"Время: {results.get('timestamp')}\n")
        f.write(f"Общий балл: {results.get('overall_score')}\n")
        f.write(f"NLP метрики: {results.get('nlp_metrics')}\n")
        f.write(f"Технические метрики: {results.get('technical_metrics')}\n")
        f.write(f"Практические метрики: {results.get('practical_metrics')}\n")
        f.write(f"Этические метрики: {results.get('ethical_metrics')}\n")
        f.write(f"Red Team метрики: {results.get('red_team_metrics')}\n")

    print(f"Отчет сохранен в {report_file}")


def main():
    """Основная функция для запуска оценки"""
    evaluator = OSINTEvaluator(
        model_path="models/final_model",
        test_dataset_path="data/processed/test.jsonl"
    )

    results = evaluator.run_comprehensive_evaluation()

    # Генерация отчета
    generate_evaluation_report(results)


if __name__ == "__main__":
    main()
