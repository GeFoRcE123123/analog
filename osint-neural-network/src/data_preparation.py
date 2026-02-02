import json
import random
import pandas as pd
from pathlib import Path
from tqdm import tqdm
import re
from typing import Dict, List, Any
import nltk
from nltk.tokenize import sent_tokenize

nltk.download('punkt')


class OSINTDatasetPreparer:
    """
    Подготовка датасета для OSINT нейросети
    Собирает данные из различных источников и форматирует в нужную структуру
    """

    def __init__(self, output_dir: str = "data/processed"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Категории для балансировки
        self.categories = [
            "shodan_queries", "google_dorking", "dns_enumeration",
            "github_reconnaissance", "social_media_analysis",
            "vulnerability_analysis", "methodology", "ethics_legal"
        ]

    def generate_synthetic_examples(self, num_examples: int = 5000) -> List[Dict]:
        """
        Генерация синтетических примеров для начального обучения
        В реальном проекте заменить на сбор реальных данных
        """
        examples = []
        difficulties = ["beginner", "intermediate", "advanced"]

        for i in range(num_examples):
            category = random.choice(self.categories)
            difficulty = random.choice(difficulties)

            # Генерация примеров в зависимости от категории
            if category == "shodan_queries":
                example = self._generate_shodan_example(i, difficulty)
            elif category == "google_dorking":
                example = self._generate_dorking_example(i, difficulty)
            elif category == "dns_enumeration":
                example = self._generate_dns_example(i, difficulty)
            elif category == "github_reconnaissance":
                example = self._generate_github_example(i, difficulty)
            elif category == "vulnerability_analysis":
                example = self._generate_vuln_example(i, difficulty)
            elif category == "methodology":
                example = self._generate_methodology_example(i, difficulty)
            elif category == "ethics_legal":
                example = self._generate_ethics_example(i, difficulty)
            else:
                example = self._generate_social_media_example(i, difficulty)

            examples.append(example)

        return examples

    def _generate_shodan_example(self, idx: int, difficulty: str) -> Dict:
        """Генерация примеров для Shodan"""
        org_names = ["example.com", "google.com", "microsoft.com", "facebook.com", "twitter.com"]
        org = random.choice(org_names)
        port = random.choice([80, 443, 22, 21, 3389, 8080])

        if difficulty == "beginner":
            question = f"Как найти открытые веб-серверы для {org} с помощью Shodan?"
            answer = f"""Для поиска открытых веб-серверов {org} в Shodan используйте следующий синтаксис:

```
org:"{org}" http.title:""
```

Этот запрос найдет все хосты, принадлежащие {org}, которые имеют веб-сервер (порт 80 или 443) и пустой заголовок страницы.

Для более точного поиска можно добавить фильтр по порту:
```
org:"{org}" port:80
```

Также можно искать по конкретным технологиям:
```
org:"{org}" product:"nginx"
```

Важно: Используйте Shodan только для легальных целей и с разрешения владельца инфраструктуры."""

            examples = [{
                "input": f'org:"{org}" http.title:""',
                "output": "Поиск всех веб-серверов организации",
                "tool": "Shodan"
            }]

        elif difficulty == "intermediate":
            question = f"Как найти уязвимые сервисы {org} с помощью Shodan?"
            answer = f"""Для поиска потенциально уязвимых сервисов {org} в Shodan используйте комбинацию фильтров:

```
org:"{org}" vuln:* 
```

Этот запрос найдет все хосты с известными уязвимостями. Более конкретные примеры:

1. Поиск старых версий Apache:
```
org:"{org}" product:"apache" version:<2.4.50
```

2. Поиск уязвимых SSH серверов:
```
org:"{org}" product:"openssh" version:<8.0
```

3. Поиск Elasticsearch без аутентификации:
```
org:"{org}" product:"elasticsearch" http.title:"Elasticsearch"
```

После нахождения таких сервисов, обязательно проверьте их на наличие конкретных CVE и примите меры к защите."""

            examples = [{
                "input": f'org:"{org}" vuln:*',
                "output": "Поиск хостов с известными уязвимостями",
                "tool": "Shodan"
            }]

        else:  # advanced
            question = f"Как провести комплексную разведку инфраструктуры {org} с помощью Shodan API?"
            answer = f"""Для комплексной разведки {org} через Shodan API следует использовать следующий подход:

```python
import shodan
import json

API_KEY = "your_shodan_api_key"
api = shodan.Shodan(API_KEY)

# 1. Основной поиск по организации
query = f'org:"{org}"'
results = api.search(query)

# 2. Анализ технологий
tech_stats = {}
for result in results['matches']:
    for tech in result.get('products', []):
        tech_name = tech.get('name', '')
        if tech_name:
            tech_stats[tech_name] = tech_stats.get(tech_name, 0) + 1

# 3. Поиск уязвимостей по версиям
vuln_hosts = []
for result in results['matches']:
    for vuln in result.get('vulns', []):
        vuln_hosts.append({
            'ip': result['ip_str'],
            'port': result['port'],
            'vuln_id': vuln,
            'cvss': result['vulns'][vuln].get('cvss', 0)
        })

# 4. Экспорт результатов
with open('shodan_recon.json', 'w') as f:
    json.dump({
        'organization': '{org}',
        'total_hosts': results['total'],
        'technology_stats': tech_stats,
        'vulnerable_hosts': vuln_hosts
    }, f, indent=2)
```

Этот скрипт предоставляет структурированный анализ инфраструктуры с фокусом на безопасности. Всегда соблюдайте законодательство и этические нормы при использовании этих данных."""

            examples = [{
                "input": "Python script for comprehensive Shodan reconnaissance",
                "output": "Full API integration example with vulnerability analysis",
                "tool": "Shodan API"
            }]

        return self._create_standard_example(idx, category, question, answer, examples, difficulty)

    def _generate_dorking_example(self, idx: int, difficulty: str) -> Dict:
        """Генерация примеров для Google Dorking"""
        target = random.choice(["example.com", "corp.local", "intranet.example.com"])
        question = f"Как найти публичные документы организации {target} через Google Dorks?"
        answer = f"""Для поиска публичных документов используйте Google Dorks с фильтрами filetype и site:

```
site:{target} filetype:pdf
site:{target} filetype:doc OR filetype:docx
```

Рекомендуется добавлять точные ключевые слова, например:
```
site:{target} filetype:xlsx "confidential"
```

Важно соблюдать правовые ограничения и не использовать найденные материалы без разрешения."""
        examples = [{
            "input": f"site:{target} filetype:pdf",
            "output": "Поиск PDF документов на целевом домене",
            "tool": "Google"
        }]
        return self._create_standard_example(idx, "google_dorking", question, answer, examples, difficulty)

    def _generate_dns_example(self, idx: int, difficulty: str) -> Dict:
        """Генерация примеров для DNS разведки"""
        domain = random.choice(["example.com", "example.org", "example.net"])
        question = f"Как провести перечисление поддоменов для {domain}?"
        answer = f"""Для DNS разведки можно использовать сочетание пассивных и активных методов:

1. Пассивный поиск (без активного сканирования):
```
dig +short {domain}
```

2. Использование словарей для поддоменов:
```
sublist3r -d {domain}
```

Всегда соблюдайте правила тестируемой инфраструктуры."""
        examples = [{
            "input": f"sublist3r -d {domain}",
            "output": "Поиск поддоменов",
            "tool": "DNS"
        }]
        return self._create_standard_example(idx, "dns_enumeration", question, answer, examples, difficulty)

    def _generate_github_example(self, idx: int, difficulty: str) -> Dict:
        """Генерация примеров для GitHub разведки"""
        org = random.choice(["example", "acme-corp", "sample-org"])
        question = f"Как искать утечки секретов в репозиториях организации {org} на GitHub?"
        answer = f"""Используйте поиск по ключевым словам и шаблонам:

```
org:{org} "API_KEY"
org:{org} "password"
org:{org} filename:.env
```

Также полезны инструменты:
- trufflehog
- gitleaks

Всегда действуйте в рамках разрешений."""
        examples = [{
            "input": f'org:{org} filename:.env',
            "output": "Поиск файлов окружения",
            "tool": "GitHub"
        }]
        return self._create_standard_example(idx, "github_reconnaissance", question, answer, examples, difficulty)

    def _generate_vuln_example(self, idx: int, difficulty: str) -> Dict:
        """Генерация примеров для анализа уязвимостей"""
        cve = random.choice(["CVE-2023-1234", "CVE-2022-9876", "CVE-2021-44228"])
        question = f"Как интерпретировать CVE {cve} и оценить риск?"
        answer = f"""Для оценки CVE используйте:
1. Описание уязвимости (NVD, vendor advisory)
2. CVSS балл и вектор
3. Наличие публичных эксплойтов

Пример: {cve} — проверьте версию ПО, затем оцените необходимость срочного патча."""
        examples = [{
            "input": cve,
            "output": "Поиск информации об уязвимости",
            "tool": "NVD"
        }]
        return self._create_standard_example(idx, "vulnerability_analysis", question, answer, examples, difficulty)

    def _generate_methodology_example(self, idx: int, difficulty: str) -> Dict:
        """Генерация примеров для методологии OSINT"""
        question = "Опиши базовый процесс OSINT-разведки для инфраструктуры."
        answer = """Типовой процесс включает:
1. Определение целей и разрешений
2. Сбор открытых данных
3. Верификация источников
4. Корреляция и анализ
5. Документирование и рекомендации"""
        examples = [{
            "input": "OSINT methodology steps",
            "output": "Пошаговый процесс разведки",
            "tool": "Methodology"
        }]
        return self._create_standard_example(idx, "methodology", question, answer, examples, difficulty)

    def _generate_ethics_example(self, idx: int, difficulty: str) -> Dict:
        """Генерация примеров для этики и права"""
        question = "Какие этические ограничения нужно соблюдать при OSINT?"
        answer = """Ключевые правила:
1. Работать только с разрешенными целями
2. Не превышать полномочия
3. Не публиковать персональные данные
4. Документировать источники и соблюдать закон"""
        examples = [{
            "input": "OSINT ethics",
            "output": "Список этических ограничений",
            "tool": "Ethics"
        }]
        return self._create_standard_example(idx, "ethics_legal", question, answer, examples, difficulty)

    def _generate_social_media_example(self, idx: int, difficulty: str) -> Dict:
        """Генерация примеров для соцсетей"""
        target = random.choice(["Иван Иванов", "John Doe", "Example Person"])
        question = f"Как безопасно собрать публичную информацию о {target}?"
        answer = """Используйте только публичные данные:
- Профили и открытые посты
- Поиск по никнеймам и email (если разрешено)
- Кросс-ссылки на другие ресурсы

Не используйте методы социальной инженерии и не нарушайте приватность."""
        examples = [{
            "input": "Public profile search",
            "output": "Сбор публичных данных",
            "tool": "Social Media"
        }]
        return self._create_standard_example(idx, "social_media_analysis", question, answer, examples, difficulty)

    def _create_standard_example(self, idx: int, category: str, question: str,
                                answer: str, examples: List[Dict], difficulty: str) -> Dict:
        """Создание стандартной структуры примера"""
        return {
            "id": f"osint_{category}_{idx}",
            "category": category,
            "question": question,
            "answer": answer,
            "examples": examples,
            "technical_details": self._generate_technical_details(category, difficulty),
            "sources": ["shodan.io", "osintframework.com", "github.com"],
            "difficulty": difficulty,
            "tags": self._get_tags_for_category(category),
            "created_at": "2024-01-25"
        }

    def _generate_technical_details(self, category: str, difficulty: str) -> str:
        """Генерация технических деталей в зависимости от категории и сложности"""
        details = {
            "shodan_queries": {
                "beginner": "Shodan использует специальный синтаксис запросов для фильтрации результатов по различным параметрам: org, port, product, version, vuln и др.",
                "intermediate": "Shodan API предоставляет доступ к raw данным и позволяет автоматизировать разведку. Важно учитывать rate limits (1 запрос/сек для бесплатного аккаунта).",
                "advanced": "Для эффективного использования Shodan API необходимо реализовать обработку ошибок, pagination и кэширование результатов для снижения количества запросов."
            }
        }

        category_details = details.get(category, {})
        return category_details.get(difficulty, "Технические детали для данной категории")

    def _get_tags_for_category(self, category: str) -> List[str]:
        """Получение тегов для категории"""
        tag_mapping = {
            "shodan_queries": ["shodan", "reconnaissance", "infrastructure", "security"],
            "google_dorking": ["google", "dorking", "search", "data-leakage"],
            "dns_enumeration": ["dns", "subdomain", "enumeration", "network"],
            "github_reconnaissance": ["github", "code", "secrets", "repository"],
            "social_media_analysis": ["social", "osint", "person", "profile"],
            "vulnerability_analysis": ["cve", "vulnerability", "security", "risk"],
            "methodology": ["methodology", "process", "workflow", "best-practices"],
            "ethics_legal": ["ethics", "legal", "compliance", "responsible-disclosure"]
        }
        return tag_mapping.get(category, ["osint", "security"])

    def save_dataset(self, examples: List[Dict], output_file: str):
        """Сохранение датасета в формате JSONL"""
        output_path = self.output_dir / output_file

        with open(output_path, 'w', encoding='utf-8') as f:
            for example in examples:
                f.write(json.dumps(example, ensure_ascii=False) + '\n')

        print(f"Датасет сохранен в {output_path}, всего примеров: {len(examples)}")

    def split_dataset(self, examples: List[Dict], train_ratio: float = 0.8,
                     val_ratio: float = 0.1):
        """Разделение датасета на train/val/test"""
        random.shuffle(examples)

        train_size = int(len(examples) * train_ratio)
        val_size = int(len(examples) * val_ratio)

        train_examples = examples[:train_size]
        val_examples = examples[train_size:train_size + val_size]
        test_examples = examples[train_size + val_size:]

        self.save_dataset(train_examples, "train.jsonl")
        self.save_dataset(val_examples, "val.jsonl")
        self.save_dataset(test_examples, "test.jsonl")

        print(f"Разделение завершено:")
        print(f"Train: {len(train_examples)} примеров")
        print(f"Validation: {len(val_examples)} примеров")
        print(f"Test: {len(test_examples)} примеров")


def main():
    """Основная функция для подготовки данных"""
    preparer = OSINTDatasetPreparer()

    # Генерация синтетических данных (в реальном проекте заменить на сбор реальных данных)
    print("Генерация синтетического датасета...")
    examples = preparer.generate_synthetic_examples(num_examples=10000)

    # Разделение на train/val/test
    print("Разделение датасета...")
    preparer.split_dataset(examples)

    print("Подготовка данных завершена!")


if __name__ == "__main__":
    main()
