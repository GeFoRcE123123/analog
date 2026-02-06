import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel
from typing import Dict, Any, List
import json
import time
from pathlib import Path


class OSINTInference:
    """
    Класс для инференса OSINT-специализированной нейросети
    """

    def __init__(self, model_path: str = "models/final_model",
                 use_lora: bool = False, base_model: str = "mistralai/Mistral-7B-v0.1"):
        self.model_path = Path(model_path)
        self.use_lora = use_lora
        self.base_model = base_model

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Используется устройство: {self.device}")

        self.load_model()
        self.setup_prompt_template()

    def load_model(self):
        """Загрузка обученной модели"""
        print("Загрузка модели...")

        # Загрузка токенизатора
        self.tokenizer = AutoTokenizer.from_pretrained(
            str(self.model_path) if self.model_path.exists() else self.base_model,
            trust_remote_code=True
        )

        if not self.tokenizer.pad_token:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        # Загрузка модели
        if self.use_lora:
            # Загрузка базовой модели
            base_model = AutoModelForCausalLM.from_pretrained(
                self.base_model,
                device_map="auto",
                trust_remote_code=True
            )

            # Загрузка LoRA адаптеров
            self.model = PeftModel.from_pretrained(
                base_model,
                str(self.model_path)
            )
        else:
            # Загрузка полной модели
            self.model = AutoModelForCausalLM.from_pretrained(
                str(self.model_path) if self.model_path.exists() else self.base_model,
                device_map="auto",
                trust_remote_code=True
            )

        self.model.eval()
        print("Модель успешно загружена")

    def setup_prompt_template(self):
        """Настройка шаблона промпта"""
        self.system_prompt = """Ты — специалист по OSINT (Open Source Intelligence) с глубокими знаниями в области разведки по открытым источникам.

Ваша задача — помогать пользователям в сборе, анализе и верификации информации из общедоступных источников для целей кибербезопасности.

Компетенции:
- Shodan, Censys, Google Dorking для поиска открытой инфраструктуры
- DNS разведка, SSL/TLS анализ, WHOIS lookups
- GitHub разведка, социальные сети, веб-архивы
- Верификация информации и анализ уязвимостей
- Этические и правовые ограничения OSINT разведки

Всегда отвечайте:
1. Структурированно и по делу
2. С конкретными примерами и синтаксисом
3. С указанием инструментов и методов
4. С учетом этических и правовых ограничений
5. С рекомендациями по дальнейшим действиям"""

    def format_prompt(self, user_query: str) -> str:
        """Форматирование промпта для инференса"""
        return f"""[INST] <<SYS>>
{self.system_prompt}
<</SYS>>

{user_query} [/INST]"""

    def generate_response(self, prompt: str, max_length: int = 2048,
                         temperature: float = 0.3, top_p: float = 0.9) -> str:
        """Генерация ответа моделью"""
        inputs = self.tokenizer(
            prompt,
            return_tensors="pt",
            max_length=max_length,
            truncation=True,
            padding=True
        ).to(self.device)

        with torch.no_grad():
            start_time = time.time()

            outputs = self.model.generate(
                **inputs,
                max_new_tokens=max_length,
                temperature=temperature,
                top_p=top_p,
                do_sample=True,
                pad_token_id=self.tokenizer.pad_token_id,
                eos_token_id=self.tokenizer.eos_token_id
            )

            generation_time = time.time() - start_time

        response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)

        # Извлечение только сгенерированной части ответа
        if "[/INST]" in response:
            response = response.split("[/INST]")[-1].strip()

        print(f"Время генерации: {generation_time:.2f} секунд")
        print(f"Длина ответа: {len(response)} символов")

        return response

    def process_osint_query(
        self,
        query: str,
        include_tools: bool = True,
        use_cyberintel: bool = True,
    ) -> Dict[str, Any]:
        """Обработка OSINT запроса с полным анализом"""
        print(f"\n=== Обработка OSINT запроса ===")
        print(f"Запрос: {query}")
        print(f"CyberIntel активирован: {use_cyberintel}")

        # Форматирование промпта
        formatted_prompt = self.format_prompt(query)

        # Генерация ответа
        response = self.generate_response(
            formatted_prompt,
            max_length=2048,
            temperature=0.3,
            top_p=0.9
        )

        # Парсинг ответа
        parsed_response = self.parse_response(response)

        # Добавление информации об инструментах если требуется
        if include_tools:
            parsed_response['tools'] = self.identify_relevant_tools(query, response)

        # Добавление временной метки и метаданных
        parsed_response.update({
            'timestamp': time.time(),
            'query': query,
            'model': str(self.model_path),
            'cyberintel_used': use_cyberintel,
            'processing_time': time.time() - time.time()  # Заменить на реальное время
        })

        return parsed_response

    def parse_response(self, response: str) -> Dict[str, Any]:
        """Парсинг ответа в структурированный формат"""
        # Простой парсинг для демонстрации
        # В реальной реализации можно использовать более сложный парсинг

        sections = {
            'task': '',
            'strategy': [],
            'examples': [],
            'analysis': '',
            'sources': [],
            'limitations': '',
            'raw_response': response
        }

        # Разделение на строки
        lines = response.split('\n')
        current_section = 'task'

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Определение секций
            if line.startswith('## Задача') or line.startswith('# Задача'):
                current_section = 'task'
            elif line.startswith('## Стратегия') or line.startswith('# Стратегия'):
                current_section = 'strategy'
            elif line.startswith('## Примеры') or line.startswith('# Примеры'):
                current_section = 'examples'
            elif line.startswith('## Анализ') or line.startswith('# Анализ'):
                current_section = 'analysis'
            elif line.startswith('## Источники') or line.startswith('# Источники'):
                current_section = 'sources'
            elif line.startswith('## Ограничения') or line.startswith('# Ограничения'):
                current_section = 'limitations'

            # Заполнение секций
            if current_section == 'task' and not line.startswith('## Задача') and not line.startswith('# Задача'):
                sections['task'] += line + ' '
            elif current_section == 'strategy' and line.startswith('1.') or line.startswith('2.') or line.startswith('3.'):
                sections['strategy'].append(line)
            elif current_section == 'examples' and line.startswith('```'):
                sections['examples'].append(line)
            elif current_section == 'analysis' and not line.startswith('## Анализ') and not line.startswith('# Анализ'):
                sections['analysis'] += line + ' '
            elif current_section == 'sources' and line.startswith('-'):
                sections['sources'].append(line[1:].strip())
            elif current_section == 'limitations' and not line.startswith('## Ограничения') and not line.startswith('# Ограничения'):
                sections['limitations'] += line + ' '

        # Очистка
        for key in sections:
            if isinstance(sections[key], str):
                sections[key] = sections[key].strip()

        return sections

    def identify_relevant_tools(self, query: str, response: str) -> List[str]:
        """Идентификация релевантных инструментов для запроса"""
        relevant_tools = []
        tool_keywords = {
            'shodan': ['shodan', 'host search', 'service search', 'vulnerability search'],
            'censys': ['censys', 'certificate search', 'ssl search'],
            'google_dorking': ['google dork', 'site:', 'filetype:', 'intitle:'],
            'nmap': ['nmap', 'port scan', 'service detection', 'os detection'],
            'dns': ['dns', 'whois', 'dig', 'nslookup', 'subdomain'],
            'github': ['github', 'repository', 'code search', 'secret search'],
            'social_media': ['linkedin', 'twitter', 'facebook', 'sherlock'],
            'vulnerability': ['cve', 'vulnerability', 'exploit', 'cve search']
        }

        query_lower = query.lower() + ' ' + response.lower()

        for tool, keywords in tool_keywords.items():
            if any(keyword in query_lower for keyword in keywords):
                relevant_tools.append(tool)

        return list(set(relevant_tools))

    def save_response(self, response_data: Dict[str, Any], output_file: str):
        """Сохранение ответа в файл"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(response_data, f, indent=2, ensure_ascii=False)

        print(f"Ответ сохранен в {output_file}")


def main():
    """Тестовая функция для демонстрации работы"""
    try:
        # Инициализация
        inference = OSINTInference(
            model_path="models/final_model",
            use_lora=True,
            base_model="mistralai/Mistral-7B-v0.1"
        )

        # Тестовые запросы
        test_queries = [
            "Как найти открытые сервисы компании example.com с помощью Shodan?",
            "Проведи OSINT разведку для домена google.com",
            "Как проверить домен на наличие уязвимостей с помощью открытых инструментов?",
            "Какие инструменты использовать для поиска утечек данных в GitHub?",
            "Как провести этичную OSINT разведку сотрудника компании?"
        ]

        for i, query in enumerate(test_queries, 1):
            print(f"\n{'='*60}")
            print(f"Тестовый запрос #{i}: {query}")
            print(f"{'='*60}")

            # Обработка запроса
            result = inference.process_osint_query(query)

            # Вывод результатов
            print("\n=== СТРУКТУРИРОВАННЫЙ ОТВЕТ ===")
            print(f"Задача: {result.get('task', '')[:100]}...")
            print(f"Стратегия: {len(result.get('strategy', []))} шагов")
            print(f"Примеры: {len(result.get('examples', []))} примеров")
            print(f"Релевантные инструменты: {', '.join(result.get('tools', []))}")
            print(f"Ограничения: {result.get('limitations', '')[:100]}...")

            # Сохранение результата
            output_file = f"test_result_{i}.json"
            inference.save_response(result, output_file)

            print(f"\nПолный ответ сохранен в {output_file}")

            if i < len(test_queries):
                print("\nНажмите Enter для продолжения к следующему запросу...")
                input()

        print("\nТестирование завершено успешно!")

    except Exception as e:
        print(f"Ошибка при тестировании: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
