import torch
import wandb
import os
from pathlib import Path
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    TrainingArguments,
    Trainer,
    BitsAndBytesConfig,
    DataCollatorForLanguageModeling
)
from peft import (
    LoraConfig,
    get_peft_model,
    prepare_model_for_kbit_training,
    TaskType
)
from datasets import load_dataset
from accelerate import Accelerator
import yaml
from tqdm import tqdm
import numpy as np
from typing import Dict, Any, Optional
import json


class OSINTTrainer:
    """
    Класс для обучения OSINT-специализированной нейросети
    Использует LoRA для эффективного fine-tuning
    """

    def __init__(self, config_path: str = "configs/training_config.yaml"):
        self.config = self.load_config(config_path)
        self.accelerator = Accelerator()

        # Инициализация WandB
        if self.config.get('wandb', {}).get('enabled', True):
            wandb.init(
                project=self.config['wandb']['project_name'],
                config=self.config,
                name=self.config['wandb']['run_name']
            )

        # Создание директорий для моделей
        self.model_dir = Path(self.config['paths']['model_dir'])
        self.checkpoint_dir = Path(self.config['paths']['checkpoint_dir'])
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        self.setup_device()
        self.load_tokenizer()
        self.prepare_dataset()
        self.load_model()
        self.setup_training_args()

    def load_config(self, config_path: str) -> Dict[str, Any]:
        """Загрузка конфигурации из YAML файла"""
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)

    def setup_device(self):
        """Настройка устройства для обучения"""
        if torch.cuda.is_available():
            self.device = torch.device("cuda")
            self.device_map = "auto"
            print(f"Используется GPU: {torch.cuda.get_device_name(0)}")
        else:
            self.device = torch.device("cpu")
            self.device_map = None
            print("GPU не доступен, используется CPU")

    def load_tokenizer(self):
        """Загрузка токенизатора"""
        print(f"Загрузка токенизатора: {self.config['model']['base_model']}")
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.config['model']['base_model'],
            trust_remote_code=True
        )

        # Добавление специальных токенов для OSINT
        special_tokens = {
            'additional_special_tokens': ['[OSINT]', '[TOOL]', '[CVE]', '[ETHICS]']
        }
        self.tokenizer.add_special_tokens(special_tokens)

        # Установка pad_token
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

    def prepare_dataset(self):
        """Подготовка датасета для обучения"""
        print("Загрузка и подготовка датасета...")

        # Загрузка датасета
        dataset_path = self.config['paths']['dataset_dir']
        self.dataset = load_dataset(
            'json',
            data_files={
                'train': f"{dataset_path}/train.jsonl",
                'validation': f"{dataset_path}/val.jsonl"
            },
            split=None
        )

        print(f"Размер обучающего набора: {len(self.dataset['train'])}")
        print(f"Размер валидационного набора: {len(self.dataset['validation'])}")

        # Форматирование промптов
        def format_prompt(example):
            system_prompt = """Ты — специалист по OSINT (Open Source Intelligence) с глубокими знаниями в области разведки по открытым источникам.

Ваша задача — помогать пользователям в сборе, анализе и верификации информации из общедоступных источников для целей кибербезопасности.

Компетенции:
- Shodan, Censys, Google Dorking для поиска открытой инфраструктуры
- DNS разведка, SSL/TLS анализ, WHOIS lookups
- GitHub разведка, социальные сети, веб-архивы
- Верификация информации и анализ уязвимостей
- Этические и правовые ограничения OSINT разведки"""

            user_prompt = example['question']
            assistant_response = example['answer']

            formatted_prompt = f"""[INST] <<SYS>>
{system_prompt}
<</SYS>>

{user_prompt} [/INST]

{assistant_response}"""

            return {'text': formatted_prompt}

        # Применение форматирования
        self.dataset = self.dataset.map(format_prompt)

        # Токенизация
        def tokenize_function(examples):
            return self.tokenizer(
                examples['text'],
                padding='max_length',
                truncation=True,
                max_length=self.config['training']['max_seq_length'],
                return_tensors='pt'
            )

        self.tokenized_dataset = self.dataset.map(
            tokenize_function,
            batched=True,
            remove_columns=self.dataset['train'].column_names
        )

        print("Датасет успешно подготовлен и токенизирован")

    def load_model(self):
        """Загрузка и настройка модели"""
        print("Загрузка базовой модели...")

        # Конфигурация для квантизации
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=self.config['model']['load_in_4bit'],
            bnb_4bit_quant_type=self.config['model']['bnb_4bit_quant_type'],
            bnb_4bit_compute_dtype=getattr(torch, self.config['model']['bnb_4bit_compute_dtype']),
            bnb_4bit_use_double_quant=self.config['model']['bnb_4bit_use_double_quant'],
        )

        # Загрузка модели
        self.model = AutoModelForCausalLM.from_pretrained(
            self.config['model']['base_model'],
            quantization_config=bnb_config if self.config['model']['use_quantization'] else None,
            device_map=self.device_map,
            trust_remote_code=True,
            use_cache=False
        )

        # Подготовка модели для k-bit обучения
        if self.config['model']['use_quantization']:
            self.model = prepare_model_for_kbit_training(self.model)

        # Настройка LoRA
        if self.config['training']['use_lora']:
            lora_config = LoraConfig(
                r=self.config['lora']['r'],
                lora_alpha=self.config['lora']['lora_alpha'],
                target_modules=self.config['lora']['target_modules'],
                lora_dropout=self.config['lora']['lora_dropout'],
                bias=self.config['lora']['bias'],
                task_type=TaskType.CAUSAL_LM
            )
            self.model = get_peft_model(self.model, lora_config)
            self.model.print_trainable_parameters()

        # Изменение размера эмбеддингов если были добавлены специальные токены
        if len(self.tokenizer) != self.model.config.vocab_size:
            self.model.resize_token_embeddings(len(self.tokenizer))

    def setup_training_args(self):
        """Настройка параметров обучения"""
        self.training_args = TrainingArguments(
            output_dir=str(self.checkpoint_dir),
            num_train_epochs=self.config['training']['num_epochs'],
            per_device_train_batch_size=self.config['training']['per_device_train_batch_size'],
            per_device_eval_batch_size=self.config['training']['per_device_eval_batch_size'],
            gradient_accumulation_steps=self.config['training']['gradient_accumulation_steps'],
            learning_rate=self.config['training']['learning_rate'],
            weight_decay=self.config['training']['weight_decay'],
            warmup_steps=self.config['training']['warmup_steps'],
            logging_steps=self.config['training']['logging_steps'],
            eval_steps=self.config['training']['eval_steps'],
            save_steps=self.config['training']['save_steps'],
            evaluation_strategy="steps",
            save_strategy="steps",
            load_best_model_at_end=True,
            metric_for_best_model="eval_loss",
            greater_is_better=False,
            fp16=self.config['training']['fp16'],
            bf16=self.config['training']['bf16'],
            gradient_checkpointing=self.config['training']['gradient_checkpointing'],
            optim=self.config['training']['optim'],
            lr_scheduler_type=self.config['training']['lr_scheduler_type'],
            report_to=["wandb"] if self.config.get('wandb', {}).get('enabled', True) else ["none"],
            run_name=self.config['wandb']['run_name'] if self.config.get('wandb', {}).get('enabled', True) else None,
            push_to_hub=False,
            max_grad_norm=self.config['training']['max_grad_norm']
        )

        # Data collator
        self.data_collator = DataCollatorForLanguageModeling(
            tokenizer=self.tokenizer,
            mlm=False
        )

    def compute_metrics(self, eval_pred):
        """Вычисление метрик для валидации"""
        logits, labels = eval_pred
        predictions = np.argmax(logits, axis=-1)

        # Вычисление Perplexity
        loss_fct = torch.nn.CrossEntropyLoss()
        logits_tensor = torch.tensor(logits)
        labels_tensor = torch.tensor(labels)

        # Маскирование pad токенов
        attention_mask = (labels_tensor != -100)

        # Вычисление loss
        shift_logits = logits_tensor[..., :-1, :].contiguous()
        shift_labels = labels_tensor[..., 1:].contiguous()
        loss = loss_fct(shift_logits.view(-1, shift_logits.size(-1)), shift_labels.view(-1))

        perplexity = torch.exp(loss).item()

        return {
            "perplexity": perplexity,
            "eval_loss": loss.item()
        }

    def train(self):
        """Запуск обучения модели"""
        print("Начало обучения...")

        trainer = Trainer(
            model=self.model,
            args=self.training_args,
            train_dataset=self.tokenized_dataset['train'],
            eval_dataset=self.tokenized_dataset['validation'],
            data_collator=self.data_collator,
            compute_metrics=self.compute_metrics
        )

        # Обучение
        train_result = trainer.train()

        # Сохранение результатов
        print("Сохранение обученной модели...")
        trainer.save_model(str(self.model_dir))
        self.tokenizer.save_pretrained(str(self.model_dir))

        # Логирование результатов
        metrics = train_result.metrics
        trainer.log_metrics("train", metrics)
        trainer.save_metrics("train", metrics)
        trainer.save_state()

        print("Обучение завершено успешно!")
        return metrics

    def save_final_model(self):
        """Сохранение финальной модели"""
        # Если используется LoRA, объединяем адаптеры с базовой моделью
        if self.config['training']['use_lora']:
            print("Объединение LoRA адаптеров с базовой моделью...")
            self.model = self.model.merge_and_unload()

        # Сохранение модели
        self.model.save_pretrained(str(self.model_dir / "final_model"))
        self.tokenizer.save_pretrained(str(self.model_dir / "final_model"))

        print(f"Финальная модель сохранена в {self.model_dir / 'final_model'}")


def main():
    """Основная функция для запуска обучения"""
    # Загрузка конфигурации по умолчанию если файл не существует
    default_config = {
        'model': {
            'base_model': 'mistralai/Mistral-7B-v0.1',
            'load_in_4bit': True,
            'bnb_4bit_quant_type': 'nf4',
            'bnb_4bit_compute_dtype': 'float16',
            'bnb_4bit_use_double_quant': True,
            'use_quantization': True
        },
        'lora': {
            'r': 8,
            'lora_alpha': 32,
            'target_modules': ['q_proj', 'k_proj', 'v_proj', 'o_proj'],
            'lora_dropout': 0.05,
            'bias': 'none'
        },
        'training': {
            'use_lora': True,
            'num_epochs': 3,
            'per_device_train_batch_size': 2,
            'per_device_eval_batch_size': 2,
            'gradient_accumulation_steps': 4,
            'learning_rate': 2e-4,
            'weight_decay': 0.01,
            'warmup_steps': 200,
            'logging_steps': 50,
            'eval_steps': 200,
            'save_steps': 200,
            'max_seq_length': 2048,
            'fp16': True,
            'bf16': False,
            'gradient_checkpointing': True,
            'optim': 'paged_adamw_32bit',
            'lr_scheduler_type': 'cosine',
            'max_grad_norm': 1.0
        },
        'paths': {
            'dataset_dir': 'data/processed',
            'model_dir': 'models/final_model',
            'checkpoint_dir': 'models/checkpoints'
        },
        'wandb': {
            'enabled': True,
            'project_name': 'osint-neural-network',
            'run_name': 'mistral-7b-osint-v1'
        }
    }

    # Сохранение конфигурации если файл не существует
    config_path = "configs/training_config.yaml"
    Path("configs").mkdir(exist_ok=True)

    if not Path(config_path).exists():
        with open(config_path, 'w') as f:
            yaml.dump(default_config, f)
        print(f"Создан конфигурационный файл: {config_path}")

    # Инициализация и запуск обучения
    trainer = OSINTTrainer(config_path)
    metrics = trainer.train()
    trainer.save_final_model()

    print("Обучение завершено. Метрики:")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
