# Инструкция по развертыванию

Подробная инструкция по развертыванию платформы нейросетевых вычислений на Ubuntu Server.

## Предварительные требования

### Системные требования

- Ubuntu Server 20.04+ или 22.04 LTS
- Python 3.8+
- Минимум 8 GB RAM
- 50 GB свободного места на диске
- GPU с CUDA 12.4+ (опционально, но рекомендуется)

### Установка системных зависимостей

```bash
# Обновление системы
sudo apt update && sudo apt upgrade -y

# Установка Python и инструментов
sudo apt install -y python3 python3-pip python3-venv git build-essential

# Установка системных библиотек для работы с данными
sudo apt install -y libhdf5-dev libnetcdf-dev
```

## Установка CUDA (для GPU)

### 1. Установка NVIDIA драйверов

```bash
# Проверка доступных драйверов
ubuntu-drivers devices

# Автоматическая установка рекомендуемого драйвера
sudo ubuntu-drivers autoinstall

# Перезагрузка
sudo reboot
```

### 2. Проверка установки драйверов

```bash
nvidia-smi
```

### 3. Установка CUDA Toolkit

```bash
# Добавление репозитория NVIDIA
wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt-get update

# Установка CUDA 12.4
sudo apt-get -y install cuda-toolkit-12-4

# Добавление в PATH
echo 'export PATH=/usr/local/cuda/bin:$PATH' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```

### 4. Проверка CUDA

```bash
nvcc --version
```

## Установка платформы

### 1. Клонирование репозитория

```bash
cd /home/user/projects
git clone <repository-url> ml_platform
cd ml_platform
```

### 2. Создание виртуального окружения

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Установка зависимостей

```bash
# Обновление pip
pip install --upgrade pip

# Установка PyTorch (CPU версия)
pip install torch torchvision torchaudio

# Или для GPU (CUDA 12.4)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124

# Установка остальных зависимостей
pip install -r requirements.txt
```

### 4. Проверка установки

```bash
python -c "import torch; print(f'PyTorch: {torch.__version__}'); print(f'CUDA available: {torch.cuda.is_available()}')"
```

## Настройка конфигурации

### 1. Создание директорий

```bash
# Создание директорий для моделей, данных и логов
sudo mkdir -p /home/user/projects/models
sudo mkdir -p /home/user/projects/data
sudo mkdir -p /var/log/ml_platform

# Установка прав
sudo chown -R $USER:$USER /home/user/projects
sudo chown -R $USER:$USER /var/log/ml_platform
```

### 2. Настройка конфигурационного файла

```bash
cp ml_platform/config/config.yaml ml_platform/config/config.local.yaml
nano ml_platform/config/config.local.yaml
```

Отредактируйте пути и параметры под вашу систему.

## Настройка systemd service (опционально)

### 1. Создание systemd unit файла

```bash
sudo nano /etc/systemd/system/ml-platform.service
```

Содержимое:

```ini
[Unit]
Description=ML Platform API Server
After=network.target

[Service]
Type=simple
User=user
WorkingDirectory=/home/user/projects/ml_platform
Environment="PATH=/home/user/projects/ml_platform/venv/bin"
ExecStart=/home/user/projects/ml_platform/venv/bin/python -m ml_platform.api.server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 2. Запуск сервиса

```bash
sudo systemctl daemon-reload
sudo systemctl enable ml-platform
sudo systemctl start ml-platform
sudo systemctl status ml-platform
```

### 3. Просмотр логов

```bash
sudo journalctl -u ml-platform -f
```

## Настройка Jupyter Lab

### 1. Установка Jupyter Lab

```bash
pip install jupyterlab==4.1.5
```

### 2. Настройка Jupyter Lab

```bash
# Генерация конфигурации
jupyter lab --generate-config

# Создание пароля
jupyter lab password

# Настройка конфигурации
nano ~/.jupyter/jupyter_lab_config.py
```

Добавьте:

```python
c.ServerApp.ip = '0.0.0.0'
c.ServerApp.port = 8888
c.ServerApp.open_browser = False
c.ServerApp.allow_root = False
```

### 3. Запуск Jupyter Lab

```bash
# Через systemd
sudo nano /etc/systemd/system/jupyter-lab.service
```

```ini
[Unit]
Description=Jupyter Lab
After=network.target

[Service]
Type=simple
User=user
WorkingDirectory=/home/user/projects
Environment="PATH=/home/user/projects/ml_platform/venv/bin"
ExecStart=/home/user/projects/ml_platform/venv/bin/jupyter lab
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable jupyter-lab
sudo systemctl start jupyter-lab
```

## Настройка Prometheus (опционально)

### 1. Установка Prometheus

```bash
wget https://github.com/prometheus/prometheus/releases/download/v2.48.0/prometheus-2.48.0.linux-amd64.tar.gz
tar xvfz prometheus-*.tar.gz
sudo mv prometheus-2.48.0.linux-amd64 /opt/prometheus
```

### 2. Настройка конфигурации

```bash
sudo nano /opt/prometheus/prometheus.yml
```

Добавьте:

```yaml
scrape_configs:
  - job_name: 'ml-platform'
    scrape_interval: 15s
    static_configs:
      - targets: ['localhost:8000']
```

### 3. Запуск Prometheus

```bash
sudo /opt/prometheus/prometheus --config.file=/opt/prometheus/prometheus.yml
```

## Проверка развертывания

### 1. Проверка API

```bash
curl http://localhost:8000/health
curl http://localhost:8000/gpu/status
```

### 2. Проверка метрик

```bash
curl http://localhost:8000/metrics
```

### 3. Тестовый запуск обучения

```bash
cd ml_platform
python examples/training_script.py
```

## Безопасность

### 1. Firewall

```bash
# Разрешение доступа к API
sudo ufw allow 8000/tcp
sudo ufw allow 8888/tcp  # Jupyter Lab
sudo ufw enable
```

### 2. SSL/TLS (для production)

Рекомендуется использовать nginx как reverse proxy с SSL:

```bash
sudo apt install nginx certbot python3-certbot-nginx
```

Настройте nginx для проксирования запросов к API.

## Мониторинг и обслуживание

### Логи

- API логи: `/var/log/ml_platform/training.log`
- Systemd журнал: `journalctl -u ml-platform`
- Jupyter логи: `journalctl -u jupyter-lab`

### Резервное копирование

Настройте регулярное резервное копирование:
- Модели: `/home/user/projects/models`
- Конфигурация: `ml_platform/config/`
- Данные: `/home/user/projects/data`

### Обновление

```bash
cd /home/user/projects/ml_platform
source venv/bin/activate
git pull
pip install -r requirements.txt --upgrade
sudo systemctl restart ml-platform
```

## Устранение неполадок

### Проблемы с GPU

```bash
# Проверка драйверов
nvidia-smi

# Проверка CUDA
nvcc --version

# Проверка PyTorch
python -c "import torch; print(torch.cuda.is_available())"
```

### Проблемы с памятью

- Уменьшите batch_size в конфигурации
- Используйте gradient accumulation
- Очистите кэш GPU: `python -c "import torch; torch.cuda.empty_cache()"`

### Проблемы с данными

- Проверьте формат файла
- Убедитесь в правильности путей
- Проверьте права доступа к файлам

## Поддержка

При возникновении проблем:
1. Проверьте логи
2. Убедитесь в правильности конфигурации
3. Проверьте системные требования
4. Создайте issue в репозитории проекта
