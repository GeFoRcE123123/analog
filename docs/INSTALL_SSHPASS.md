# Установка sshpass на macOS

## Вариант 1: Через Homebrew (рекомендуется)

```bash
brew install hudochenkov/sshpass/sshpass
```

## Вариант 2: Настройка SSH ключей (без паролей)

Если не хотите устанавливать sshpass, можно настроить SSH ключи:

```bash
# Генерация SSH ключа (если еще нет)
ssh-keygen -t rsa -b 4096

# Копирование ключа на каждую VM
ssh-copy-id user@10.0.88.10
ssh-copy-id user@10.0.88.11
ssh-copy-id user@10.0.88.20
ssh-copy-id user@10.0.88.23
```

После этого скрипт будет работать без sshpass.

## Вариант 3: Использовать expect (альтернатива)

Можно обновить скрипт для использования expect вместо sshpass.

