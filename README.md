# epollKV

In-memory key-value store с TLS и аутентификацией

## Stack

- **C++17** - основной язык
- **OpenSSL** - TLS шифрование
- **epoll** - асинхронная обработка сетевых соединений
- **Python 3** - тестовый клиент

## Features

- TLS 1.2+ шифрование всех соединений
- SHA256 аутентификация
- SET/GET/DELETE/GETALL операции
- Edge-triggered epoll для высокой производительности
- Буферизация для корректной обработки частичных TCP пакетов

## Setup

```bash
sudo apt install build-essential libssl-dev

make

./redis_server
```

Сервер стартует на порту **8882**. Пароль по умолчанию: `password123`

## Client

```bash
python3 client.py
```

Интерактивный режим поддерживает команды:
- `set key value` - записать
- `get key` - прочитать
- `delete key` - удалить
- `getall` - показать всё
- `quit` - выход

## Protocol

**Request:** `[cmd:1][key_len:1][value_len:4][key][value]`

**Response:** `[status:1][value_len:4][value]`

Commands: `0=AUTH`, `1=SET`, `2=GET`, `3=GETALL`, `4=DELETE`

Status: `0=OK`, `1=NOT_FOUND`, `2=ERROR`, `3=AUTH_REQUIRED`

## Сменить пароль

```bash
echo -n "mypassword" | sha256sum
```

Обновить `PASSWORD_HASH` в `main.cpp`
