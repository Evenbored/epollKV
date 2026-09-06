#!/usr/bin/env python3
"""
Клиент для подключения к Redis-подобному серверу с TLS и аутентификацией
"""

import socket
import ssl
import struct
import sys

# Команды
CMD_AUTH = 0
CMD_SET = 1
CMD_GET = 2
CMD_GETALL = 3
CMD_DELETE = 4

# Статусы ответов
RES_OK = 0
RES_NOT_FOUND = 1
RES_ERR = 2
RES_AUTH_REQUIRED = 3

STATUS_NAMES = {
    RES_OK: "OK",
    RES_NOT_FOUND: "NOT FOUND",
    RES_ERR: "ERROR",
    RES_AUTH_REQUIRED: "AUTH REQUIRED"
}


class RedisClient:
    def __init__(self, host='localhost', port=8882):
        self.host = host
        self.port = port
        self.ssl_sock = None
        self.authenticated = False
        
    def connect(self):
        """Подключение к серверу с TLS"""
        try:
            # Создаем обычный сокет
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Создаем SSL контекст (отключаем проверку сертификата для самоподписанных)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Оборачиваем сокет в SSL
            self.ssl_sock = context.wrap_socket(sock, server_hostname=self.host)
            
            # Подключаемся
            self.ssl_sock.connect((self.host, self.port))
            print(f"✓ Подключено к {self.host}:{self.port} через TLS")
            return True
            
        except Exception as e:
            print(f"✗ Ошибка подключения: {e}")
            return False
    
    def disconnect(self):
        """Отключение от сервера"""
        if self.ssl_sock:
            try:
                self.ssl_sock.close()
                print("✓ Отключено от сервера")
            except:
                pass
            self.ssl_sock = None
            self.authenticated = False
    
    def _send_command(self, cmd, key="", value=""):
        """Отправка команды на сервер"""
        if not self.ssl_sock:
            raise Exception("Нет подключения к серверу")
        
        # Подготовка данных
        key_bytes = key.encode('utf-8')
        value_bytes = value.encode('utf-8')
        
        # Формирование заголовка: 1 байт команда + 1 байт длина ключа + 4 байта длина значения
        header = struct.pack('<BBI', cmd, len(key_bytes), len(value_bytes))
        
        # Отправка заголовка + ключа + значения
        message = header + key_bytes + value_bytes
        self.ssl_sock.sendall(message)
    
    def _recv_response(self):
        """Получение ответа от сервера"""
        if not self.ssl_sock:
            raise Exception("Нет подключения к серверу")
        
        # Читаем заголовок ответа: 1 байт статус + 4 байта длина значения
        header = self._recv_exact(5)
        status = header[0]
        value_len = struct.unpack('<I', header[1:5])[0]
        
        # Читаем значение
        value = b""
        if value_len > 0:
            value = self._recv_exact(value_len)
        
        return status, value.decode('utf-8', errors='replace')
    
    def _recv_exact(self, n):
        """Получить точно n байт"""
        data = b""
        while len(data) < n:
            chunk = self.ssl_sock.recv(n - len(data))
            if not chunk:
                raise Exception("Соединение закрыто сервером")
            data += chunk
        return data
    
    def authenticate(self, password):
        """Аутентификация на сервере"""
        try:
            print(f"Аутентификация...")
            self._send_command(CMD_AUTH, value=password)
            status, response = self._recv_response()
            
            if status == RES_OK:
                self.authenticated = True
                print("✓ Аутентификация успешна")
                return True
            else:
                print(f"✗ Аутентификация не удалась: {response}")
                return False
                
        except Exception as e:
            print(f"✗ Ошибка аутентификации: {e}")
            return False
    
    def set(self, key, value):
        """Установить значение ключа"""
        try:
            self._send_command(CMD_SET, key, value)
            status, response = self._recv_response()
            
            print(f"SET '{key}' = '{value}': {STATUS_NAMES.get(status, 'UNKNOWN')}")
            if response:
                print(f"  Ответ: {response}")
            return status == RES_OK
            
        except Exception as e:
            print(f"✗ Ошибка SET: {e}")
            return False
    
    def get(self, key):
        """Получить значение ключа"""
        try:
            self._send_command(CMD_GET, key)
            status, response = self._recv_response()
            
            if status == RES_OK:
                print(f"GET '{key}': {response}")
                return response
            elif status == RES_NOT_FOUND:
                print(f"GET '{key}': ключ не найден")
                return None
            else:
                print(f"GET '{key}': {STATUS_NAMES.get(status, 'UNKNOWN')}")
                if response:
                    print(f"  Ответ: {response}")
                return None
                
        except Exception as e:
            print(f"✗ Ошибка GET: {e}")
            return None
    
    def getall(self):
        """Получить все ключи и значения"""
        try:
            self._send_command(CMD_GETALL)
            status, response = self._recv_response()
            
            if status == RES_OK:
                print("GETALL:")
                if response:
                    for line in response.strip().split('\n'):
                        if line:
                            print(f"  {line}")
                else:
                    print("  (база данных пуста)")
                return response
            else:
                print(f"GETALL: {STATUS_NAMES.get(status, 'UNKNOWN')}")
                if response:
                    print(f"  Ответ: {response}")
                return None
                
        except Exception as e:
            print(f"✗ Ошибка GETALL: {e}")
            return None
    
    def delete(self, key):
        """Удалить ключ"""
        try:
            self._send_command(CMD_DELETE, key)
            status, response = self._recv_response()
            
            if status == RES_OK:
                print(f"DELETE '{key}': удалено")
                return True
            elif status == RES_NOT_FOUND:
                print(f"DELETE '{key}': ключ не найден")
                return False
            else:
                print(f"DELETE '{key}': {STATUS_NAMES.get(status, 'UNKNOWN')}")
                if response:
                    print(f"  Ответ: {response}")
                return False
                
        except Exception as e:
            print(f"✗ Ошибка DELETE: {e}")
            return False


def interactive_mode(client):
    """Интерактивный режим работы с клиентом"""
    print("\n=== Интерактивный режим ===")
    print("Команды:")
    print("  set <key> <value>  - установить значение")
    print("  get <key>          - получить значение")
    print("  getall             - получить все ключи")
    print("  delete <key>       - удалить ключ")
    print("  quit/exit          - выход")
    print()
    
    while True:
        try:
            line = input("> ").strip()
            if not line:
                continue
            
            parts = line.split(maxsplit=2)
            cmd = parts[0].lower()
            
            if cmd in ['quit', 'exit', 'q']:
                break
            elif cmd == 'set' and len(parts) >= 3:
                client.set(parts[1], parts[2])
            elif cmd == 'get' and len(parts) >= 2:
                client.get(parts[1])
            elif cmd == 'getall':
                client.getall()
            elif cmd == 'delete' and len(parts) >= 2:
                client.delete(parts[1])
            else:
                print("✗ Неверная команда. Используйте: set/get/getall/delete/quit")
                
        except KeyboardInterrupt:
            print("\n")
            break
        except EOFError:
            break
        except Exception as e:
            print(f"✗ Ошибка: {e}")


def demo_mode(client):
    """Демонстрационный режим"""
    print("\n=== Демонстрация работы ===\n")
    
    # Установка значений
    print("1. Установка значений:")
    client.set("user:1", "Alice")
    client.set("user:2", "Bob")
    client.set("config:timeout", "30")
    
    print("\n2. Получение значений:")
    client.get("user:1")
    client.get("user:2")
    client.get("user:3")  # Не существует
    
    print("\n3. Получение всех записей:")
    client.getall()
    
    print("\n4. Обновление значения:")
    client.set("user:1", "Alice Smith")
    client.get("user:1")
    
    print("\n5. Удаление записи:")
    client.delete("user:2")
    client.get("user:2")  # Не должно существовать
    
    print("\n6. Финальное состояние базы:")
    client.getall()


def main():
    """Главная функция"""
    print("=== Redis-подобный клиент с TLS ===\n")
    
    # Параметры подключения
    host = input("Хост [localhost]: ").strip() or "localhost"
    port = input("Порт [8882]: ").strip() or "8882"
    port = int(port)
    
    # Создание клиента
    client = RedisClient(host, port)
    
    # Подключение
    if not client.connect():
        return 1
    
    # Аутентификация
    password = input("Пароль [password123]: ").strip() or "password123"
    if not client.authenticate(password):
        client.disconnect()
        return 1
    
    # Выбор режима
    print("\nРежимы работы:")
    print("  1 - Интерактивный режим")
    print("  2 - Демонстрация")
    mode = input("Выберите режим [1]: ").strip() or "1"
    
    try:
        if mode == "2":
            demo_mode(client)
        else:
            interactive_mode(client)
    finally:
        client.disconnect()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
