CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS = -lssl -lcrypto

TARGET = redis_server
SOURCES = main.cpp
OBJECTS = $(SOURCES:.cpp=.o)

.PHONY: all clean run certificates

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

certificates:
	@echo "Генерация самоподписанных сертификатов..."
	openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=RU/ST=Moscow/L=Moscow/O=SelfRedis/CN=localhost"
	@echo "✓ Сертификаты созданы: server.crt, server.key"

run: $(TARGET) certificates
	./$(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)
	rm -f server.crt server.key

help:
	@echo "Доступные команды:"
	@echo "  make              - компиляция сервера"
	@echo "  make certificates - генерация SSL сертификатов"
	@echo "  make run          - компиляция и запуск сервера"
	@echo "  make clean        - очистка скомпилированных файлов"
