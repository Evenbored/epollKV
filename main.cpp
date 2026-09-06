#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>

constexpr uint8_t CMD_AUTH = 0;
constexpr uint8_t CMD_SET = 1;
constexpr uint8_t CMD_GET = 2;
constexpr uint8_t CMD_GETALL = 3;
constexpr uint8_t CMD_DELETE = 4;

constexpr uint8_t RES_OK = 0;
constexpr uint8_t RES_NOT_FOUND = 1;
constexpr uint8_t RES_ERR = 2;
constexpr uint8_t RES_AUTH_REQUIRED = 3;

constexpr int LISTEN_PORT = 8882;
constexpr int LISTEN_BACKLOG = 128;
constexpr int MAX_EVENTS = 1024;
constexpr size_t HEADER_SIZE = 6;
constexpr size_t MAX_BUFFER_SIZE = 1024 * 1024;

std::unordered_map<std::string, std::string> db;

const std::string PASSWORD_HASH = "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f";
struct ClientState {
    SSL* ssl;
    bool authenticated;
    std::vector<uint8_t> read_buffer;
    
    ClientState() : ssl(nullptr), authenticated(false) {}
    ~ClientState() {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    }
};

std::unordered_map<int, std::unique_ptr<ClientState>> clients;

std::string sha256(const std::string& str) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return "";
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, str.c_str(), str.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    EVP_MD_CTX_free(ctx);
    
    char buf[65];
    for (unsigned int i = 0; i < hash_len && i < 32; i++) {
        sprintf(buf + (i * 2), "%02x", hash[i]);
    }
    buf[64] = 0;
    return std::string(buf);
}

SSL_CTX* create_ssl_context() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        std::fprintf(stderr, "Error: Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    return ctx;
}

bool load_certificates(SSL_CTX* ctx, const char* cert_file, const char* key_file) {
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    
    if (!SSL_CTX_check_private_key(ctx)) {
        std::fprintf(stderr, "Error: Private key does not match the certificate\n");
        return false;
    }
    
    return true;
}

void write_uint32_le(uint32_t value, uint8_t* buf) {
    buf[0] = static_cast<uint8_t>(value & 0xFF);
    buf[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    buf[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    buf[3] = static_cast<uint8_t>((value >> 24) & 0xFF);
}

uint32_t read_uint32_le(const uint8_t* buf) {
    return static_cast<uint32_t>(buf[0]) |
           (static_cast<uint32_t>(buf[1]) << 8) |
           (static_cast<uint32_t>(buf[2]) << 16) |
           (static_cast<uint32_t>(buf[3]) << 24);
}

void check_and_raise_fd_limit() {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        std::fprintf(stderr, "Error: Failed to get rlimit: %s\n", strerror(errno));
        return;
    }

    std::fprintf(stdout, "FD Limits - Soft: %lld, Hard: %lld\n",
                 static_cast<long long>(rl.rlim_cur),
                 static_cast<long long>(rl.rlim_max));

    if (rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &rl) == 0) {
            std::fprintf(stdout, "Raised soft FD limit to %lld\n",
                         static_cast<long long>(rl.rlim_cur));
        } else {
            std::fprintf(stderr, "Error: Failed to set rlimit: %s\n", strerror(errno));
        }
    }
}

int create_server_socket() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::fprintf(stderr, "Error: Failed to create socket: %s\n", strerror(errno));
        return -1;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::fprintf(stderr, "Error: Failed to set SO_REUSEADDR: %s\n", strerror(errno));
        close(server_fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(LISTEN_PORT);

    if (bind(server_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::fprintf(stderr, "Error: Failed to bind socket: %s\n", strerror(errno));
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, LISTEN_BACKLOG) < 0) {
        std::fprintf(stderr, "Error: Failed to listen: %s\n", strerror(errno));
        close(server_fd);
        return -1;
    }

    int flags = fcntl(server_fd, F_GETFL, 0);
    if (flags < 0) {
        std::fprintf(stderr, "Error: fcntl F_GETFL failed: %s\n", strerror(errno));
        close(server_fd);
        return -1;
    }
    if (fcntl(server_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        std::fprintf(stderr, "Error: fcntl F_SETFL failed: %s\n", strerror(errno));
        close(server_fd);
        return -1;
    }

    std::fprintf(stdout, "Server socket created and listening on port %d\n", LISTEN_PORT);
    return server_fd;
}

int accept_new_client(int epoll_fd, int server_fd, SSL_CTX* ssl_ctx) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    int client_fd = accept4(server_fd,
                            reinterpret_cast<struct sockaddr*>(&client_addr),
                            &addr_len,
                            SOCK_NONBLOCK | SOCK_CLOEXEC);

    if (client_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return -1;
        }
        std::fprintf(stderr, "Error: accept failed: %s\n", strerror(errno));
        return -1;
    }

    std::fprintf(stdout, "New client connected, fd=%d\n", client_fd);

    SSL* ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        std::fprintf(stderr, "Error: SSL_new failed\n");
        ERR_print_errors_fp(stderr);
        close(client_fd);
        return -1;
    }
    
    SSL_set_fd(ssl, client_fd);
    SSL_set_accept_state(ssl);
    
    auto client_state = std::make_unique<ClientState>();
    client_state->ssl = ssl;
    client_state->authenticated = false;
    clients[client_fd] = std::move(client_state);

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = client_fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
        std::fprintf(stderr, "Error: Failed to add client fd=%d to epoll: %s\n", client_fd, strerror(errno));
        clients.erase(client_fd);
        close(client_fd);
        return -1;
    }

    return client_fd;
}

bool send_response(int client_fd, uint8_t status, const std::string& value) {
    auto it = clients.find(client_fd);
    if (it == clients.end()) {
        std::fprintf(stderr, "Error: Client fd=%d not found\n", client_fd);
        return false;
    }
    
    SSL* ssl = it->second->ssl;
    
    uint8_t header[5];
    header[0] = status;
    write_uint32_le(static_cast<uint32_t>(value.size()), header + 1);

    size_t total_len = 5 + value.size();
    std::vector<uint8_t> buffer(total_len);
    memcpy(buffer.data(), header, 5);
    if (!value.empty()) {
        memcpy(buffer.data() + 5, value.data(), value.size());
    }

    size_t sent = 0;
    while (sent < total_len) {
        int n = SSL_write(ssl, buffer.data() + sent, total_len - sent);
        if (n > 0) {
            sent += static_cast<size_t>(n);
        } else {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                continue;
            }
            std::fprintf(stderr, "Error: SSL_write failed on fd=%d, error=%d\n", client_fd, err);
            ERR_print_errors_fp(stderr);
            return false;
        }
    }

    return true;
}

void execute_command(int client_fd, uint8_t cmd, const std::string& key, const std::string& value) {
    auto it = clients.find(client_fd);
    if (it == clients.end()) {
        return;
    }
    
    std::fprintf(stdout, "Executing command %d, key='%s'\n", cmd, key.c_str());

    if (cmd != CMD_AUTH && !it->second->authenticated) {
        std::fprintf(stdout, "Command %d rejected: not authenticated\n", cmd);
        send_response(client_fd, RES_AUTH_REQUIRED, "");
        return;
    }

    switch (cmd) {
        case CMD_AUTH: {
            std::string password_hash = sha256(value);
            if (password_hash == PASSWORD_HASH) {
                it->second->authenticated = true;
                std::fprintf(stdout, "AUTH: successful for fd=%d\n", client_fd);
                send_response(client_fd, RES_OK, "");
            } else {
                std::fprintf(stdout, "AUTH: failed for fd=%d\n", client_fd);
                send_response(client_fd, RES_ERR, "Invalid password");
            }
            break;
        }
        case CMD_SET: {
            db[key] = value;
            std::fprintf(stdout, "SET: key stored/updated\n");
            send_response(client_fd, RES_OK, "");
            break;
        }
        case CMD_GET: {
            auto db_it = db.find(key);
            if (db_it != db.end()) {
                std::fprintf(stdout, "GET: key found\n");
                send_response(client_fd, RES_OK, db_it->second);
            } else {
                std::fprintf(stdout, "GET: key not found\n");
                send_response(client_fd, RES_NOT_FOUND, "");
            }
            break;
        }
        case CMD_GETALL: {
            std::string result;
            for (const auto& pair : db) {
                result += pair.first + "=" + pair.second + "\n";
            }
            std::fprintf(stdout, "GETALL: returning %zu entries\n", db.size());
            send_response(client_fd, RES_OK, result);
            break;
        }
        case CMD_DELETE: {
            auto db_it = db.find(key);
            if (db_it != db.end()) {
                db.erase(db_it);
                std::fprintf(stdout, "DELETE: key removed\n");
                send_response(client_fd, RES_OK, "");
            } else {
                std::fprintf(stdout, "DELETE: key not found\n");
                send_response(client_fd, RES_NOT_FOUND, "");
            }
            break;
        }
        default: {
            std::fprintf(stdout, "Unknown command %d\n", cmd);
            send_response(client_fd, RES_ERR, "Unknown command");
            break;
        }
    }
}

void close_client(int epoll_fd, int client_fd) {
    std::fprintf(stdout, "Closing client fd=%d\n", client_fd);
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, nullptr);
    clients.erase(client_fd);
    close(client_fd);
}

void handle_client(int epoll_fd, int client_fd) {
    auto it = clients.find(client_fd);
    if (it == clients.end()) {
        std::fprintf(stderr, "Error: Client fd=%d not found\n", client_fd);
        return;
    }
    
    ClientState* state = it->second.get();
    SSL* ssl = state->ssl;
    
    if (!SSL_is_init_finished(ssl)) {
        int ret = SSL_accept(ssl);
        if (ret <= 0) {
            int err = SSL_get_error(ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                return;
            }
            std::fprintf(stderr, "Error: SSL_accept failed on fd=%d, error=%d\n", client_fd, err);
            ERR_print_errors_fp(stderr);
            close_client(epoll_fd, client_fd);
            return;
        }
        std::fprintf(stdout, "SSL handshake completed for fd=%d\n", client_fd);
    }
    
    uint8_t temp_buffer[4096];
    while (true) {
        int n = SSL_read(ssl, temp_buffer, sizeof(temp_buffer));
        if (n > 0) {
            state->read_buffer.insert(state->read_buffer.end(), temp_buffer, temp_buffer + n);
            
            if (state->read_buffer.size() > MAX_BUFFER_SIZE) {
                std::fprintf(stderr, "Error: Buffer overflow on fd=%d\n", client_fd);
                send_response(client_fd, RES_ERR, "Buffer overflow");
                close_client(epoll_fd, client_fd);
                return;
            }
        } else {
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                break;
            } else if (err == SSL_ERROR_ZERO_RETURN) {
                std::fprintf(stdout, "Client fd=%d closed SSL connection\n", client_fd);
                close_client(epoll_fd, client_fd);
                return;
            } else {
                std::fprintf(stderr, "Error: SSL_read failed on fd=%d, error=%d\n", client_fd, err);
                ERR_print_errors_fp(stderr);
                close_client(epoll_fd, client_fd);
                return;
            }
        }
    }
    
    while (state->read_buffer.size() >= HEADER_SIZE) {
        uint8_t cmd = state->read_buffer[0];
        uint8_t key_len = state->read_buffer[1];
        uint32_t value_len = read_uint32_le(&state->read_buffer[2]);
        
        size_t total_msg_size = HEADER_SIZE + key_len + value_len;
        
        if (state->read_buffer.size() < total_msg_size) {
            break;
        }
        
        std::string key;
        std::string value;
        
        if (key_len > 0) {
            key.assign(reinterpret_cast<const char*>(&state->read_buffer[HEADER_SIZE]), key_len);
        }
        
        if (value_len > 0) {
            value.assign(reinterpret_cast<const char*>(&state->read_buffer[HEADER_SIZE + key_len]), value_len);
        }
        
        execute_command(client_fd, cmd, key, value);
        
        state->read_buffer.erase(state->read_buffer.begin(), state->read_buffer.begin() + total_msg_size);
    }
}

int main() {
    std::fprintf(stdout, "=== Secure Redis-like Server Starting ===\n");

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    SSL_CTX* ssl_ctx = create_ssl_context();
    if (!ssl_ctx) {
        std::fprintf(stderr, "FATAL: Failed to create SSL context\n");
        return 1;
    }

    if (!load_certificates(ssl_ctx, "server.crt", "server.key")) {
        std::fprintf(stderr, "FATAL: Failed to load certificates\n");
        std::fprintf(stderr, "Please generate certificates:\n");
        std::fprintf(stderr, "  openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes\n");
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    check_and_raise_fd_limit();

    int server_fd = create_server_socket();
    if (server_fd < 0) {
        std::fprintf(stderr, "FATAL: Failed to create server socket\n");
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        std::fprintf(stderr, "Error: Failed to create epoll: %s\n", strerror(errno));
        close(server_fd);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = server_fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) < 0) {
        std::fprintf(stderr, "Error: Failed to add server fd to epoll: %s\n", strerror(errno));
        close(epoll_fd);
        close(server_fd);
        SSL_CTX_free(ssl_ctx);
        return 1;
    }

    std::fprintf(stdout, "Server started with TLS on port %d\n", LISTEN_PORT);
    std::fprintf(stdout, "Default password: password123\n");
    std::fprintf(stdout, "Waiting for connections...\n");

    struct epoll_event events[MAX_EVENTS];

    while (true) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::fprintf(stderr, "Error: epoll_wait failed: %s\n", strerror(errno));
            break;
        }

        for (int i = 0; i < n; ++i) {
            int fd = events[i].data.fd;
            uint32_t epoll_events = events[i].events;

            if (fd == server_fd) {
                while (true) {
                    int client_fd = accept_new_client(epoll_fd, server_fd, ssl_ctx);
                    if (client_fd < 0) {
                        break;
                    }
                }
            } else {
                if (epoll_events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
                    handle_client(epoll_fd, fd);
                }
            }
        }
    }

    clients.clear();
    close(epoll_fd);
    close(server_fd);
    SSL_CTX_free(ssl_ctx);
    EVP_cleanup();
    std::fprintf(stdout, "Server stopped\n");

    return 0;
}