#include "coordinator.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

// ===================================================================
// I/O HELPERS — do not modify
// ===================================================================

std::string Coordinator::readLine(int fd)
{
    std::string line;
    char c;
    while (true) {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) return "";
        if (c == '\n') return line;
        line += c;
    }
}

void Coordinator::sendResponse(int fd, const std::string& msg)
{
    std::string full = msg + "\n";
    sendRaw(fd, full.c_str(), full.size());
}

std::string Coordinator::readBytes(int fd, size_t n)
{
    std::string buf(n, '\0');
    size_t received = 0;
    while (received < n) {
        ssize_t r = recv(fd, &buf[received], n - received, 0);
        if (r <= 0) { buf.resize(received); return buf; }
        received += static_cast<size_t>(r);
    }
    return buf;
}

void Coordinator::sendRaw(int fd, const char* data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) return;
        sent += static_cast<size_t>(n);
    }
}

std::vector<std::string> Coordinator::tokenize(const std::string& line)
{
    std::vector<std::string> tokens;
    std::istringstream stream(line);
    std::string token;
    while (stream >> token) tokens.push_back(token);
    return tokens;
}

// ===================================================================
// CONSTRUCTOR
// ===================================================================

Coordinator::Coordinator(int port,
                         const std::string& secret,
                         const std::string& sa_host, int sa_port,
                         const std::string& sb_host, int sb_port,
                         const std::string& user_file,
                         int lock_timeout_seconds)
    : port_(port),
      secret_(secret),
      auth_(user_file),
      lock_timeout_s_(lock_timeout_seconds),
      storage_a_(sa_host, sa_port, secret),
      storage_b_(sb_host, sb_port, secret)
{
}

// ===================================================================
// RUN — accept loop, do not modify
// ===================================================================

void Coordinator::run()
{
    if (!storage_a_.connect()) {
        std::cerr << "ERROR: cannot connect to storage-a" << std::endl;
        return;
    }
    if (!storage_b_.connect()) {
        std::cerr << "ERROR: cannot connect to storage-b" << std::endl;
        return;
    }

    std::cout << "Coordinator connected to both storage nodes" << std::endl;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "ERROR: socket() failed: " << strerror(errno) << std::endl;
        return;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(static_cast<uint16_t>(port_));

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "ERROR: bind() failed: " << strerror(errno) << std::endl;
        close(server_fd);
        return;
    }

    if (listen(server_fd, 10) < 0) {
        std::cerr << "ERROR: listen() failed: " << strerror(errno) << std::endl;
        close(server_fd);
        return;
    }

    std::cout << "Coordinator listening on port " << port_ << std::endl;

    while (true) {
        sockaddr_in client_addr{};
        socklen_t   client_len = sizeof(client_addr);
        int client_fd = accept(server_fd,
                               reinterpret_cast<sockaddr*>(&client_addr),
                               &client_len);
        if (client_fd < 0) {
            std::cerr << "WARN: accept() failed: " << strerror(errno) << std::endl;
            continue;
        }
        std::thread(&Coordinator::handleClient, this, client_fd).detach();
    }

    close(server_fd);
}

// ===================================================================
// CLIENT HANDLER
// ===================================================================

void Coordinator::handleClient(int client_fd)
{
    bool        authenticated = false;
    std::string username;

    while (true) {
        std::string line = readLine(client_fd);
        if (line.empty()) break;

        auto tokens = tokenize(line);
        if (tokens.empty()) continue;

        const std::string& cmd = tokens[0];

        // ── LOGIN ────────────────────────────────────────────────
        if (cmd == "LOGIN") {
            if (tokens.size() < 3) {
                sendResponse(client_fd, "ERR_BAD_REQUEST");
                continue;
            }
            if (auth_.authenticate(tokens[1], tokens[2])) {
                authenticated = true;
                username      = tokens[1];
                sendResponse(client_fd, "OK");
            } else {
                sendResponse(client_fd, "ERR_AUTH_FAILED");
            }
            continue;
        }

        if (cmd == "LOGOUT") {
            authenticated = false;
            username.clear();
            sendResponse(client_fd, "OK");
            continue;
        }

        if (!authenticated) {
            sendResponse(client_fd, "ERR_NOT_AUTHENTICATED");
            continue;
        }

        // ── WRITE ────────────────────────────────────────────────
        // Syntax: WRITE <path> <byte_count> <perms>
        if (cmd == "WRITE") {
            if (tokens.size() < 4) {
                sendResponse(client_fd, "ERR_BAD_REQUEST");
                continue;
            }
            const std::string& path = tokens[1];
            size_t   byte_count     = std::stoull(tokens[2]);
            uint16_t perms          = static_cast<uint16_t>(
                                          std::stoul(tokens[3]));
            std::string body        = readBytes(client_fd, byte_count);

            if (!acquireWriteLock(path)) {
                sendResponse(client_fd, "ERR_LOCK_TIMEOUT");
                continue;
            }

            AckResult ra = storage_a_.write(path, body, username, perms);
            AckResult rb = storage_b_.write(path, body, username, perms);

            releaseWriteLock(path);

            if (ra.success && rb.success)
                sendResponse(client_fd, "OK");
            else
                sendResponse(client_fd, "ERR_STORAGE_FAILURE");
            continue;
        }

        // ── DELETE ───────────────────────────────────────────────
        // Syntax: DELETE <path>
        if (cmd == "DELETE") {
            if (tokens.size() < 2) {
                sendResponse(client_fd, "ERR_BAD_REQUEST");
                continue;
            }
            const std::string& path = tokens[1];

            if (!acquireWriteLock(path)) {
                sendResponse(client_fd, "ERR_LOCK_TIMEOUT");
                continue;
            }

            AckResult ra = storage_a_.remove(path);
            AckResult rb = storage_b_.remove(path);

            releaseWriteLock(path);

            if (ra.success && rb.success)
                sendResponse(client_fd, "OK");
            else
                sendResponse(client_fd, "ERR_STORAGE_FAILURE");
            continue;
        }

        // ── READ ─────────────────────────────────────────────────
        // Syntax: READ <path>
        // Response: "OK <byte_count>\n" then raw bytes
        if (cmd == "READ") {
            if (tokens.size() < 2) {
                sendResponse(client_fd, "ERR_BAD_REQUEST");
                continue;
            }
            std::string data;
            AckResult r = storage_a_.read(tokens[1], data);
            if (!r.success) {
                sendResponse(client_fd, "ERR_STORAGE_FAILURE");
            } else {
                sendResponse(client_fd,
                             "OK " + std::to_string(data.size()));
                sendRaw(client_fd, data.c_str(), data.size());
            }
            continue;
        }

        // ── LIST ─────────────────────────────────────────────────
        // Syntax: LIST <path>
        // Response: "OK <count>\n" then one entry per line
        if (cmd == "LIST") {
            if (tokens.size() < 2) {
                sendResponse(client_fd, "ERR_BAD_REQUEST");
                continue;
            }
            std::vector<std::string> entries;
            AckResult r = storage_a_.list(tokens[1], entries);
            if (!r.success) {
                sendResponse(client_fd, "ERR_STORAGE_FAILURE");
            } else {
                sendResponse(client_fd,
                             "OK " + std::to_string(entries.size()));
                for (const auto& e : entries)
                    sendResponse(client_fd, e);
            }
            continue;
        }

        // ── STAT ─────────────────────────────────────────────────
        // Syntax: STAT <path>
        if (cmd == "STAT") {
            if (tokens.size() < 2) {
                sendResponse(client_fd, "ERR_BAD_REQUEST");
                continue;
            }
            std::string stat_out;
            AckResult r = storage_a_.stat(tokens[1], stat_out);
            if (!r.success) {
                sendResponse(client_fd, "ERR_STORAGE_FAILURE");
            } else {
                sendResponse(client_fd, "OK");
                sendResponse(client_fd, stat_out);
            }
            continue;
        }

        // ── MKDIR ────────────────────────────────────────────────
        // Syntax: MKDIR <path>
        if (cmd == "MKDIR") {
            if (tokens.size() < 2) {
                sendResponse(client_fd, "ERR_BAD_REQUEST");
                continue;
            }
            const std::string& path = tokens[1];

            if (!acquireWriteLock(path)) {
                sendResponse(client_fd, "ERR_LOCK_TIMEOUT");
                continue;
            }

            AckResult ra = storage_a_.mkdir(path, username);
            AckResult rb = storage_b_.mkdir(path, username);

            releaseWriteLock(path);

            if (ra.success && rb.success)
                sendResponse(client_fd, "OK");
            else
                sendResponse(client_fd, "ERR_STORAGE_FAILURE");
            continue;
        }

        sendResponse(client_fd, "ERR_UNKNOWN_COMMAND");
    }

    close(client_fd);
}

// ===================================================================
// WRITE LOCK MANAGEMENT
// ===================================================================

bool Coordinator::acquireWriteLock(const std::string& path)
{
    std::shared_ptr<WriteLock> wl;
    {
        std::lock_guard<std::mutex> map_guard(locks_map_mutex_);
        auto it = write_locks_.find(path);
        if (it == write_locks_.end()) {
            wl = std::make_shared<WriteLock>();
            write_locks_[path] = wl;
        } else {
            wl = it->second;
        }
    }

    auto deadline = std::chrono::steady_clock::now()
                    + std::chrono::seconds(lock_timeout_s_);

    std::unique_lock<std::mutex> ul(wl->mtx);

    bool acquired = wl->cv.wait_until(ul, deadline,
                                      [&wl]{ return !wl->locked; });

    if (!acquired) {
        std::cerr << "WARN: forced lock release on " << path
                  << " after timeout" << std::endl;
        // Fall through and take the lock anyway.
    }

    wl->locked      = true;
    wl->acquired_at = std::chrono::steady_clock::now();
    return true;
}

void Coordinator::releaseWriteLock(const std::string& path)
{
    std::shared_ptr<WriteLock> wl;
    {
        std::lock_guard<std::mutex> map_guard(locks_map_mutex_);
        auto it = write_locks_.find(path);
        if (it == write_locks_.end()) return;
        wl = it->second;
    }

    {
        std::lock_guard<std::mutex> ul(wl->mtx);
        wl->locked = false;
    }
    wl->cv.notify_one();
}

// ===================================================================
// MAIN
// ===================================================================

int main()
{
    int port = 8080;

    const char* env_secret  = std::getenv("DOCUVAULT_SECRET");
    const char* env_timeout = std::getenv("LOCK_TIMEOUT_SECONDS");
    const char* env_sa_host = std::getenv("STORAGE_A_HOST");
    const char* env_sa_port = std::getenv("STORAGE_A_PORT");
    const char* env_sb_host = std::getenv("STORAGE_B_HOST");
    const char* env_sb_port = std::getenv("STORAGE_B_PORT");
    const char* env_users   = std::getenv("USERS_FILE");

    std::string secret       = env_secret  ? env_secret  : "default_secret";
    int         lock_timeout = env_timeout ? std::atoi(env_timeout) : 5;
    std::string sa_host      = env_sa_host ? env_sa_host : "storage-a";
    int         sa_port      = env_sa_port ? std::atoi(env_sa_port) : 9001;
    std::string sb_host      = env_sb_host ? env_sb_host : "storage-b";
    int         sb_port      = env_sb_port ? std::atoi(env_sb_port) : 9002;
    std::string user_file    = env_users   ? env_users   : "/data/users.txt";

    std::cout << "Coordinator starting..." << std::endl;
    std::cout << "  Storage A: " << sa_host << ":" << sa_port << std::endl;
    std::cout << "  Storage B: " << sb_host << ":" << sb_port << std::endl;
    std::cout << "  Lock timeout: " << lock_timeout << "s" << std::endl;

    Coordinator coord(port, secret,
                      sa_host, sa_port,
                      sb_host, sb_port,
                      user_file, lock_timeout);
    coord.run();

    return 0;
}