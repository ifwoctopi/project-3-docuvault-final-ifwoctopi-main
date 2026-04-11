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
// I/O HELPERS — reused from Checkpoint 1, do not modify
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
    // Connect to both storage nodes.
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
// CLIENT HANDLER — dispatcher scaffold, implement the handlers
// ===================================================================

void Coordinator::handleClient(int client_fd)
{
    // TODO: implement
    //
    // This follows the same pattern as Checkpoint 1's handleClient:
    //
    // 1. Maintain a Session (authenticated flag + username).
    //
    // 2. Read commands with readLine(), tokenize, dispatch.
    //
    // 3. LOGIN and LOGOUT are handled locally using auth_.
    //    All other commands are forwarded to storage nodes via
    //    storage_a_ and storage_b_.
    //
    // For WRITE and DELETE:
    //   - Acquire the write lock (acquireWriteLock).
    //   - Forward to BOTH storage nodes.
    //   - Wait for ACK_OK from both.
    //   - Release the write lock.
    //   - If either returns ACK_ERR, respond ERR_STORAGE_FAILURE.
    //
    // For READ, LIST, STAT, MKDIR:
    //   - Forward to ONE storage node (your choice — either is fine
    //     since replicas are identical).
    //   - Return the result to the client.
    //
    // The client-facing protocol is identical to Checkpoint 1:
    //   - Same command syntax
    //   - Same response format (OK / ERR_ lines)
    //   - READ sends "OK <byte_count>\n" then raw bytes
    //   - LIST sends "OK <count>\n" then one line per entry
    //
    // Close the socket when the client disconnects.

    (void)client_fd;
    close(client_fd);
}

// ===================================================================
// WRITE LOCK MANAGEMENT — implement both methods
// ===================================================================

bool Coordinator::acquireWriteLock(const std::string& path)
{
    // TODO: implement
    //
    // Acquire the write lock for `path`.  If the lock is already
    // held by another request, wait until it becomes available or
    // the timeout (lock_timeout_s_ seconds) expires.
    //
    // If the timeout expires and the lock is still held, forcibly
    // release it and log:
    //   "WARN: forced lock release on <path> after timeout"
    //
    // Return true if the lock was acquired.

    (void)path;
    return true;
}

void Coordinator::releaseWriteLock(const std::string& path)
{
    // TODO: implement
    //
    // Release the write lock for `path` so queued requests can
    // proceed.

    (void)path;
}

// ===================================================================
// MAIN — reads configuration from environment variables
// ===================================================================

int main()
{
    // Read configuration from environment variables.
    // docker-compose.yml sets all of these.
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
