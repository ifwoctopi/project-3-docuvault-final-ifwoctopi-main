#include "fs.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <openssl/hmac.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

// ===================================================================
// Storage Node — accepts binary-framed requests from the Coordinator,
// verifies HMAC authentication, executes file operations using your
// Checkpoint 1 FileSystem class, and sends ACK responses.
//
// This is a NEW entry point — it does NOT use the text-based command
// protocol from Checkpoint 1.  It reuses your FileSystem and block
// storage code, but wraps it in the binary message protocol defined
// in protocol.h.
// ===================================================================

// -------------------------------------------------------------------
// Low-level I/O helpers — do not modify
// -------------------------------------------------------------------

static bool sendAll(int fd, const void* buf, size_t len)
{
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

static bool recvAll(int fd, void* buf, size_t len)
{
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t received = 0;
    while (received < len) {
        ssize_t n = recv(fd, p + received, len - received, 0);
        if (n <= 0) return false;
        received += static_cast<size_t>(n);
    }
    return true;
}

// ===================================================================
// HMAC VERIFICATION — implement this
// ===================================================================

// Compute HMAC-SHA256 over `data` (length `len`) using `secret`.
// Write the 32-byte result into `out`.
static void computeHMAC(const std::string& secret,
                        const uint8_t* data, size_t len,
                        uint8_t* out)
{
    // TODO: implement
    //
    // Use OpenSSL's HMAC() function from <openssl/hmac.h>.

    (void)secret; (void)data; (void)len; (void)out;
}

// Verify that the HMAC tag on a received frame is correct.
// Returns true if the tag matches.
static bool verifyHMAC(const std::string& secret,
                       const uint8_t* signable_data, size_t signable_len,
                       const uint8_t* received_hmac)
{
    // TODO: implement
    //
    // 1. Compute the expected HMAC over signable_data.
    // 2. Compare it to received_hmac (constant-time comparison
    //    is ideal but not required for this project).
    // 3. Return true if they match.

    (void)secret; (void)signable_data; (void)signable_len;
    (void)received_hmac;
    return false;
}

// ===================================================================
// FRAME SEND — implement this
// ===================================================================

static bool sendAck(int fd, const std::string& secret,
                    MessageType type,
                    const std::vector<uint8_t>& payload)
{
    // TODO: implement
    //
    // Build and send a response frame (ACK_OK or ACK_ERR):
    //
    // 1. Write the 4-byte magic (network byte order).
    // 2. Write the 1-byte message type.
    // 3. Write the 4-byte payload length (network byte order).
    // 4. Write the payload.
    // 5. Compute HMAC over (type + length + payload) and write it.

    (void)fd; (void)secret; (void)type; (void)payload;
    return false;
}

// ===================================================================
// CONNECTION HANDLER — implement this
// ===================================================================

static void handleConnection(int client_fd,
                              FileSystem& fs,
                              const std::string& secret)
{
    // TODO: implement
    //
    // Loop: receive binary frames, dispatch to FileSystem, send ACKs.
    //
    // For each frame:
    //   1. Read the header, payload, and HMAC tag.
    //   2. Verify the magic number and HMAC.
    //      If the HMAC is invalid, log:
    //        "WARN: rejected unauthenticated message from <ip>"
    //      and send ACK_ERR (but don't disconnect).
    //   3. Dispatch the message type to the appropriate FileSystem
    //      method and send an ACK response with any result data.

    (void)client_fd; (void)fs; (void)secret;
    close(client_fd);
}

// ===================================================================
// MAIN — do not modify
// ===================================================================

int main(int argc, char* argv[])
{
    int port = 9001;
    std::string data_dir = "/data/store";

    // Parse optional port override.
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            port = std::atoi(argv[++i]);
        } else if (arg == "--data" && i + 1 < argc) {
            data_dir = argv[++i];
        }
    }

    // Read the shared secret from the environment.
    const char* env_secret = std::getenv("DOCUVAULT_SECRET");
    if (!env_secret || std::strlen(env_secret) == 0) {
        std::cerr << "ERROR: DOCUVAULT_SECRET environment variable not set"
                  << std::endl;
        return 1;
    }
    std::string secret = env_secret;

    // Initialize the file system (reuses your Checkpoint 1 code).
    FileSystem fs(data_dir);

    std::cout << "Storage node starting on port " << port << std::endl;

    // Create listening socket.
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "ERROR: socket() failed: " << strerror(errno) << std::endl;
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(static_cast<uint16_t>(port));

    if (bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "ERROR: bind() failed: " << strerror(errno) << std::endl;
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 10) < 0) {
        std::cerr << "ERROR: listen() failed: " << strerror(errno) << std::endl;
        close(server_fd);
        return 1;
    }

    std::cout << "Storage node listening on port " << port << std::endl;

    // Accept loop — one thread per connection.
    while (true) {
        sockaddr_in client_addr{};
        socklen_t   client_len = sizeof(client_addr);
        int client_fd = accept(server_fd,
                               reinterpret_cast<sockaddr*>(&client_addr),
                               &client_len);
        if (client_fd < 0) {
            std::cerr << "WARN: accept() failed: " << strerror(errno)
                      << std::endl;
            continue;
        }
        std::thread(handleConnection, client_fd,
                    std::ref(fs), std::cref(secret)).detach();
    }

    close(server_fd);
    return 0;
}
