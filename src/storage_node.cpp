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
// HMAC
// ===================================================================

static void computeHMAC(const std::string& secret,
                        const uint8_t* data, size_t len,
                        uint8_t* out)
{
    unsigned int out_len = HMAC_SIZE;
    HMAC(EVP_sha256(),
         secret.data(), static_cast<int>(secret.size()),
         data, len,
         out, &out_len);
}

static bool verifyHMAC(const std::string& secret,
                       const uint8_t* signable_data, size_t signable_len,
                       const uint8_t* received_hmac)
{
    uint8_t expected[HMAC_SIZE];
    computeHMAC(secret, signable_data, signable_len, expected);
    return std::memcmp(expected, received_hmac, HMAC_SIZE) == 0;
}

// ===================================================================
// FRAME SEND
// ===================================================================

static bool sendAck(int fd, const std::string& secret,
                    MessageType type,
                    const std::vector<uint8_t>& payload)
{
    uint32_t magic_ne  = htonl(PROTO_MAGIC);
    uint8_t  type_byte = static_cast<uint8_t>(type);
    uint32_t plen_ne   = htonl(static_cast<uint32_t>(payload.size()));

    if (!sendAll(fd, &magic_ne,  4)) return false;
    if (!sendAll(fd, &type_byte, 1)) return false;
    if (!sendAll(fd, &plen_ne,   4)) return false;

    if (!payload.empty())
        if (!sendAll(fd, payload.data(), payload.size())) return false;

    // HMAC over type(1) + payload_len_NBO(4) + payload
    std::vector<uint8_t> signable;
    signable.reserve(5 + payload.size());
    signable.push_back(type_byte);
    signable.push_back(static_cast<uint8_t>((payload.size() >> 24) & 0xFF));
    signable.push_back(static_cast<uint8_t>((payload.size() >> 16) & 0xFF));
    signable.push_back(static_cast<uint8_t>((payload.size() >>  8) & 0xFF));
    signable.push_back(static_cast<uint8_t>( payload.size()        & 0xFF));
    signable.insert(signable.end(), payload.begin(), payload.end());

    uint8_t tag[HMAC_SIZE];
    computeHMAC(secret, signable.data(), signable.size(), tag);
    if (!sendAll(fd, tag, HMAC_SIZE)) return false;

    return true;
}

static bool sendAckOk(int fd, const std::string& secret,
                      const std::vector<uint8_t>& payload = {})
{
    return sendAck(fd, secret, MSG_ACK_OK, payload);
}

static bool sendAckErr(int fd, const std::string& secret,
                       const std::string& msg)
{
    std::vector<uint8_t> payload(msg.begin(), msg.end());
    return sendAck(fd, secret, MSG_ACK_ERR, payload);
}

// ===================================================================
// CONNECTION HANDLER
// ===================================================================

static void handleConnection(int client_fd,
                              FileSystem& fs,
                              const std::string& secret)
{
    // Get client IP for log messages.
    sockaddr_in peer{};
    socklen_t peer_len = sizeof(peer);
    getpeername(client_fd, reinterpret_cast<sockaddr*>(&peer), &peer_len);
    char peer_ip[INET_ADDRSTRLEN] = "unknown";
    inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));

    while (true) {
        // ── Read 9-byte header ────────────────────────────────────
        uint8_t header[FRAME_HEADER_SIZE];
        if (!recvAll(client_fd, header, FRAME_HEADER_SIZE)) break;

        // ── Verify magic ──────────────────────────────────────────
        uint32_t magic = 0;
        std::memcpy(&magic, header, 4);
        if (ntohl(magic) != PROTO_MAGIC) {
            std::cerr << "WARN: bad magic from " << peer_ip << std::endl;
            break;
        }

        MessageType msg_type   = static_cast<MessageType>(header[4]);
        uint32_t    plen_ne    = 0;
        std::memcpy(&plen_ne, header + 5, 4);
        uint32_t    payload_len = ntohl(plen_ne);

        // ── Read payload ──────────────────────────────────────────
        std::vector<uint8_t> payload(payload_len);
        if (payload_len > 0)
            if (!recvAll(client_fd, payload.data(), payload_len)) break;

        // ── Read HMAC tag ─────────────────────────────────────────
        uint8_t received_hmac[HMAC_SIZE];
        if (!recvAll(client_fd, received_hmac, HMAC_SIZE)) break;

        // ── Verify HMAC (type + payload_len NBO bytes + payload) ──
        // Reuse the raw NBO bytes already in header[4..8] so the
        // signable region is byte-for-byte identical to what the
        // coordinator signed.
        std::vector<uint8_t> signable;
        signable.reserve(5 + payload_len);
        signable.insert(signable.end(), header + 4, header + 9);
        signable.insert(signable.end(), payload.begin(), payload.end());

        if (!verifyHMAC(secret,
                        signable.data(), signable.size(),
                        received_hmac)) {
            std::cerr << "WARN: rejected unauthenticated message from "
                      << peer_ip << std::endl;
            sendAckErr(client_fd, secret, "HMAC verification failed");
            continue;
        }

        // ── Dispatch ──────────────────────────────────────────────
        std::vector<std::string> fields;
        size_t data_offset = 0;

        switch (msg_type) {

        // ── WRITE ─────────────────────────────────────────────────
        // Payload fields: path, owner, perms  +  trailing file bytes
        case MSG_FORWARD_WRITE: {
            if (!unpackFields(payload, 3, fields, data_offset)) {
                sendAckErr(client_fd, secret, "malformed WRITE payload");
                break;
            }
            const std::string& path  = fields[0];
            const std::string& owner = fields[1];
            // perms field present in protocol but writeFile() doesn't
            // accept it — FileSystem uses DEFAULT_FILE_PERMS internally.
            std::string data(payload.begin() + data_offset, payload.end());

            bool ok = fs.writeFile(path, data, owner);
            if (ok) sendAckOk(client_fd, secret);
            else    sendAckErr(client_fd, secret, "write failed");
            break;
        }

        // ── READ ──────────────────────────────────────────────────
        // ACK_OK payload: raw file bytes
        case MSG_FORWARD_READ: {
            if (!unpackFields(payload, 1, fields, data_offset)) {
                sendAckErr(client_fd, secret, "malformed READ payload");
                break;
            }
            std::string data;
            bool ok = fs.readFile(fields[0], data);
            if (ok) {
                std::vector<uint8_t> resp(data.begin(), data.end());
                sendAckOk(client_fd, secret, resp);
            } else {
                sendAckErr(client_fd, secret, "ERR_NOT_FOUND");  // was "file not found"
            }
            break;
        }

        // ── DELETE ────────────────────────────────────────────────
        case MSG_FORWARD_DELETE: {
            if (!unpackFields(payload, 1, fields, data_offset)) {
                sendAckErr(client_fd, secret, "malformed DELETE payload");
                break;
            }
            bool ok = fs.deleteFile(fields[0]);
            if (ok) sendAckOk(client_fd, secret);
            else    sendAckErr(client_fd, secret, "ERR_NOT_FOUND");  // was "delete failed"
            break;
        }

        // ── LIST ──────────────────────────────────────────────────
        // ACK_OK payload: entry\0 entry\0 ...
        case MSG_FORWARD_LIST: {
            if (!unpackFields(payload, 1, fields, data_offset)) {
                sendAckErr(client_fd, secret, "malformed LIST payload");
                break;
            }
            std::vector<FileMetadata> entries;
            try {
                entries = fs.listDirectory(fields[0]);
            } catch (const std::exception& e) {
                sendAckErr(client_fd, secret, e.what());
                break;
            }
            std::vector<uint8_t> resp;
            for (const auto& m : entries) {
                resp.insert(resp.end(), m.name.begin(), m.name.end());
                resp.push_back('\0');
            }
            sendAckOk(client_fd, secret, resp);
            break;
        }

        // ── MKDIR ─────────────────────────────────────────────────
        case MSG_FORWARD_MKDIR: {
            if (!unpackFields(payload, 2, fields, data_offset)) {
                sendAckErr(client_fd, secret, "malformed MKDIR payload");
                break;
            }
            // Treat already-exists as success — idempotent mkdir
            bool ok = fs.createDirectory(fields[0], fields[1])
                    || fs.pathExists(fields[0]);
            if (ok) sendAckOk(client_fd, secret);
            else    sendAckErr(client_fd, secret, "ERR_MKDIR_FAILED");
            break;
        }

        // ── STAT ──────────────────────────────────────────────────
        // ACK_OK payload: formatted stat string
        case MSG_FORWARD_STAT: {
            if (!unpackFields(payload, 1, fields, data_offset)) {
                sendAckErr(client_fd, secret, "malformed STAT payload");
                break;
            }
            FileMetadata meta;
            try {
                meta = fs.getStat(fields[0]);
            } catch (const std::exception& e) {
                sendAckErr(client_fd, secret, e.what());
                break;
            }
            // Format: "name size perms owner created modified is_dir"
            std::string stat_str =
                meta.name                          + " " +
                std::to_string(meta.size)          + " " +
                std::to_string(meta.perms)         + " " +
                meta.owner                         + " " +
                std::to_string(meta.created)       + " " +
                std::to_string(meta.modified)      + " " +
                (meta.is_dir ? "dir" : "file");
            std::vector<uint8_t> resp(stat_str.begin(), stat_str.end());
            sendAckOk(client_fd, secret, resp);
            break;
        }

        default:
            sendAckErr(client_fd, secret, "unknown message type");
            break;
        }
    }

    close(client_fd);
}

// ===================================================================
// MAIN — do not modify
// ===================================================================

int main(int argc, char* argv[])
{
    int port = 9001;
    std::string data_dir = "/data/store";

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            port = std::atoi(argv[++i]);
        } else if (arg == "--data" && i + 1 < argc) {
            data_dir = argv[++i];
        }
    }

    const char* env_secret = std::getenv("DOCUVAULT_SECRET");
    if (!env_secret || std::strlen(env_secret) == 0) {
        std::cerr << "ERROR: DOCUVAULT_SECRET environment variable not set"
                  << std::endl;
        return 1;
    }
    std::string secret = env_secret;

    FileSystem fs(data_dir);

    std::cout << "Storage node starting on port " << port << std::endl;

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