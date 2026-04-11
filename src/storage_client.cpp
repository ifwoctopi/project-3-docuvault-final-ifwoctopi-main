#include "coordinator.h"

#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <openssl/hmac.h>
#include <sys/socket.h>
#include <unistd.h>

// ===================================================================
// Construction / Connection
// ===================================================================

StorageClient::StorageClient(const std::string& host, int port,
                             const std::string& secret)
    : host_(host), port_(port), secret_(secret)
{
}

StorageClient::~StorageClient()
{
    disconnect();
}

bool StorageClient::connect()
{
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string port_str = std::to_string(port_);
    int rc = getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0) {
        std::cerr << "StorageClient: getaddrinfo(" << host_ << "): "
                  << gai_strerror(rc) << std::endl;
        return false;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        std::cerr << "StorageClient: socket(): " << strerror(errno) << std::endl;
        freeaddrinfo(res);
        return false;
    }

    // 10-second timeout so a dead storage node doesn't hang the coordinator.
    struct timeval tv{ 10, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (::connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        std::cerr << "StorageClient: connect(" << host_ << ":" << port_ << "): "
                  << strerror(errno) << std::endl;
        close(sock);
        freeaddrinfo(res);
        return false;
    }

    freeaddrinfo(res);
    fd_ = sock;
    return true;
}

void StorageClient::disconnect()
{
    if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
    }
}

bool StorageClient::isConnected() const
{
    return fd_ >= 0;
}

// ===================================================================
// Low-level I/O
// ===================================================================

bool StorageClient::sendAll(const void* buf, size_t len)
{
    const char* ptr = static_cast<const char*>(buf);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = ::send(fd_, ptr + sent, len - sent, 0);
        if (n <= 0) {
            std::cerr << "StorageClient: send(): " << strerror(errno) << std::endl;
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool StorageClient::recvAll(void* buf, size_t len)
{
    char* ptr = static_cast<char*>(buf);
    size_t received = 0;
    while (received < len) {
        ssize_t n = ::recv(fd_, ptr + received, len - received, 0);
        if (n <= 0) {
            std::cerr << "StorageClient: recv(): " << strerror(errno) << std::endl;
            return false;
        }
        received += static_cast<size_t>(n);
    }
    return true;
}

// ===================================================================
// HMAC computation
// ===================================================================

void StorageClient::computeHMAC(const uint8_t* data, size_t len,
                                uint8_t* out) const
{
    unsigned int out_len = HMAC_SIZE;
    HMAC(EVP_sha256(),
         secret_.data(), static_cast<int>(secret_.size()),
         data, len,
         out, &out_len);
}

// ===================================================================
// Frame send / receive
// ===================================================================

bool StorageClient::sendFrame(MessageType type,
                              const std::vector<uint8_t>& payload)
{
    std::lock_guard<std::mutex> lock(io_mutex_);

    // ── Header ────────────────────────────────────────────────────
    uint32_t magic_ne = htonl(PROTO_MAGIC);
    uint8_t  type_byte = static_cast<uint8_t>(type);
    uint32_t plen_ne   = htonl(static_cast<uint32_t>(payload.size()));

    if (!sendAll(&magic_ne,  4)) return false;
    if (!sendAll(&type_byte, 1)) return false;
    if (!sendAll(&plen_ne,   4)) return false;

    // ── Payload ───────────────────────────────────────────────────
    if (!payload.empty())
        if (!sendAll(payload.data(), payload.size())) return false;

    // ── HMAC over signable region: type(1) + payload_len(4) + payload ──
    std::vector<uint8_t> signable;
    signable.reserve(1 + 4 + payload.size());
    signable.push_back(type_byte);
    signable.push_back(static_cast<uint8_t>((payload.size() >> 24) & 0xFF));
    signable.push_back(static_cast<uint8_t>((payload.size() >> 16) & 0xFF));
    signable.push_back(static_cast<uint8_t>((payload.size() >>  8) & 0xFF));
    signable.push_back(static_cast<uint8_t>( payload.size()        & 0xFF));
    signable.insert(signable.end(), payload.begin(), payload.end());

    uint8_t tag[HMAC_SIZE];
    computeHMAC(signable.data(), signable.size(), tag);
    if (!sendAll(tag, HMAC_SIZE)) return false;

    return true;
}

bool StorageClient::recvFrame(MessageFrame& frame)
{
    std::lock_guard<std::mutex> lock(io_mutex_);

    // ── Header (9 bytes) ─────────────────────────────────────────
    uint8_t header[FRAME_HEADER_SIZE];
    if (!recvAll(header, FRAME_HEADER_SIZE)) return false;

    uint32_t magic = 0;
    std::memcpy(&magic, header, 4);
    magic = ntohl(magic);
    if (magic != PROTO_MAGIC) {
        std::cerr << "StorageClient: bad magic 0x" << std::hex << magic << std::endl;
        return false;
    }

    frame.msg_type = static_cast<MessageType>(header[4]);

    uint32_t plen_ne = 0;
    std::memcpy(&plen_ne, header + 5, 4);
    frame.payload_len = ntohl(plen_ne);

    // ── Payload ───────────────────────────────────────────────────
    frame.payload.resize(frame.payload_len);
    if (frame.payload_len > 0)
        if (!recvAll(frame.payload.data(), frame.payload_len)) return false;

    // ── HMAC tag ──────────────────────────────────────────────────
    if (!recvAll(frame.hmac, HMAC_SIZE)) return false;

    // ── Verify: recompute over type(1) + payload_len(4) + payload ──
    std::vector<uint8_t> signable;
    signable.reserve(1 + 4 + frame.payload_len);
    signable.push_back(header[4]);                  // type byte (already raw)
    signable.push_back(header[5]);                  // payload_len bytes (NBO)
    signable.push_back(header[6]);
    signable.push_back(header[7]);
    signable.push_back(header[8]);
    signable.insert(signable.end(), frame.payload.begin(), frame.payload.end());

    uint8_t expected[HMAC_SIZE];
    computeHMAC(signable.data(), signable.size(), expected);

    if (std::memcmp(expected, frame.hmac, HMAC_SIZE) != 0) {
        std::cerr << "StorageClient: HMAC verification failed" << std::endl;
        return false;
    }

    return true;
}

// ===================================================================
// RPC helper — send a frame and receive the ACK, with io_mutex_
// already released (sendFrame/recvFrame each take it individually).
// ===================================================================

static AckResult makeErr(const std::string& msg)
{
    return AckResult{false, msg};
}

// ===================================================================
// RPC methods
// ===================================================================

AckResult StorageClient::write(const std::string& path,
                               const std::string& data,
                               const std::string& owner,
                               uint16_t perms)
{
    // Payload: path\0  owner\0  perms_str\0  <raw file bytes>
    auto payload = packFields(
        { path, owner, std::to_string(perms) },
        data
    );

    if (!sendFrame(MSG_FORWARD_WRITE, payload))
        return makeErr("send failed");

    MessageFrame ack;
    if (!recvFrame(ack))
        return makeErr("recv failed");

    if (ack.msg_type == MSG_ACK_OK)
        return AckResult{true};

    // ACK_ERR payload is a human-readable error string.
    std::string err(ack.payload.begin(), ack.payload.end());
    return makeErr(err);
}

AckResult StorageClient::read(const std::string& path,
                              std::string& data_out)
{
    auto payload = packFields({ path });

    if (!sendFrame(MSG_FORWARD_READ, payload))
        return makeErr("send failed");

    MessageFrame ack;
    if (!recvFrame(ack))
        return makeErr("recv failed");

    if (ack.msg_type != MSG_ACK_OK) {
        std::string err(ack.payload.begin(), ack.payload.end());
        return makeErr(err);
    }

    // ACK_OK payload for READ: path\0 <raw file bytes>
    // We only need the file bytes — skip past the first null-term field.
    std::vector<std::string> fields;
    size_t data_offset = 0;
    if (unpackFields(ack.payload, 1, fields, data_offset)) {
        data_out.assign(ack.payload.begin() + data_offset, ack.payload.end());
    } else {
        // No field prefix — payload is raw file data.
        data_out.assign(ack.payload.begin(), ack.payload.end());
    }

    return AckResult{true};
}

AckResult StorageClient::remove(const std::string& path)
{
    auto payload = packFields({ path });

    if (!sendFrame(MSG_FORWARD_DELETE, payload))
        return makeErr("send failed");

    MessageFrame ack;
    if (!recvFrame(ack))
        return makeErr("recv failed");

    if (ack.msg_type == MSG_ACK_OK)
        return AckResult{true};

    std::string err(ack.payload.begin(), ack.payload.end());
    return makeErr(err);
}

AckResult StorageClient::list(const std::string& path,
                              std::vector<std::string>& entries_out)
{
    auto payload = packFields({ path });

    if (!sendFrame(MSG_FORWARD_LIST, payload))
        return makeErr("send failed");

    MessageFrame ack;
    if (!recvFrame(ack))
        return makeErr("recv failed");

    if (ack.msg_type != MSG_ACK_OK) {
        std::string err(ack.payload.begin(), ack.payload.end());
        return makeErr(err);
    }

    // ACK_OK payload for LIST: entry\0 entry\0 ... entry\0
    entries_out.clear();
    size_t pos = 0;
    while (pos < ack.payload.size()) {
        size_t end = pos;
        while (end < ack.payload.size() && ack.payload[end] != '\0') ++end;
        entries_out.emplace_back(ack.payload.begin() + pos,
                                 ack.payload.begin() + end);
        pos = end + 1;
    }

    return AckResult{true};
}

AckResult StorageClient::mkdir(const std::string& path,
                               const std::string& owner)
{
    auto payload = packFields({ path, owner });

    if (!sendFrame(MSG_FORWARD_MKDIR, payload))
        return makeErr("send failed");

    MessageFrame ack;
    if (!recvFrame(ack))
        return makeErr("recv failed");

    if (ack.msg_type == MSG_ACK_OK)
        return AckResult{true};

    std::string err(ack.payload.begin(), ack.payload.end());
    return makeErr(err);
}

AckResult StorageClient::stat(const std::string& path,
                              std::string& stat_out)
{
    auto payload = packFields({ path });

    if (!sendFrame(MSG_FORWARD_STAT, payload))
        return makeErr("send failed");

    MessageFrame ack;
    if (!recvFrame(ack))
        return makeErr("recv failed");

    if (ack.msg_type != MSG_ACK_OK) {
        std::string err(ack.payload.begin(), ack.payload.end());
        return makeErr(err);
    }

    // ACK_OK payload for STAT is the stat string directly.
    stat_out.assign(ack.payload.begin(), ack.payload.end());
    return AckResult{true};
}