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
    // TODO: implement
    //
    // 1. Create a TCP socket.
    // 2. Resolve host_ using getaddrinfo().
    // 3. Connect to the resolved address on port_.
    // 4. Store the file descriptor in fd_.
    // 5. Return true on success.
    //
    // Consider setting SO_RCVTIMEO / SO_SNDTIMEO on the socket
    // so that operations don't block forever if a storage node
    // becomes unresponsive.

    return false;
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
    // TODO: implement
    //
    // Send exactly `len` bytes from `buf` over fd_.
    // Loop on partial sends.  Return false on error.

    (void)buf; (void)len;
    return false;
}

bool StorageClient::recvAll(void* buf, size_t len)
{
    // TODO: implement
    //
    // Receive exactly `len` bytes into `buf` from fd_.
    // Loop on partial recvs.  Return false on error.

    (void)buf; (void)len;
    return false;
}

// ===================================================================
// HMAC computation
// ===================================================================

void StorageClient::computeHMAC(const uint8_t* data, size_t len,
                                uint8_t* out) const
{
    // TODO: implement
    //
    // Compute HMAC-SHA256 over `data` (length `len`) using secret_
    // as the key.  Write the 32-byte result into `out`.
    //
    // Use OpenSSL's HMAC() function from <openssl/hmac.h>.

    (void)data; (void)len; (void)out;
}

// ===================================================================
// Frame send / receive
// ===================================================================

bool StorageClient::sendFrame(MessageType type,
                              const std::vector<uint8_t>& payload)
{
    // TODO: implement
    //
    // Build a binary frame and send it over the socket:
    //
    // 1. Write the 4-byte magic (network byte order).
    // 2. Write the 1-byte message type.
    // 3. Write the 4-byte payload length (network byte order).
    // 4. Write the payload bytes.
    // 5. Compute the HMAC over the signable region
    //    (type + payload_length + payload) and write the 32-byte tag.
    //
    // Return true if all bytes were sent successfully.

    (void)type; (void)payload;
    return false;
}

bool StorageClient::recvFrame(MessageFrame& frame)
{
    // TODO: implement
    //
    // Read a complete binary frame from the socket:
    //
    // 1. Read the 9-byte header (magic + type + length).
    // 2. Verify the magic number.
    // 3. Read `payload_len` bytes of payload.
    // 4. Read the 32-byte HMAC tag.
    // 5. Verify the HMAC by computing it locally and comparing.
    //    If it doesn't match, return false.
    // 6. Populate the MessageFrame struct and return true.

    (void)frame;
    return false;
}

// ===================================================================
// RPC methods
// ===================================================================

AckResult StorageClient::write(const std::string& path,
                               const std::string& data,
                               const std::string& owner,
                               uint16_t perms)
{
    // TODO: implement
    //
    // 1. Pack the path, owner, and perms into a payload (use the
    //    helpers in protocol.h or your own encoding).
    // 2. Append the file data to the payload.
    // 3. Send a MSG_FORWARD_WRITE frame.
    // 4. Receive the ACK frame.
    // 5. Return an AckResult based on whether it was ACK_OK or ACK_ERR.

    (void)path; (void)data; (void)owner; (void)perms;
    return AckResult{false, "Not implemented"};
}

AckResult StorageClient::read(const std::string& path,
                              std::string& data_out)
{
    // TODO: implement
    //
    // 1. Pack the path into a payload.
    // 2. Send a MSG_FORWARD_READ frame.
    // 3. Receive the ACK frame.
    // 4. If ACK_OK, extract the file data from the response payload
    //    into data_out.

    (void)path; (void)data_out;
    return AckResult{false, "Not implemented"};
}

AckResult StorageClient::remove(const std::string& path)
{
    // TODO: implement

    (void)path;
    return AckResult{false, "Not implemented"};
}

AckResult StorageClient::list(const std::string& path,
                              std::vector<std::string>& entries_out)
{
    // TODO: implement

    (void)path; (void)entries_out;
    return AckResult{false, "Not implemented"};
}

AckResult StorageClient::mkdir(const std::string& path,
                               const std::string& owner)
{
    // TODO: implement

    (void)path; (void)owner;
    return AckResult{false, "Not implemented"};
}

AckResult StorageClient::stat(const std::string& path,
                              std::string& stat_out)
{
    // TODO: implement

    (void)path; (void)stat_out;
    return AckResult{false, "Not implemented"};
}
