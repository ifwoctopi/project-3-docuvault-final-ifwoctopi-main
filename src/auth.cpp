#include "auth.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <openssl/sha.h>
#include <sstream>
#include <stdexcept>

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

AuthManager::AuthManager(const std::string& user_file_path)
{
    loadUsers(user_file_path);
}

// ---------------------------------------------------------------------------
// loadUsers — parse the user file
//
// File format (one user per line):
//     username:sha256_hex_hash
//
// Lines that are empty or start with '#' are comments and should be
// skipped.  If a line does not contain exactly one ':', skip it and
// print a warning to stderr.
// ---------------------------------------------------------------------------

void AuthManager::loadUsers(const std::string& path)
{
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open user file: " + path);
    }

    std::string line;
    int count = 0;
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // Find the ':' separator
        size_t colon_pos = line.find(':');
        if (colon_pos == std::string::npos) {
            std::cerr << "WARN: Malformed user line (no colon): " << line << std::endl;
            continue;
        }

        std::string username = line.substr(0, colon_pos);
        std::string hash = line.substr(colon_pos + 1);

        users_[username] = User{username, hash};
        count++;
    }

    std::cout << "Loaded " << count << " users" << std::endl;
}

// ---------------------------------------------------------------------------
// authenticate — check a plaintext password against the stored hash
// ---------------------------------------------------------------------------

bool AuthManager::authenticate(const std::string& username,
                               const std::string& password) const
{
    auto it = users_.find(username);
    if (it == users_.end()) {
        return false;
    }

    std::string computed_hash = hashPassword(password);
    return computed_hash == it->second.password_hash;
}

// ---------------------------------------------------------------------------
// userExists
// ---------------------------------------------------------------------------

bool AuthManager::userExists(const std::string& username) const
{
    return users_.find(username) != users_.end();
}

// ---------------------------------------------------------------------------
// hashPassword — SHA-256 hex digest
//
// Use OpenSSL's SHA256() function.  It writes 32 raw bytes into a
// buffer.  Convert each byte to a two-character lowercase hex string
// and concatenate them.
//
// Example:
//   hashPassword("admin123")
//   → "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"
// ---------------------------------------------------------------------------

std::string AuthManager::hashPassword(const std::string& input)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()),
           input.length(),
           digest);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(digest[i]);
    }

    return oss.str();
}
