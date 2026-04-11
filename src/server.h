#ifndef DOCUVAULT_SERVER_H
#define DOCUVAULT_SERVER_H

#include "auth.h"
#include "fs.h"

#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Session — per-connection state
// ---------------------------------------------------------------------------

struct Session {
    bool        authenticated = false;
    std::string username;
};

// ---------------------------------------------------------------------------
// Handler function declarations
//
// Each handler receives parsed arguments and the current session.
// Handlers that need to send multi-part responses (raw bytes after the
// status line) also receive client_fd and send their own response,
// returning "" to signal "already sent."
//
// All other handlers return a single response string that the
// dispatcher sends via sendResponse().
// ---------------------------------------------------------------------------

// LOGIN <user> <password>
std::string handleLogin(const std::vector<std::string>& args,
                        Session& session,
                        const AuthManager& auth);

// LOGOUT
std::string handleLogout(Session& session, FileSystem& fs);

// WRITE <path> <byte_count>   (reads raw data from the socket)
std::string handleWrite(int client_fd,
                        const std::vector<std::string>& args,
                        Session& session,
                        FileSystem& fs);

// READ <path>                 (sends OK <byte_count>\n then raw bytes)
// Returns "" after sending its own response.
std::string handleRead(int client_fd,
                       const std::vector<std::string>& args,
                       Session& session,
                       FileSystem& fs);

// DELETE <path>
std::string handleDelete(const std::vector<std::string>& args,
                         Session& session,
                         FileSystem& fs);

// LIST <path>                 (sends OK <count>\n then one line per entry)
// Returns "" after sending its own response.
std::string handleList(int client_fd,
                       const std::vector<std::string>& args,
                       Session& session,
                       FileSystem& fs);

// MKDIR <path>
std::string handleMkdir(const std::vector<std::string>& args,
                        Session& session,
                        FileSystem& fs);

// STAT <path>
std::string handleStat(const std::vector<std::string>& args,
                       Session& session,
                       FileSystem& fs);

// ---------------------------------------------------------------------------
// I/O helpers — complete implementations provided in server.cpp
//
// These are stateless utility functions for reading and writing on a
// connected TCP socket.  They are not OS-concept code — they are
// plumbing so you can focus on the handlers.
// ---------------------------------------------------------------------------

// Read one line from fd (up to and including '\n').
// Returns the line content WITHOUT the trailing '\n'.
// Returns "" if the connection is closed or an error occurs.
std::string readLine(int fd);

// Send a text response followed by '\n'.
void sendResponse(int fd, const std::string& msg);

// Read exactly `n` bytes from fd into a string.
// Returns a short string if the connection closes early.
std::string readBytes(int fd, size_t n);

// Send exactly `len` raw bytes to fd (no trailing newline).
void sendRaw(int fd, const char* data, size_t len);

// ---------------------------------------------------------------------------
// Server entry point
// ---------------------------------------------------------------------------

// Parse a single command line into tokens split on whitespace.
std::vector<std::string> tokenize(const std::string& line);

// Main client-handling loop: read commands, dispatch to handlers,
// send responses.  Runs in its own thread per client.
void handleClient(int client_fd, AuthManager& auth, FileSystem& fs);

#endif // DOCUVAULT_SERVER_H
