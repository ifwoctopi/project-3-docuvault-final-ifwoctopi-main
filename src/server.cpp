#include "server.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

// ===================================================================
// I/O HELPERS — complete implementations, do not modify
// ===================================================================

std::string readLine(int fd)
{
    std::string line;
    char c;
    while (true) {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) return "";      // connection closed or error
        if (c == '\n') return line;  // end of line — do NOT include '\n'
        line += c;
    }
}

void sendResponse(int fd, const std::string& msg)
{
    std::string full = msg + "\n";
    sendRaw(fd, full.c_str(), full.size());
}

std::string readBytes(int fd, size_t n)
{
    std::string buf(n, '\0');
    size_t received = 0;
    while (received < n) {
        ssize_t r = recv(fd, &buf[received], n - received, 0);
        if (r <= 0) {
            buf.resize(received);
            return buf;             // short read — connection closed early
        }
        received += static_cast<size_t>(r);
    }
    return buf;
}

void sendRaw(int fd, const char* data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) return;         // connection lost
        sent += static_cast<size_t>(n);
    }
}

std::vector<std::string> tokenize(const std::string& line)
{
    std::vector<std::string> tokens;
    std::istringstream stream(line);
    std::string token;
    while (stream >> token) {
        tokens.push_back(token);
    }
    return tokens;
}

// Format permissions into "rwxrwxrwx" style string
static std::string formatPerms(uint16_t perms) {
    std::string s = "---------";
    if (perms & 0x100) s[0] = 'r';
    if (perms & 0x080) s[1] = 'w';
    if (perms & 0x040) s[2] = 'x';
    if (perms & 0x020) s[3] = 'r';
    if (perms & 0x010) s[4] = 'w';
    if (perms & 0x008) s[5] = 'x';
    if (perms & 0x004) s[6] = 'r';
    if (perms & 0x002) s[7] = 'w';
    if (perms & 0x001) s[8] = 'x';
    return s;
}

// Format time_t to ISO-8601 (YYYY-MM-DDTHH:MM:SS)
static std::string formatTime(std::time_t t) {
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", std::localtime(&t));
    return std::string(buf);
}

// ===================================================================
// CLIENT HANDLER — complete dispatcher, do not modify
// ===================================================================

void handleClient(int client_fd, AuthManager& auth, FileSystem& fs)
{
    Session session;

    while (true) {
        std::string line = readLine(client_fd);
        if (line.empty()) break;   // client disconnected

        std::vector<std::string> tokens = tokenize(line);
        if (tokens.empty()) continue;

        std::string cmd = tokens[0];

        // Build args vector (everything after the command name).
        std::vector<std::string> args(tokens.begin() + 1, tokens.end());

        // ---- pre-login guard ----
        // LOGIN is the only command allowed before authentication.
        if (!session.authenticated && cmd != "LOGIN") {
            sendResponse(client_fd, "ERR_UNAUTHORIZED Not logged in");
            continue;
        }

        // ---- dispatch ----
        std::string response;

        if      (cmd == "LOGIN")   response = handleLogin(args, session, auth);
        else if (cmd == "LOGOUT")  response = handleLogout(session, fs);
        else if (cmd == "WRITE")   response = handleWrite(client_fd, args, session, fs);
        else if (cmd == "READ")    response = handleRead(client_fd, args, session, fs);
        else if (cmd == "DELETE")  response = handleDelete(args, session, fs);
        else if (cmd == "LIST")    response = handleList(client_fd, args, session, fs);
        else if (cmd == "MKDIR")   response = handleMkdir(args, session, fs);
        else if (cmd == "STAT")    response = handleStat(args, session, fs);
        else                       response = "ERR_BAD_REQUEST Unknown command";

        // Handlers that send their own multi-part response (handleRead,
        // handleList) return "" to signal "already sent."
        if (!response.empty()) {
            sendResponse(client_fd, response);
        }
    }

    // Flush any buffered writes before the connection closes.
    fs.flushBuffer();
    close(client_fd);
}

// ===================================================================
// HANDLER STUBS — implement each one
// ===================================================================

// LOGIN <username> <password>
//
// 1. Validate that args has exactly 2 elements; return ERR_BAD_REQUEST
//    if not.
// 2. Call auth.authenticate(username, password).
// 3. On success: set session.authenticated = true, session.username,
//    and return "OK Logged in".
// 4. On failure: return "ERR_UNAUTHORIZED Invalid credentials".
std::string handleLogin(const std::vector<std::string>& args,
                        Session& session,
                        const AuthManager& auth)
{
    if (args.size() != 2) return "ERR_BAD_REQUEST Usage: LOGIN <user> <pass>";
    
    if (auth.authenticate(args[0], args[1])) {
        session.authenticated = true;
        session.username = args[0];
        return "OK Logged in";
    }
    return "ERR_UNAUTHORIZED Invalid credentials";
}

// LOGOUT
//
// 1. Flush the write buffer (call fs.flushBuffer()).
// 2. Reset session.authenticated to false and clear session.username.
// 3. Return "OK Logged out".
std::string handleLogout(Session& session, FileSystem& fs)
{
    fs.flushBuffer();
    session.authenticated = false;
    session.username = "";
    return "OK Logged out";
}

// WRITE <path> <byte_count>
//
// Protocol:
//   Client sends:  WRITE /dir/file.txt 1024\n
//                  <exactly 1024 raw bytes, NO trailing newline>
//   Server reads the byte_count from args, then reads that many raw
//   bytes from client_fd using readBytes().
//
// Steps:
//   1. Validate args (need exactly 2: path, byte_count).
//   2. Parse byte_count as an integer; return ERR_BAD_REQUEST if it
//      is not a valid non-negative number.
//   3. Read exactly byte_count bytes from client_fd via readBytes().
//   4. Check write permission on the path (if the file already exists).
//   5. Call fs.writeFile(path, data, session.username).
//   6. Return "OK Written" on success, or the appropriate ERR_ code.
//
// IMPORTANT: Do NOT call readLine() for the data — it stops at '\n'.
// The data is raw bytes and may contain newlines.  Use readBytes().
std::string handleWrite(int client_fd,
                        const std::vector<std::string>& args,
                        Session& session,
                        FileSystem& fs)
{
    if (args.size() != 2) return "ERR_BAD_REQUEST Usage: WRITE <path> <bytes>";
    
    size_t byte_count;
    try {
        byte_count = std::stoul(args[1]);
    } catch (...) {
        return "ERR_BAD_REQUEST Invalid byte count";
    }

    std::string data = readBytes(client_fd, byte_count);
    if (data.size() < byte_count) return "ERR_BAD_REQUEST Unexpected EOF";

    std::string path = args[0];
    if (fs.pathExists(path)) {
        if (!fs.checkPermission(path, session.username, PermType::PERM_WRITE)) {
            return "ERR_UNAUTHORIZED Permission denied";
        }
    }

    if (fs.writeFile(path, data, session.username)) {
        return "OK Written";
    }
    return "ERR_INTERNAL Write failed";
}

// READ <path>
//
// This handler sends a TWO-PART response and returns "":
//   Part 1 (via sendResponse):  "OK <byte_count>"
//   Part 2 (via sendRaw):       the raw file bytes (no trailing newline)
//
// Steps:
//   1. Validate args (need exactly 1: path).
//   2. Check read permission on the path.
//   3. Flush the write buffer if it targets this path (so the reader
//      sees the latest data).
//   4. Call fs.readFile(path, data_out).
//   5. Send "OK <data_out.size()>" via sendResponse().
//   6. Send the raw bytes via sendRaw().
//   7. Return "" (response already sent).
//
// On error, send the ERR_ line via sendResponse() and return "".
std::string handleRead(int client_fd,
                       const std::vector<std::string>& args,
                       Session& session,
                       FileSystem& fs)
{
    if (args.size() != 1) {
        sendResponse(client_fd, "ERR_BAD_REQUEST Usage: READ <path>");
        return "";
    }

    std::string path = args[0];
    if (!fs.pathExists(path)) {
        sendResponse(client_fd, "ERR_NOT_FOUND Path not found");
        return "";
    }

    if (!fs.checkPermission(path, session.username, PermType::PERM_READ)) {
        sendResponse(client_fd, "ERR_UNAUTHORIZED Permission denied");
        return "";
    }

    std::string data;
    if (fs.readFile(path, data)) {
        sendResponse(client_fd, "OK " + std::to_string(data.size()));
        sendRaw(client_fd, data.c_str(), data.size());
    } else {
        sendResponse(client_fd, "ERR_INTERNAL Read failed");
    }
    return "";
}

// DELETE <path>
//
// 1. Validate args (need exactly 1: path).
// 2. Check that the path exists; return ERR_NOT_FOUND if not.
// 3. Check write permission on the path.
// 4. Call fs.deleteFile(path).
// 5. Return "OK Deleted" on success.
std::string handleDelete(const std::vector<std::string>& args,
                         Session& session,
                         FileSystem& fs)
{
    if (args.size() != 1) return "ERR_BAD_REQUEST Usage: DELETE <path>";
    
    std::string path = args[0];
    if (!fs.pathExists(path)) return "ERR_NOT_FOUND Not found";
    
    if (!fs.checkPermission(path, session.username, PermType::PERM_WRITE)) {
        return "ERR_UNAUTHORIZED Permission denied";
    }

    if (fs.deleteFile(path)) return "OK Deleted";
    return "ERR_INTERNAL Delete failed";
}

// LIST <path>
//
// This handler sends a MULTI-LINE response and returns "":
//   Line 1 (via sendResponse):   "OK <entry_count>"
//   Lines 2..N (via sendResponse, one per entry):
//       "<name> <type> <size> <perm_string>"
//
//   where type is "FILE" or "DIR", and perm_string is a 9-character
//   Unix-style string like "rwx------" or "rw-r--r--".
//
// Steps:
//   1. Validate args (need exactly 1: path).
//   2. Check read permission on the directory.
//   3. Call fs.listDirectory(path) — this throws if the path does
//      not exist or is not a directory.
//   4. Send the "OK <count>" header.
//   5. Send one line per entry.
//   6. Return "".
//
// On error, send the ERR_ line via sendResponse() and return "".
std::string handleList(int client_fd,
                       const std::vector<std::string>& args,
                       Session& session,
                       FileSystem& fs)
{
    if (args.size() != 1) {
        sendResponse(client_fd, "ERR_BAD_REQUEST Usage: LIST <path>");
        return "";
    }

    std::string path = args[0];
    try {
        if (!fs.checkPermission(path, session.username, PermType::PERM_READ)) {
            sendResponse(client_fd, "ERR_UNAUTHORIZED Permission denied");
            return "";
        }

        auto entries = fs.listDirectory(path);
        sendResponse(client_fd, "OK " + std::to_string(entries.size()));
        for (const auto& meta : entries) {
            std::string type = meta.is_dir ? "DIR" : "FILE";
            std::string line = meta.name + " " + type + " " + 
                               std::to_string(meta.size) + " " + 
                               formatPerms(meta.perms);
            sendResponse(client_fd, line);
        }
    } catch (const std::exception& e) {
        sendResponse(client_fd, "ERR_NOT_FOUND " + std::string(e.what()));
    }
    return "";
}

// MKDIR <path>
//
// 1. Validate args (need exactly 1: path).
// 2. Check that the path does not already exist; return ERR_EXISTS if
//    it does.
// 3. Call fs.createDirectory(path, session.username).
// 4. Return "OK Directory created" on success.
std::string handleMkdir(const std::vector<std::string>& args,
                        Session& session,
                        FileSystem& fs)
{
    if (args.size() != 1) return "ERR_BAD_REQUEST Usage: MKDIR <path>";
    if (fs.pathExists(args[0])) return "ERR_EXISTS Path exists";

    if (fs.createDirectory(args[0], session.username)) {
        return "OK Directory created";
    }
    return "ERR_INTERNAL Mkdir failed";
}

// STAT <path>
//
// 1. Validate args (need exactly 1: path).
// 2. Check that the path exists; return ERR_NOT_FOUND if not.
// 3. Call fs.getStat(path) to get the metadata.
// 4. Return a single line:
//    "OK <name> <owner> <size> <perm_string> <created> <modified>"
//
// Timestamps should be formatted as ISO-8601 (e.g. 2025-03-24T14:30:00).
// Permission string is 9 characters (e.g. "rwx------").
std::string handleStat(const std::vector<std::string>& args,
                       Session& session,
                       FileSystem& fs)
{
    if (args.size() != 1) return "ERR_BAD_REQUEST Usage: STAT <path>";
    
    std::string path = args[0];
    if (!fs.pathExists(path)) return "ERR_NOT_FOUND Not found";

    try {
        auto meta = fs.getStat(path);
        std::stringstream ss;
        ss << "OK " << meta.name << " " << meta.owner << " " << meta.size << " "
           << formatPerms(meta.perms) << " " << formatTime(meta.created) << " " 
           << formatTime(meta.modified);
        return ss.str();
    } catch (...) {
        return "ERR_INTERNAL Stat failed";
    }
}

// ===================================================================
// MAIN — complete, do not modify
// ===================================================================

int main(int argc, char* argv[])
{
    int port = 8080;
    std::string data_dir  = "/data/store";
    std::string user_file = "/data/users.txt";

    // Simple argument overrides (for local testing).
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        } else if (arg == "--data" && i + 1 < argc) {
            data_dir = argv[++i];
        } else if (arg == "--users" && i + 1 < argc) {
            user_file = argv[++i];
        }
    }

    // Initialize subsystems.
    AuthManager auth(user_file);
    FileSystem  fs(data_dir);

    std::cout << "DocuVault starting on port " << port << std::endl;

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

    std::cout << "DocuVault listening on port " << port << std::endl;

    // Accept loop — one thread per client.
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

        // Spawn a detached thread to handle this client.
        std::thread(handleClient, client_fd, std::ref(auth), std::ref(fs)).detach();
    }

    close(server_fd);
    return 0;
}
