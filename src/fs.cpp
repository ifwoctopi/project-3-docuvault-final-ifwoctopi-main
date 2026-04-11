#include "fs.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>

// ===================================================================
// WriteBuffer
// ===================================================================

size_t WriteBuffer::append(const char* data, size_t len)
{
    size_t available = BUFFER_CAP - data_.size();
    size_t to_append = std::min(len, available);
    
    data_.insert(data_.end(), data, data + to_append);
    return to_append;
}

void WriteBuffer::clear()
{
    data_.clear();
    // Do NOT clear target_path_ — it should persist across multiple flushes
    // Only clear it when switching to a different file
}

// ===================================================================
// FileSystem — constructor and init
// ===================================================================

FileSystem::FileSystem(const std::string& base_path)
    : base_path_(base_path),
      block_bitmap_(MAX_BLOCKS, false)
{
    init();
}

void FileSystem::init()
{
    // Create base directory
    std::string cmd = "mkdir -p " + base_path_ + "/blocks";
    int ret = system(cmd.c_str());
    (void)ret;
    
    // Try to load existing index
    loadIndex();
    
    // If no index was loaded, create root directory
    if (index_.empty()) {
        FileMetadata root;
        root.path = "/";
        root.name = "/";
        root.owner = "root";
        root.is_dir = true;
        root.perms = 0777;  // Make root world-accessible (rwxrwxrwx)
        root.created = std::time(nullptr);
        root.modified = std::time(nullptr);
        index_["/"] = root;
        saveIndex();
    }
}

// ===================================================================
// Directory operations
// ===================================================================

bool FileSystem::createDirectory(const std::string& path,
                                 const std::string& owner)
{
    if (pathExists(path)) {
        return false;
    }
    
    std::string parent = parentPath(path);
    if (!pathExists(parent)) {
        return false;
    }
    
    FileMetadata meta;
    meta.name = baseName(path);
    meta.path = path;
    meta.owner = owner;
    meta.is_dir = true;
    meta.perms = DEFAULT_DIR_PERMS;
    meta.created = std::time(nullptr);
    meta.modified = std::time(nullptr);
    
    index_[path] = meta;
    saveIndex();
    return true;
}

std::vector<FileMetadata> FileSystem::listDirectory(const std::string& path) const
{
    auto it = index_.find(path);
    if (it == index_.end() || !it->second.is_dir) {
        throw std::runtime_error("Path is not a directory: " + path);
    }
    
    std::vector<FileMetadata> entries;
    std::string parent = (path == "/") ? "/" : path;
    
    for (const auto& pair : index_) {
        if (pair.first == path) continue;  // Skip the directory itself
        if (parentPath(pair.first) == parent) {
            entries.push_back(pair.second);
        }
    }
    
    return entries;
}

// ===================================================================
// File operations
// ===================================================================

bool FileSystem::writeFile(const std::string& path,
                           const std::string& data,
                           const std::string& owner)
{
    // Flush buffer if targeting a different file
    if (write_buffer_.targetPath() != path && write_buffer_.targetPath() != "") {
        flushBuffer();
    }
    
    write_buffer_.setTargetPath(path);
    
    // If file exists, free old blocks
    auto it = index_.find(path);
    if (it != index_.end()) {
        freeBlocks(it->second.blocks);
        it->second.blocks.clear();
    } else {
        // File doesn't exist — check parent
        std::string parent = parentPath(path);
        if (!pathExists(parent)) {
            return false;
        }
        
        FileMetadata meta;
        meta.name = baseName(path);
        meta.path = path;
        meta.owner = owner;
        meta.perms = DEFAULT_FILE_PERMS;
        meta.created = std::time(nullptr);
        meta.modified = std::time(nullptr);
        meta.is_dir = false;
        meta.size = 0;
        index_[path] = meta;
    }
    
    // Append data to buffer, flushing as needed
    size_t offset = 0;
    while (offset < data.size()) {
        size_t appended = write_buffer_.append(data.c_str() + offset,
                                               data.size() - offset);
        offset += appended;
        
        if (write_buffer_.isFull()) {
            flushBuffer();
        }
    }
    
    // Update metadata
    index_[path].size = data.size();
    index_[path].modified = std::time(nullptr);
    
    saveIndex();
    return true;
}

bool FileSystem::readFile(const std::string& path, std::string& data_out)
{
    // Flush if buffer targets this path
    if (write_buffer_.targetPath() == path) {
        flushBuffer();
    }
    
    auto it = index_.find(path);
    if (it == index_.end() || it->second.is_dir) {
        return false;
    }
    
    const auto& meta = it->second;
    data_out.clear();
    
    char buf[BLOCK_SIZE];
    for (int block_id : meta.blocks) {
        size_t n = readBlock(block_id, buf, BLOCK_SIZE);
        data_out.append(buf, n);
    }
    
    // Truncate to actual file size
    if (data_out.size() > meta.size) {
        data_out.resize(meta.size);
    }
    
    return true;
}

bool FileSystem::deleteFile(const std::string& path)
{
    auto it = index_.find(path);
    if (it == index_.end() || it->second.is_dir) {
        return false;
    }
    
    const auto& meta = it->second;
    freeBlocks(meta.blocks);
    
    index_.erase(path);
    
    if (write_buffer_.targetPath() == path) {
        write_buffer_.clear();
    }
    
    saveIndex();
    return true;
}

// ===================================================================
// Metadata
// ===================================================================

FileMetadata FileSystem::getStat(const std::string& path) const
{
    auto it = index_.find(path);
    if (it == index_.end()) {
        throw std::out_of_range("Path not found: " + path);
    }
    return it->second;
}

bool FileSystem::pathExists(const std::string& path) const
{
    return index_.find(path) != index_.end();
}

// ===================================================================
// Permissions
// ===================================================================

bool FileSystem::checkPermission(const std::string& path,
                                 const std::string& username,
                                 PermType perm) const
{
    auto it = index_.find(path);
    if (it == index_.end()) {
        throw std::out_of_range("Path not found in index");
    }
    
    const auto& meta = it->second;
    
    // Owner has full access
    if (meta.owner == username) {
        return true;
    }
    
    // Check permission bits (owner bits are in 0x100, 0x080, 0x040)
    // For non-owner, we check the "group" bits (0x020, 0x010, 0x008)
    // Actually, looking at the permission format, it seems to be Unix rwxrwxrwx
    // Standard Unix: owner(3 bits) | group(3 bits) | other(3 bits)
    // The enum has single bits: 4(read), 2(write), 1(execute)
    // Let me check what the format actually is...
    // Looking at formatPerms in server.cpp: it checks bits 0x100, 0x080, etc.
    // Those correspond to owner bits. For non-owner, checking other bits.
    
    uint16_t perm_bits = meta.perms;
    if (perm == PERM_READ) {
        return (perm_bits & 0x004) != 0;  // other read bit
    } else if (perm == PERM_WRITE) {
        return (perm_bits & 0x002) != 0;  // other write bit
    } else if (perm == PERM_EXECUTE) {
        return (perm_bits & 0x001) != 0;  // other execute bit
    }
    return false;
}

// ===================================================================
// Buffering
// ===================================================================

void FileSystem::flushBuffer()
{
    if (!write_buffer_.hasData()) {
        return;
    }
    
    const auto& data = write_buffer_.data();
    size_t bytes_needed = data.size();
    int blocks_needed = (bytes_needed + BLOCK_SIZE - 1) / BLOCK_SIZE;
    
    std::vector<int> blocks = allocateBlocks(blocks_needed);
    if (blocks.empty()) {
        std::cerr << "ERROR: Could not allocate blocks for buffer" << std::endl;
        return;
    }
    
    // Write blocks to disk
    auto it = index_.find(write_buffer_.targetPath());
    if (it != index_.end()) {
        size_t offset = 0;
        for (int block_id : blocks) {
            size_t to_write = std::min((size_t)BLOCK_SIZE, bytes_needed - offset);
            writeBlock(block_id, data.data() + offset, to_write);
            it->second.blocks.push_back(block_id);
            offset += to_write;
        }
    }
    
    write_buffer_.clear();
    saveIndex();
}

// ===================================================================
// Disk state
// ===================================================================

int FileSystem::freeBlockCount() const
{
    int count = 0;
    for (int i = 0; i < MAX_BLOCKS; ++i) {
        if (!block_bitmap_[i]) {
            count++;
        }
    }
    return count;
}

// ===================================================================
// Private helpers
// ===================================================================

void FileSystem::saveIndex() const
{
    std::string index_path = base_path_ + "/index.txt";
    std::ofstream f(index_path);
    if (!f) {
        throw std::runtime_error("Cannot write index: " + index_path);
    }
    
    for (const auto& pair : index_) {
        const auto& meta = pair.second;
        f << meta.path << "|" << meta.name << "|" << meta.owner << "|" 
          << meta.size << "|" << meta.perms << "|" << meta.created << "|" 
          << meta.modified << "|" << (meta.is_dir ? "1" : "0") << "|";
        
        for (const auto& block_id : meta.blocks) {
            f << block_id << ",";
        }
        f << "\n";
    }
}

void FileSystem::loadIndex()
{
    std::string index_path = base_path_ + "/index.txt";
    std::ifstream f(index_path);
    if (!f) {
        // No index file — start fresh with root directory
        return;
    }
    
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        
        std::istringstream ss(line);
        std::string path, name, owner, size_str, perms_str, created_str, 
                    modified_str, is_dir_str, blocks_str;
        
        if (!std::getline(ss, path, '|') ||
            !std::getline(ss, name, '|') ||
            !std::getline(ss, owner, '|') ||
            !std::getline(ss, size_str, '|') ||
            !std::getline(ss, perms_str, '|') ||
            !std::getline(ss, created_str, '|') ||
            !std::getline(ss, modified_str, '|') ||
            !std::getline(ss, is_dir_str, '|') ||
            !std::getline(ss, blocks_str, '|')) {
            continue;
        }
        
        FileMetadata meta;
        meta.path = path;
        meta.name = name;
        meta.owner = owner;
        meta.size = std::stoul(size_str);
        meta.perms = std::stoul(perms_str);
        meta.created = std::stol(created_str);
        meta.modified = std::stol(modified_str);
        meta.is_dir = (is_dir_str == "1");
        
        // Parse block IDs
        std::istringstream block_stream(blocks_str);
        std::string block_str;
        while (std::getline(block_stream, block_str, ',')) {
            if (!block_str.empty()) {
                meta.blocks.push_back(std::stoi(block_str));
                // Mark block as in-use
                int block_id = std::stoi(block_str);
                if (block_id >= 0 && block_id < MAX_BLOCKS) {
                    block_bitmap_[block_id] = true;
                }
            }
        }
        
        index_[path] = meta;
    }
}

std::vector<int> FileSystem::allocateBlocks(int n)
{
    std::vector<int> result;
    int count = 0;
    for (int i = 0; i < MAX_BLOCKS && count < n; ++i) {
        if (!block_bitmap_[i]) {
            block_bitmap_[i] = true;
            result.push_back(i);
            count++;
        }
    }
    
    if (count < n) {
        // Allocation failed — free what we allocated and return empty
        for (int block_id : result) {
            block_bitmap_[block_id] = false;
        }
        return {};
    }
    return result;
}

void FileSystem::freeBlocks(const std::vector<int>& block_ids)
{
    for (int block_id : block_ids) {
        if (block_id >= 0 && block_id < MAX_BLOCKS) {
            block_bitmap_[block_id] = false;
        }
    }
}

void FileSystem::writeBlock(int block_id, const char* data, size_t len)
{
    std::string block_path = base_path_ + "/blocks/" + std::to_string(block_id);
    std::ofstream f(block_path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("Cannot write block: " + block_path);
    }
    f.write(data, static_cast<std::streamsize>(len));
}

size_t FileSystem::readBlock(int block_id, char* buf, size_t buf_size) const
{
    std::string block_path = base_path_ + "/blocks/" + std::to_string(block_id);
    std::ifstream f(block_path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("Cannot read block: " + block_path);
    }
    f.read(buf, static_cast<std::streamsize>(buf_size));
    return f.gcount();
}

std::string FileSystem::parentPath(const std::string& path)
{
    if (path == "/") return "/";
    
    size_t last_slash = path.rfind('/');
    if (last_slash == std::string::npos || last_slash == 0) {
        return "/";
    }
    return path.substr(0, last_slash);
}

std::string FileSystem::baseName(const std::string& path)
{
    if (path == "/") return "/";
    
    size_t last_slash = path.rfind('/');
    if (last_slash == std::string::npos) {
        return path;
    }
    if (last_slash == 0 && path.length() > 1) {
        return path.substr(1);
    }
    return path.substr(last_slash + 1);
}
