#ifndef DOCUVAULT_FS_H
#define DOCUVAULT_FS_H

#include <cstdint>
#include <ctime>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

inline constexpr int    BLOCK_SIZE  = 4096;   // bytes per disk block
inline constexpr int    MAX_BLOCKS  = 1024;   // total blocks in the store
inline constexpr size_t BUFFER_CAP  = 4096;   // write-buffer capacity (bytes)

// Default permission bits (Unix rwx style, 9-bit):
//   owner: rw-  group: ---  other: ---   →  0600 for files
//   owner: rwx  group: ---  other: ---   →  0700 for directories
inline constexpr uint16_t DEFAULT_FILE_PERMS = 0600;
inline constexpr uint16_t DEFAULT_DIR_PERMS  = 0700;

// Permission bit masks used by checkPermission().
enum PermType : uint8_t {
    PERM_READ    = 4,   // r bit
    PERM_WRITE   = 2,   // w bit
    PERM_EXECUTE = 1    // x bit
};

// ---------------------------------------------------------------------------
// FileMetadata — one entry per file or directory in the index
// ---------------------------------------------------------------------------

struct FileMetadata {
    std::string         name;       // base name (e.g. "report.txt")
    std::string         path;       // full path  (e.g. "/docs/report.txt")
    std::string         owner;      // username that created this entry
    size_t              size = 0;   // file size in bytes (0 for directories)
    uint16_t            perms = 0;  // 9-bit Unix rwx (owner | group | other)
    std::time_t         created  = 0;
    std::time_t         modified = 0;
    bool                is_dir   = false;
    std::vector<int>    blocks;     // indices into the block store (files only)
};

// ---------------------------------------------------------------------------
// WriteBuffer — fixed-capacity in-memory buffer for incoming writes
//
// Accumulates data from WRITE commands.  When the buffer is full it must
// be flushed to disk.  It must also be flushed on LOGOUT, on server
// shutdown, and before a READ of the buffered path (so the reader sees
// the latest data).
// ---------------------------------------------------------------------------

class WriteBuffer {
public:
    WriteBuffer() = default;

    // Append raw bytes to the buffer.  Returns the number of bytes that
    // were accepted (may be less than `len` if the buffer fills up).
    size_t append(const char* data, size_t len);

    // Flush the buffer contents to disk via the FileSystem that owns
    // this buffer.  This is called by FileSystem::flushBuffer().
    // After flushing, the buffer is cleared.
    //
    // The actual disk-write logic lives in FileSystem — the buffer
    // itself only stores bytes.  See FileSystem::flushBuffer() for the
    // implementation contract.
    void clear();

    bool   isFull()  const { return data_.size() >= BUFFER_CAP; }
    bool   hasData() const { return !data_.empty(); }
    size_t size()    const { return data_.size(); }

    const std::vector<char>& data() const { return data_; }

    // Target path: the file currently being written through this buffer.
    void               setTargetPath(const std::string& p) { target_path_ = p; }
    const std::string& targetPath()  const                 { return target_path_; }

private:
    std::vector<char> data_;
    std::string       target_path_;
};

// ---------------------------------------------------------------------------
// FileSystem — manages the on-disk block store, metadata index, and
//              write buffering.
//
// Students implement every method marked TODO in fs.cpp.
// ---------------------------------------------------------------------------

class FileSystem {
public:
    // Construct with the base directory where all data is stored.
    // The constructor should call init() to set up the storage directory,
    // block bitmap, and root directory entry.
    explicit FileSystem(const std::string& base_path);

    // ----- directory operations -----

    // Create a directory at `path` owned by `owner`.
    // Returns true on success, false if the path already exists or the
    // parent directory does not exist.
    bool createDirectory(const std::string& path, const std::string& owner);

    // List entries in the directory at `path`.
    // Returns a vector of metadata for each child entry.
    // Throws std::runtime_error if `path` is not a directory or does
    // not exist.
    std::vector<FileMetadata> listDirectory(const std::string& path) const;

    // ----- file operations -----

    // Write `data` to the file at `path`.  Creates the file if it does
    // not exist; overwrites if it does.  Data passes through the write
    // buffer before reaching disk.
    //
    // Returns true on success, false on failure (e.g. disk full, bad
    // parent path).
    bool writeFile(const std::string& path,
                   const std::string& data,
                   const std::string& owner);

    // Read the entire contents of the file at `path` into `data_out`.
    // Flushes the write buffer first if it targets this path (so the
    // reader always sees the latest bytes).
    //
    // Returns true on success, false if the path does not exist or is
    // a directory.
    bool readFile(const std::string& path, std::string& data_out);

    // Delete the file at `path`, free its blocks, and remove its index
    // entry.  Returns true on success, false if the path does not exist
    // or is a directory.
    bool deleteFile(const std::string& path);

    // ----- metadata -----

    // Return the metadata for `path`.
    // Throws std::out_of_range if `path` is not in the index.
    FileMetadata getStat(const std::string& path) const;

    // Return true if `path` exists in the index (file or directory).
    bool pathExists(const std::string& path) const;

    // ----- permissions -----

    // Check whether `username` has the `perm` bit set for `path`.
    // The owner of a file always has full permissions regardless of
    // the stored bits.
    //
    // Returns true if access is allowed, false otherwise.
    // Throws std::out_of_range if `path` is not in the index.
    bool checkPermission(const std::string& path,
                         const std::string& username,
                         PermType perm) const;

    // ----- buffering -----

    // Flush the write buffer to disk.  This allocates blocks for the
    // buffered data, writes them to the block store, and updates the
    // file's metadata (size, modified time, block list).
    void flushBuffer();

    // Expose the buffer so the server layer can inspect it (e.g. to
    // flush before a READ of the same path).
    WriteBuffer&       writeBuffer()       { return write_buffer_; }
    const WriteBuffer& writeBuffer() const { return write_buffer_; }

    // ----- disk state (for testing / debugging) -----

    // Return the number of free blocks remaining.
    int freeBlockCount() const;

private:
    // Called by the constructor.  Creates the storage directory if it
    // does not exist, initializes the block bitmap to all-free, and
    // adds a root directory ("/") entry to the index.
    void init();

    // Persist the current index to disk (data/index.dat or equivalent).
    void saveIndex() const;

    // Load the index from disk on startup.
    void loadIndex();

    // Allocate `n` free blocks from the bitmap.  Returns their indices.
    // Returns an empty vector if fewer than `n` blocks are available.
    std::vector<int> allocateBlocks(int n);

    // Mark the given block indices as free in the bitmap.
    void freeBlocks(const std::vector<int>& block_ids);

    // Write raw bytes to the block at `block_id`.
    void writeBlock(int block_id, const char* data, size_t len);

    // Read the block at `block_id` into `buf`.  Returns the number of
    // bytes actually stored in that block.
    size_t readBlock(int block_id, char* buf, size_t buf_size) const;

    // Resolve the parent directory from a full path (e.g. "/docs/f.txt"
    // → "/docs").  Returns "/" for top-level entries.
    static std::string parentPath(const std::string& path);

    // Extract the base name from a full path (e.g. "/docs/f.txt"
    // → "f.txt").
    static std::string baseName(const std::string& path);

    std::string                                base_path_;
    std::unordered_map<std::string, FileMetadata> index_;
    std::vector<bool>                          block_bitmap_;   // true = in use
    WriteBuffer                                write_buffer_;
    mutable std::mutex                         mutex_;          // guards index_ and bitmap_
};

#endif // DOCUVAULT_FS_H
