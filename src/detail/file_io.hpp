#pragma once

#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

#include "nof/error.hpp"

// Small, explicit file primitives used by the durable store. Nothing here
// buffers silently: every write either completes or reports a refusal.
namespace nof::detail {

struct FileHandle {
  std::FILE* file = nullptr;

  FileHandle() = default;
  FileHandle(const FileHandle&) = delete;
  FileHandle& operator=(const FileHandle&) = delete;
  FileHandle(FileHandle&& other) noexcept : file(other.file) { other.file = nullptr; }
  FileHandle& operator=(FileHandle&& other) noexcept {
    if (this != &other) {
      close();
      file = other.file;
      other.file = nullptr;
    }
    return *this;
  }
  ~FileHandle() { close(); }

  void close() noexcept;
  bool valid() const noexcept { return file != nullptr; }
};

// Opens for read+write. `create` allows the file to be created when missing and
// `append` positions at end of file. `truncate` is a separate, explicit
// decision: opening an existing store must never destroy it.
Result<FileHandle> open_file(const std::string& path, bool create, bool append,
                             bool truncate = false);

// Reads a whole file, refusing when it exceeds max_bytes rather than partially
// loading a damaged or absurd file.
Result<std::vector<std::byte>> read_file(const std::string& path, std::uint64_t max_bytes);

Result<std::uint64_t> file_size(const std::string& path);
bool file_exists(const std::string& path);

Status write_all(std::FILE* file, std::span<const std::byte> data);
Status flush_and_sync(std::FILE* file, bool durable);
Status truncate_to(std::FILE* file, std::uint64_t size);

// Atomically replaces `target` with `source`. On POSIX this is rename(); on
// Windows it is MoveFileEx with MOVEFILE_REPLACE_EXISTING.
Status atomic_replace(const std::string& source, const std::string& target);

Status remove_file(const std::string& path) noexcept;

// Creates a directory (and intermediate directories) when missing.
Status ensure_directory(const std::string& path);

// Creates (or leaves in place) the parent directory of a path.
Status ensure_parent_directory(const std::string& path);

}  // namespace nof::detail
