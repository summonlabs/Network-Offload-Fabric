#include "detail/file_io.hpp"

#include <cerrno>
#include <cstring>

#if defined(_WIN32)
#include <direct.h>
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace nof::detail {

namespace {

Error io_error(ReasonCode code, const std::string& path, const char* what) {
  return Error(code, std::string(what) + ": " + path);
}

// fopen_s / fopen on Windows open files without sharing, which makes a second
// reader (tooling, a verifier, or another coordinator inspecting the same
// store) fail with a sharing violation. The store must be readable by other
// processes, so the shared open is used explicitly.
std::FILE* open_shared(const char* path, const char* mode) {
#if defined(_WIN32)
  return _fsopen(path, mode, _SH_DENYNO);
#else
  return std::fopen(path, mode);
#endif
}

}  // namespace

void FileHandle::close() noexcept {
  if (file != nullptr) {
    std::fclose(file);
    file = nullptr;
  }
}

Result<FileHandle> open_file(const std::string& path, bool create, bool append, bool truncate) {
  const bool exists = file_exists(path);
  if (!exists && !create) {
    return io_error(ReasonCode::StoreUnavailable, path, "cannot open store file");
  }
  const char* mode = nullptr;
  if (truncate || !exists) {
    mode = "w+b";
  } else if (append) {
    mode = "r+b";
  } else {
    mode = "rb";
  }
  std::FILE* raw = open_shared(path.c_str(), mode);
  if (raw == nullptr) {
    return create ? io_error(ReasonCode::StoreUnavailable, path, "cannot create store file")
                  : io_error(ReasonCode::StoreUnavailable, path, "cannot open store file");
  }
  FileHandle handle;
  handle.file = raw;
  if (append) {
    if (std::fseek(raw, 0, SEEK_END) != 0) {
      return io_error(ReasonCode::StoreUnavailable, path, "cannot seek to end of store file");
    }
  }
  return handle;
}

Result<std::vector<std::byte>> read_file(const std::string& path, std::uint64_t max_bytes) {
  auto handle = open_file(path, false, false);
  if (!handle) {
    return handle.error();
  }
  std::FILE* file = handle.value().file;
  if (std::fseek(file, 0, SEEK_END) != 0) {
    return io_error(ReasonCode::StoreUnavailable, path, "cannot seek store file");
  }
  const long length = std::ftell(file);
  if (length < 0) {
    return io_error(ReasonCode::StoreUnavailable, path, "cannot size store file");
  }
  const auto size = static_cast<std::uint64_t>(length);
  if (size > max_bytes) {
    return Error(ReasonCode::OversizedInput, "store file exceeds the configured size bound");
  }
  if (std::fseek(file, 0, SEEK_SET) != 0) {
    return io_error(ReasonCode::StoreUnavailable, path, "cannot rewind store file");
  }
  std::vector<std::byte> buffer(static_cast<std::size_t>(size));
  if (size > 0) {
    const std::size_t read = std::fread(buffer.data(), 1, buffer.size(), file);
    if (read != buffer.size()) {
      return Error(ReasonCode::StoreTruncated, "store file could not be read in full");
    }
  }
  return buffer;
}

Result<std::uint64_t> file_size(const std::string& path) {
  std::FILE* raw = open_shared(path.c_str(), "rb");
  if (raw == nullptr) {
    return io_error(ReasonCode::StoreUnavailable, path, "cannot stat store file");
  }
  FileHandle handle;
  handle.file = raw;
  if (std::fseek(raw, 0, SEEK_END) != 0) {
    return io_error(ReasonCode::StoreUnavailable, path, "cannot seek store file");
  }
  const long length = std::ftell(raw);
  if (length < 0) {
    return io_error(ReasonCode::StoreUnavailable, path, "cannot size store file");
  }
  return static_cast<std::uint64_t>(length);
}

bool file_exists(const std::string& path) {
  std::FILE* raw = open_shared(path.c_str(), "rb");
  if (raw == nullptr) {
    return false;
  }
  std::fclose(raw);
  return true;
}

Status write_all(std::FILE* file, std::span<const std::byte> data) {
  if (data.empty()) {
    return ok_status();
  }
  const std::size_t written = std::fwrite(data.data(), 1, data.size(), file);
  if (written != data.size()) {
    return Error(ReasonCode::StoreUnavailable, "short write to store file");
  }
  return ok_status();
}

Status flush_and_sync(std::FILE* file, bool durable) {
  if (std::fflush(file) != 0) {
    return Error(ReasonCode::StoreUnavailable, "store flush failed");
  }
  if (!durable) {
    return ok_status();
  }
#if defined(_WIN32)
  if (_commit(_fileno(file)) != 0) {
    return Error(ReasonCode::StoreUnavailable, "store commit failed");
  }
#else
  if (fsync(fileno(file)) != 0) {
    return Error(ReasonCode::StoreUnavailable, "store commit failed");
  }
#endif
  return ok_status();
}

Status truncate_to(std::FILE* file, std::uint64_t size) {
  if (std::fflush(file) != 0) {
    return Error(ReasonCode::StoreUnavailable, "store flush failed before truncation");
  }
#if defined(_WIN32)
  if (_chsize_s(_fileno(file), static_cast<__int64>(size)) != 0) {
    return Error(ReasonCode::StoreUnavailable, "store truncation failed");
  }
#else
  if (ftruncate(fileno(file), static_cast<off_t>(size)) != 0) {
    return Error(ReasonCode::StoreUnavailable, "store truncation failed");
  }
#endif
  if (std::fseek(file, static_cast<long>(size), SEEK_SET) != 0) {
    return Error(ReasonCode::StoreUnavailable, "store seek after truncation failed");
  }
  return ok_status();
}

Status atomic_replace(const std::string& source, const std::string& target) {
#if defined(_WIN32)
  if (MoveFileExA(source.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING) == 0) {
    return Error(ReasonCode::StoreUnavailable, "atomic replace failed for " + target);
  }
  return ok_status();
#else
  if (std::rename(source.c_str(), target.c_str()) != 0) {
    return Error(ReasonCode::StoreUnavailable, "atomic replace failed for " + target);
  }
  return ok_status();
#endif
}

Status remove_file(const std::string& path) noexcept {
#if defined(_WIN32)
  if (DeleteFileA(path.c_str()) == 0) {
    return Error(ReasonCode::StoreUnavailable, "cannot remove " + path);
  }
  return ok_status();
#else
  if (std::remove(path.c_str()) != 0) {
    return Error(ReasonCode::StoreUnavailable, "cannot remove " + path);
  }
  return ok_status();
#endif
}

Status ensure_directory(const std::string& path) {
  if (path.empty()) {
    return ok_status();
  }
#if defined(_WIN32)
  const int result = _mkdir(path.c_str());
#else
  const int result = mkdir(path.c_str(), 0755);
#endif
  if (result == 0 || errno == EEXIST) {
    return ok_status();
  }
  return Error(ReasonCode::StoreUnavailable, "cannot create directory " + path);
}

Status ensure_parent_directory(const std::string& path) {
  const std::size_t slash = path.find_last_of("/\\");
  if (slash == std::string::npos || slash == 0) {
    return ok_status();
  }
  const std::string parent = path.substr(0, slash);
  return ensure_directory(parent);
}

}  // namespace nof::detail
