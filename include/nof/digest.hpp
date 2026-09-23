#pragma once

#include <cstdint>
#include <span>
#include <string_view>

#include "nof/ids.hpp"

// In-house, dependency-free integrity and fingerprint primitives. Both are
// implemented from their specifications and validated against the standard
// published test vectors in tests/test_digest.cpp.
namespace nof {

// SHA-256 over an arbitrary byte span. Used for canonical state fingerprints,
// request fingerprints, and digest-chained journal records.
Digest sha256(std::span<const std::byte> data) noexcept;
Digest sha256(std::string_view data) noexcept;

// Incremental SHA-256 so large documents can be hashed without materializing a
// second copy of the bytes.
class Sha256 {
 public:
  Sha256() noexcept;
  void update(std::span<const std::byte> data) noexcept;
  void update(std::string_view data) noexcept;
  Digest finish() noexcept;

 private:
  void compress(const std::uint8_t block[64]) noexcept;
  std::uint32_t state_[8];
  std::uint64_t bit_length_;
  std::uint8_t buffer_[64];
  std::size_t buffer_length_;
};

// CRC-32C (Castagnoli, reflected, polynomial 0x1EDC6F41). Guards every durable
// record and every protocol frame.
std::uint32_t crc32c(std::span<const std::byte> data) noexcept;
std::uint32_t crc32c(std::string_view data) noexcept;

// Canonical lowercase hex rendering of a 32-bit value (8 characters).
std::string hex32(std::uint32_t value);
std::string hex64(std::uint64_t value);

}  // namespace nof
