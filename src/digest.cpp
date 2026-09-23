#include "nof/digest.hpp"

#include <array>
#include <cstring>

namespace nof {

namespace {

constexpr std::uint32_t kSha256Initial[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                                             0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

constexpr std::uint32_t kSha256Round[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u,
    0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu,
    0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu,
    0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
    0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u,
    0xc67178f2u};

inline std::uint32_t rotr(std::uint32_t value, std::uint32_t count) noexcept {
  return (value >> count) | (value << (32u - count));
}

inline std::uint32_t load_be32(const std::uint8_t* data) noexcept {
  return (static_cast<std::uint32_t>(data[0]) << 24) | (static_cast<std::uint32_t>(data[1]) << 16) |
         (static_cast<std::uint32_t>(data[2]) << 8) | static_cast<std::uint32_t>(data[3]);
}

inline void store_be32(std::uint8_t* out, std::uint32_t value) noexcept {
  out[0] = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
  out[1] = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
  out[2] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  out[3] = static_cast<std::uint8_t>(value & 0xFFu);
}

const std::array<std::uint32_t, 256>& crc32c_table() {
  static const std::array<std::uint32_t, 256> table = [] {
    std::array<std::uint32_t, 256> built{};
    for (std::uint32_t i = 0; i < 256; ++i) {
      std::uint32_t crc = i;
      for (int bit = 0; bit < 8; ++bit) {
        crc = (crc & 1u) != 0u ? (crc >> 1) ^ 0x82F63B78u : (crc >> 1);
      }
      built[i] = crc;
    }
    return built;
  }();
  return table;
}

}  // namespace

Sha256::Sha256() noexcept
    : bit_length_(0), buffer_length_(0) {
  std::memcpy(state_, kSha256Initial, sizeof(state_));
  std::memset(buffer_, 0, sizeof(buffer_));
}

void Sha256::compress(const std::uint8_t block[64]) noexcept {
  std::uint32_t schedule[64];
  for (int i = 0; i < 16; ++i) {
    schedule[i] = load_be32(block + i * 4);
  }
  for (int i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotr(schedule[i - 15], 7) ^ rotr(schedule[i - 15], 18) ^
                             (schedule[i - 15] >> 3);
    const std::uint32_t s1 = rotr(schedule[i - 2], 17) ^ rotr(schedule[i - 2], 19) ^
                             (schedule[i - 2] >> 10);
    schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
  }

  std::uint32_t a = state_[0];
  std::uint32_t b = state_[1];
  std::uint32_t c = state_[2];
  std::uint32_t d = state_[3];
  std::uint32_t e = state_[4];
  std::uint32_t f = state_[5];
  std::uint32_t g = state_[6];
  std::uint32_t h = state_[7];

  for (int i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + ch + kSha256Round[i] + schedule[i];
    const std::uint32_t s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;
  state_[5] += f;
  state_[6] += g;
  state_[7] += h;
}

void Sha256::update(std::span<const std::byte> data) noexcept {
  const auto* bytes = reinterpret_cast<const std::uint8_t*>(data.data());
  std::size_t length = data.size();
  bit_length_ += static_cast<std::uint64_t>(length) * 8u;

  while (length > 0) {
    const std::size_t room = 64 - buffer_length_;
    const std::size_t take = length < room ? length : room;
    std::memcpy(buffer_ + buffer_length_, bytes, take);
    buffer_length_ += take;
    bytes += take;
    length -= take;
    if (buffer_length_ == 64) {
      compress(buffer_);
      buffer_length_ = 0;
    }
  }
}

void Sha256::update(std::string_view data) noexcept {
  update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()), data.size()));
}

Digest Sha256::finish() noexcept {
  const std::uint64_t total_bits = bit_length_;
  const std::uint8_t pad = 0x80;
  update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&pad), 1));
  const std::uint8_t zero = 0x00;
  while (buffer_length_ != 56) {
    update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&zero), 1));
  }
  std::uint8_t length_bytes[8];
  for (int i = 0; i < 8; ++i) {
    length_bytes[7 - i] = static_cast<std::uint8_t>((total_bits >> (i * 8)) & 0xFFu);
  }
  // The length field must not itself be counted as message data.
  const std::uint64_t saved = bit_length_;
  update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(length_bytes), 8));
  bit_length_ = saved;

  Digest out;
  for (int i = 0; i < 8; ++i) {
    store_be32(out.bytes + i * 4, state_[i]);
  }
  return out;
}

Digest sha256(std::span<const std::byte> data) noexcept {
  Sha256 hasher;
  hasher.update(data);
  return hasher.finish();
}

Digest sha256(std::string_view data) noexcept {
  Sha256 hasher;
  hasher.update(data);
  return hasher.finish();
}

std::uint32_t crc32c(std::span<const std::byte> data) noexcept {
  const auto& table = crc32c_table();
  std::uint32_t crc = 0xFFFFFFFFu;
  for (const std::byte item : data) {
    const auto index = static_cast<std::uint8_t>(crc ^ static_cast<std::uint32_t>(item));
    crc = (crc >> 8) ^ table[index];
  }
  return crc ^ 0xFFFFFFFFu;
}

std::uint32_t crc32c(std::string_view data) noexcept {
  return crc32c(std::span<const std::byte>(reinterpret_cast<const std::byte*>(data.data()),
                                           data.size()));
}

std::string hex32(std::uint32_t value) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(8);
  for (int i = 7; i >= 0; --i) {
    out.push_back(kDigits[(value >> (i * 4)) & 0xFu]);
  }
  return out;
}

std::string hex64(std::uint64_t value) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(16);
  for (int i = 15; i >= 0; --i) {
    out.push_back(kDigits[(value >> (i * 4)) & 0xFu]);
  }
  return out;
}

}  // namespace nof
