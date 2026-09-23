#include "nof/ids.hpp"

#include <array>
#include <cstdio>

namespace nof {

namespace tokens {

bool is_valid_token(std::string_view text) noexcept {
  if (text.empty() || text.size() > kMaxTokenLength) {
    return false;
  }
  const auto is_head = [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
  };
  const auto is_tail = [&](char c) {
    return is_head(c) || c == '.' || c == '_' || c == ':' || c == '-';
  };
  if (!is_head(text.front())) {
    return false;
  }
  for (const char c : text) {
    if (!is_tail(c)) {
      return false;
    }
  }
  return true;
}

bool is_lower_hex(std::string_view text, std::size_t length) noexcept {
  if (text.size() != length) {
    return false;
  }
  for (const char c : text) {
    const bool digit = c >= '0' && c <= '9';
    const bool lower = c >= 'a' && c <= 'f';
    if (!digit && !lower) {
      return false;
    }
  }
  return true;
}

bool is_valid_selector(std::string_view text) noexcept {
  if (text.empty() || text.size() > kMaxSelectorLength) {
    return false;
  }
  for (const char c : text) {
    const bool alnum = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    if (!alnum && c != '.' && c != '_' && c != ':' && c != '-' && c != '=' && c != ',') {
      return false;
    }
  }
  return true;
}

}  // namespace tokens

namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

void append_hex(std::string& out, std::uint64_t value, std::size_t digits) {
  std::array<char, 16> buffer{};
  for (std::size_t i = 0; i < digits; ++i) {
    const std::size_t shift = (digits - 1 - i) * 4;
    buffer[i] = kHexDigits[(value >> shift) & 0xFu];
  }
  out.append(buffer.data(), digits);
}

}  // namespace

BootId BootId::generate(std::uint64_t entropy_a, std::uint64_t entropy_b) {
  std::string text;
  text.reserve(2 * tokens::kBootIdLength / 2);
  append_hex(text, entropy_a, tokens::kBootIdLength / 2);
  append_hex(text, entropy_b, tokens::kBootIdLength / 2);
  return BootId::from_validated(std::move(text));
}

bool Digest::is_zero() const noexcept {
  for (const std::uint8_t byte : bytes) {
    if (byte != 0) {
      return false;
    }
  }
  return true;
}

std::string Digest::hex() const {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (const std::uint8_t byte : bytes) {
    out.push_back(kDigits[(byte >> 4) & 0xFu]);
    out.push_back(kDigits[byte & 0xFu]);
  }
  return out;
}

Result<Digest> Digest::from_hex(std::string_view text) {
  if (text.size() != 64 || !tokens::is_lower_hex(text, 64)) {
    return Error(ReasonCode::InvalidIdentifier, "digest must be 64 lowercase hex characters");
  }
  Digest out;
  const auto nibble = [](char c) -> std::uint8_t {
    if (c >= '0' && c <= '9') {
      return static_cast<std::uint8_t>(c - '0');
    }
    return static_cast<std::uint8_t>(c - 'a' + 10);
  };
  for (std::size_t i = 0; i < 32; ++i) {
    const std::uint8_t high = nibble(text[i * 2]);
    const std::uint8_t low = nibble(text[i * 2 + 1]);
    out.bytes[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return out;
}

}  // namespace nof
