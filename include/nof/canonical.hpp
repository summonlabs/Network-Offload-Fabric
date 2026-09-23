#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "nof/error.hpp"
#include "nof/ids.hpp"

// Canonical encodings.
//
// Binary: little-endian fixed-width integers, length-prefixed byte strings, and
// an explicit presence marker for optional fields, so that no two distinct
// values share an encoding. Digests are computed over this encoding.
//
// JSON: integers only (never floating point), object keys emitted in sorted
// order with duplicates refused, ASCII-only output with non-printable bytes
// escaped. Two equal documents always serialize to identical bytes.
namespace nof {

class BinWriter {
 public:
  explicit BinWriter(std::size_t max_bytes) : max_bytes_(max_bytes) {}

  Status u8(std::uint8_t value);
  Status u16(std::uint16_t value);
  Status u32(std::uint32_t value);
  Status u64(std::uint64_t value);
  Status i64(std::int64_t value);
  Status boolean(bool value);
  Status presence(bool present);
  Status bytes(std::span<const std::byte> value);
  Status text(std::string_view value);
  Status token(std::string_view value);
  Status digest(const Digest& value);

  const std::vector<std::byte>& data() const noexcept { return buffer_; }
  std::vector<std::byte> take() noexcept { return std::move(buffer_); }
  std::size_t size() const noexcept { return buffer_.size(); }
  std::size_t max_bytes() const noexcept { return max_bytes_; }
  bool would_fit(std::size_t extra) const noexcept;
  Digest fingerprint() const noexcept;

 private:
  Status append(const void* data, std::size_t length);

  std::vector<std::byte> buffer_;
  std::size_t max_bytes_;
};

class BinReader {
 public:
  BinReader(std::span<const std::byte> data, std::size_t max_text_bytes)
      : data_(data), max_text_bytes_(max_text_bytes) {}

  Result<std::uint8_t> u8();
  Result<std::uint16_t> u16();
  Result<std::uint32_t> u32();
  Result<std::uint64_t> u64();
  Result<std::int64_t> i64();
  Result<bool> boolean();
  Result<bool> presence();
  Result<std::string> text();
  Result<std::string> token();
  Result<Digest> digest();
  // Reads a length-prefixed byte string and returns a view into the buffer
  // without copying. Bounded by max_length before the length is trusted.
  Result<std::span<const std::byte>> take_bytes(std::size_t max_length);
  // Reads exactly `length` bytes. Used when the caller has already validated
  // the length field itself.
  Result<std::span<const std::byte>> take_raw(std::size_t length);

  bool at_end() const noexcept { return position_ == data_.size(); }
  std::size_t remaining() const noexcept { return data_.size() - position_; }
  std::size_t position() const noexcept { return position_; }

 private:
  Result<std::span<const std::byte>> take(std::size_t length);

  std::span<const std::byte> data_;
  std::size_t position_ = 0;
  std::size_t max_text_bytes_;
};

// Canonical JSON document model. Values are immutable once constructed; the
// object constructor refuses duplicate keys with DuplicateIdentity.
class JsonValue {
 public:
  using Array = std::vector<JsonValue>;
  using Member = std::pair<std::string, JsonValue>;
  using Object = std::vector<Member>;

  enum class Kind : std::uint8_t { Null, Bool, Int, UInt, String, Array, Object };

  JsonValue() = default;
  static JsonValue null();
  static JsonValue boolean(bool value);
  static JsonValue integer(std::int64_t value);
  static JsonValue uinteger(std::uint64_t value);
  static JsonValue string(std::string value);
  static Result<JsonValue> array(Array values);
  static Result<JsonValue> object(Object members);

  Kind kind() const noexcept { return kind_; }
  bool is_null() const noexcept { return kind_ == Kind::Null; }
  const std::string& as_string() const noexcept { return string_; }
  const Array& as_array() const noexcept { return array_; }
  const Object& as_object() const noexcept { return object_; }

  // Serializes to canonical JSON. Refuses (OversizedInput) when the encoded
  // document would exceed max_bytes rather than producing a truncated document
  // that still parses.
  Status dump(std::string& out, std::size_t max_bytes) const;

 private:
  void dump_into(std::string& out, std::size_t max_bytes, std::size_t depth, Status& status) const;

  Kind kind_ = Kind::Null;
  bool bool_ = false;
  std::int64_t int_ = 0;
  std::uint64_t uint_ = 0;
  std::string string_;
  Array array_;
  Object object_;
};

// Minimal, strict JSON reader used to accept externally supplied documents
// (policy, requests, journal side files). It refuses trailing garbage,
// duplicate keys, non-integer numbers, and nesting beyond a fixed depth.
class JsonReader {
 public:
  explicit JsonReader(std::string_view text, std::size_t max_depth = 32)
      : text_(text), max_depth_(max_depth) {}

  Result<JsonValue> parse();

 private:
  Status skip_whitespace();
  Result<JsonValue> parse_value(std::size_t depth);
  Result<JsonValue> parse_string();
  Result<JsonValue> parse_number();
  Result<JsonValue> parse_array(std::size_t depth);
  Result<JsonValue> parse_object(std::size_t depth);
  Result<std::string> parse_raw_string();
  bool consume(char expected);

  std::string_view text_;
  std::size_t position_ = 0;
  std::size_t max_depth_;
};

}  // namespace nof
