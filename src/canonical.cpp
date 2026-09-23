#include "nof/canonical.hpp"

#include <algorithm>
#include <cstring>

#include "nof/checked.hpp"
#include "nof/digest.hpp"

namespace nof {

namespace {

constexpr std::size_t kJsonMaxDepth = 64;

inline std::byte to_byte(std::uint8_t value) noexcept { return static_cast<std::byte>(value); }

inline std::uint8_t from_byte(std::byte value) noexcept {
  return static_cast<std::uint8_t>(value);
}

void append_escaped(std::string& out, std::string_view text) {
  static constexpr char kDigits[] = "0123456789abcdef";
  for (const char raw : text) {
    const auto c = static_cast<unsigned char>(raw);
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      default:
        if (c < 0x20u || c >= 0x7Fu) {
          out += "\\u00";
          out.push_back(kDigits[(c >> 4) & 0xFu]);
          out.push_back(kDigits[c & 0xFu]);
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
}

}  // namespace

// ---------------------------------------------------------------------------
// BinWriter
// ---------------------------------------------------------------------------

bool BinWriter::would_fit(std::size_t extra) const noexcept {
  std::size_t total = 0;
  if (!checked_add(buffer_.size(), extra, total)) {
    return false;
  }
  return total <= max_bytes_;
}

Status BinWriter::append(const void* data, std::size_t length) {
  if (!would_fit(length)) {
    return Error(ReasonCode::OversizedInput, "canonical encoding exceeds configured bound");
  }
  const auto* bytes = static_cast<const std::byte*>(data);
  buffer_.insert(buffer_.end(), bytes, bytes + length);
  return ok_status();
}

Status BinWriter::u8(std::uint8_t value) { return append(&value, sizeof(value)); }

Status BinWriter::u16(std::uint16_t value) {
  std::uint8_t raw[2];
  raw[0] = static_cast<std::uint8_t>(value & 0xFFu);
  raw[1] = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  return append(raw, sizeof(raw));
}

Status BinWriter::u32(std::uint32_t value) {
  std::uint8_t raw[4];
  for (int i = 0; i < 4; ++i) {
    raw[i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu);
  }
  return append(raw, sizeof(raw));
}

Status BinWriter::u64(std::uint64_t value) {
  std::uint8_t raw[8];
  for (int i = 0; i < 8; ++i) {
    raw[i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xFFu);
  }
  return append(raw, sizeof(raw));
}

Status BinWriter::i64(std::int64_t value) {
  return u64(static_cast<std::uint64_t>(value));
}

Status BinWriter::boolean(bool value) { return u8(value ? 1u : 0u); }

Status BinWriter::presence(bool present) { return u8(present ? 1u : 0u); }

Status BinWriter::bytes(std::span<const std::byte> value) {
  std::uint32_t length = 0;
  if (!checked_cast<std::uint32_t>(value.size(), length)) {
    return Error(ReasonCode::OversizedInput, "byte string length exceeds 32 bits");
  }
  Status status = u32(length);
  if (!status) {
    return status;
  }
  return append(value.data(), value.size());
}

Status BinWriter::text(std::string_view value) {
  return bytes(std::span<const std::byte>(reinterpret_cast<const std::byte*>(value.data()),
                                          value.size()));
}

Status BinWriter::token(std::string_view value) { return text(value); }

Status BinWriter::digest(const Digest& value) {
  return append(value.bytes, sizeof(value.bytes));
}

Digest BinWriter::fingerprint() const noexcept {
  return sha256(std::span<const std::byte>(buffer_.data(), buffer_.size()));
}

// ---------------------------------------------------------------------------
// BinReader
// ---------------------------------------------------------------------------

Result<std::span<const std::byte>> BinReader::take(std::size_t length) {
  std::size_t end = 0;
  if (!checked_add(position_, length, end) || end > data_.size()) {
    return Error(ReasonCode::TruncatedInput, "canonical encoding ended early");
  }
  const std::span<const std::byte> slice = data_.subspan(position_, length);
  position_ = end;
  return slice;
}

Result<std::uint8_t> BinReader::u8() {
  auto slice = take(1);
  if (!slice) {
    return slice.error();
  }
  return from_byte(slice.value()[0]);
}

Result<std::uint16_t> BinReader::u16() {
  auto slice = take(2);
  if (!slice) {
    return slice.error();
  }
  const auto* raw = slice.value().data();
  std::uint16_t value = static_cast<std::uint16_t>(from_byte(raw[0]));
  value = static_cast<std::uint16_t>(value | (static_cast<std::uint16_t>(from_byte(raw[1])) << 8));
  return value;
}

Result<std::uint32_t> BinReader::u32() {
  auto slice = take(4);
  if (!slice) {
    return slice.error();
  }
  const auto* raw = slice.value().data();
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(from_byte(raw[i])) << (i * 8);
  }
  return value;
}

Result<std::uint64_t> BinReader::u64() {
  auto slice = take(8);
  if (!slice) {
    return slice.error();
  }
  const auto* raw = slice.value().data();
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(from_byte(raw[i])) << (i * 8);
  }
  return value;
}

Result<std::int64_t> BinReader::i64() {
  auto value = u64();
  if (!value) {
    return value.error();
  }
  return static_cast<std::int64_t>(value.value());
}

Result<bool> BinReader::boolean() {
  auto value = u8();
  if (!value) {
    return value.error();
  }
  if (value.value() > 1u) {
    return Error(ReasonCode::MalformedInput, "boolean must be 0 or 1");
  }
  return value.value() == 1u;
}

Result<bool> BinReader::presence() { return boolean(); }

Result<std::string> BinReader::text() {
  auto length = u32();
  if (!length) {
    return length.error();
  }
  const std::size_t size = length.value();
  if (size > max_text_bytes_) {
    return Error(ReasonCode::OversizedInput, "text field exceeds configured bound");
  }
  auto slice = take(size);
  if (!slice) {
    return slice.error();
  }
  return std::string(reinterpret_cast<const char*>(slice.value().data()), slice.value().size());
}

Result<std::string> BinReader::token() {
  auto value = text();
  if (!value) {
    return value.error();
  }
  if (!value.value().empty() && !tokens::is_valid_token(value.value())) {
    return Error(ReasonCode::InvalidIdentifier, "token is not canonical");
  }
  return value;
}

Result<std::span<const std::byte>> BinReader::take_bytes(std::size_t max_length) {
  auto length = u32();
  if (!length) {
    return length.error();
  }
  if (length.value() > max_length) {
    return Error(ReasonCode::OversizedInput, "byte string exceeds the configured bound");
  }
  return take(length.value());
}

Result<std::span<const std::byte>> BinReader::take_raw(std::size_t length) { return take(length); }

Result<Digest> BinReader::digest() {
  auto slice = take(32);
  if (!slice) {
    return slice.error();
  }
  Digest out;
  std::memcpy(out.bytes, slice.value().data(), 32);
  return out;
}

// ---------------------------------------------------------------------------
// JsonValue
// ---------------------------------------------------------------------------

JsonValue JsonValue::null() { return JsonValue{}; }

JsonValue JsonValue::boolean(bool value) {
  JsonValue out;
  out.kind_ = Kind::Bool;
  out.bool_ = value;
  return out;
}

JsonValue JsonValue::integer(std::int64_t value) {
  JsonValue out;
  out.kind_ = Kind::Int;
  out.int_ = value;
  return out;
}

JsonValue JsonValue::uinteger(std::uint64_t value) {
  JsonValue out;
  out.kind_ = Kind::UInt;
  out.uint_ = value;
  return out;
}

JsonValue JsonValue::string(std::string value) {
  JsonValue out;
  out.kind_ = Kind::String;
  out.string_ = std::move(value);
  return out;
}

Result<JsonValue> JsonValue::array(Array values) {
  JsonValue out;
  out.kind_ = Kind::Array;
  out.array_ = std::move(values);
  return out;
}

Result<JsonValue> JsonValue::object(Object members) {
  std::sort(members.begin(), members.end(),
            [](const Member& left, const Member& right) { return left.first < right.first; });
  for (std::size_t i = 1; i < members.size(); ++i) {
    if (members[i].first == members[i - 1].first) {
      return Error(ReasonCode::DuplicateIdentity, "duplicate JSON key: " + members[i].first);
    }
  }
  JsonValue out;
  out.kind_ = Kind::Object;
  out.object_ = std::move(members);
  return out;
}

void JsonValue::dump_into(std::string& out, std::size_t max_bytes, std::size_t depth,
                          Status& status) const {
  if (!status) {
    return;
  }
  if (depth > kJsonMaxDepth) {
    status = Error(ReasonCode::OutOfRange, "json nesting depth exceeded");
    return;
  }
  const auto guard = [&](std::size_t extra) {
    if (status && out.size() + extra > max_bytes) {
      status = Error(ReasonCode::OversizedInput, "canonical json exceeds configured bound");
    }
  };
  guard(1);
  if (!status) {
    return;
  }
  switch (kind_) {
    case Kind::Null:
      out += "null";
      break;
    case Kind::Bool:
      out += bool_ ? "true" : "false";
      break;
    case Kind::Int: {
      char buffer[32];
      const int written = std::snprintf(buffer, sizeof(buffer), "%lld",
                                        static_cast<long long>(int_));
      out.append(buffer, static_cast<std::size_t>(written));
      break;
    }
    case Kind::UInt: {
      char buffer[32];
      const int written = std::snprintf(buffer, sizeof(buffer), "%llu",
                                        static_cast<unsigned long long>(uint_));
      out.append(buffer, static_cast<std::size_t>(written));
      break;
    }
    case Kind::String:
      out.push_back('"');
      append_escaped(out, string_);
      out.push_back('"');
      break;
    case Kind::Array: {
      out.push_back('[');
      for (std::size_t i = 0; i < array_.size(); ++i) {
        if (i != 0) {
          out.push_back(',');
        }
        array_[i].dump_into(out, max_bytes, depth + 1, status);
        if (!status) {
          return;
        }
      }
      out.push_back(']');
      break;
    }
    case Kind::Object: {
      out.push_back('{');
      for (std::size_t i = 0; i < object_.size(); ++i) {
        if (i != 0) {
          out.push_back(',');
        }
        out.push_back('"');
        append_escaped(out, object_[i].first);
        out.push_back('"');
        out.push_back(':');
        object_[i].second.dump_into(out, max_bytes, depth + 1, status);
        if (!status) {
          return;
        }
      }
      out.push_back('}');
      break;
    }
  }
}

Status JsonValue::dump(std::string& out, std::size_t max_bytes) const {
  out.clear();
  Status status = ok_status();
  dump_into(out, max_bytes, 0, status);
  if (!status) {
    out.clear();
    return status;
  }
  return ok_status();
}

// ---------------------------------------------------------------------------
// JsonReader
// ---------------------------------------------------------------------------

Status JsonReader::skip_whitespace() {
  while (position_ < text_.size()) {
    const char c = text_[position_];
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      ++position_;
      continue;
    }
    break;
  }
  return ok_status();
}

bool JsonReader::consume(char expected) {
  if (position_ < text_.size() && text_[position_] == expected) {
    ++position_;
    return true;
  }
  return false;
}

Result<std::string> JsonReader::parse_raw_string() {
  if (!consume('"')) {
    return Error(ReasonCode::MalformedInput, "expected string");
  }
  std::string out;
  while (position_ < text_.size()) {
    const char c = text_[position_++];
    if (c == '"') {
      return out;
    }
    if (c == '\\') {
      if (position_ >= text_.size()) {
        return Error(ReasonCode::TruncatedInput, "string escape ended early");
      }
      const char escape = text_[position_++];
      switch (escape) {
        case '"':
          out.push_back('"');
          break;
        case '\\':
          out.push_back('\\');
          break;
        case '/':
          out.push_back('/');
          break;
        case 'b':
          out.push_back('\b');
          break;
        case 'f':
          out.push_back('\f');
          break;
        case 'n':
          out.push_back('\n');
          break;
        case 'r':
          out.push_back('\r');
          break;
        case 't':
          out.push_back('\t');
          break;
        case 'u': {
          if (position_ + 4 > text_.size()) {
            return Error(ReasonCode::TruncatedInput, "unicode escape ended early");
          }
          unsigned value = 0;
          for (int i = 0; i < 4; ++i) {
            const char digit = text_[position_ + static_cast<std::size_t>(i)];
            unsigned nibble = 0;
            if (digit >= '0' && digit <= '9') {
              nibble = static_cast<unsigned>(digit - '0');
            } else if (digit >= 'a' && digit <= 'f') {
              nibble = static_cast<unsigned>(digit - 'a' + 10);
            } else if (digit >= 'A' && digit <= 'F') {
              nibble = static_cast<unsigned>(digit - 'A' + 10);
            } else {
              return Error(ReasonCode::MalformedInput, "invalid unicode escape");
            }
            value = (value << 4) | nibble;
          }
          position_ += 4;
          if (value > 0x7Fu) {
            return Error(ReasonCode::UnsupportedValue,
                         "canonical documents are ASCII: non-ascii escape refused");
          }
          out.push_back(static_cast<char>(value));
          break;
        }
        default:
          return Error(ReasonCode::MalformedInput, "invalid string escape");
      }
      continue;
    }
    const auto code = static_cast<unsigned char>(c);
    if (code < 0x20u) {
      return Error(ReasonCode::MalformedInput, "control character in string");
    }
    if (code >= 0x7Fu) {
      return Error(ReasonCode::UnsupportedValue,
                   "canonical documents are ASCII: non-ascii byte refused");
    }
    out.push_back(c);
  }
  return Error(ReasonCode::TruncatedInput, "unterminated string");
}

Result<JsonValue> JsonReader::parse_string() {
  auto raw = parse_raw_string();
  if (!raw) {
    return raw.error();
  }
  return JsonValue::string(raw.take());
}

Result<JsonValue> JsonReader::parse_number() {
  const std::size_t start = position_;
  if (position_ < text_.size() && text_[position_] == '-') {
    ++position_;
  }
  std::size_t digits = 0;
  while (position_ < text_.size()) {
    const char c = text_[position_];
    if (c < '0' || c > '9') {
      break;
    }
    ++position_;
    ++digits;
  }
  if (digits == 0) {
    return Error(ReasonCode::MalformedInput, "expected integer");
  }
  if (position_ < text_.size()) {
    const char c = text_[position_];
    if (c == '.' || c == 'e' || c == 'E') {
      return Error(ReasonCode::UnsupportedValue, "canonical documents use integers only");
    }
  }
  const std::string_view literal = text_.substr(start, position_ - start);
  if (literal.front() == '-') {
    std::int64_t value = 0;
    for (std::size_t i = 1; i < literal.size(); ++i) {
      const std::int64_t digit = static_cast<std::int64_t>(literal[i] - '0');
      std::int64_t scaled = 0;
      if (!checked_mul(value, std::int64_t{10}, scaled) ||
          !checked_sub(scaled, digit, value)) {
        return Error(ReasonCode::ArithmeticOverflow, "integer literal out of range");
      }
    }
    return JsonValue::integer(value);
  }
  std::uint64_t value = 0;
  for (const char c : literal) {
    const std::uint64_t digit = static_cast<std::uint64_t>(c - '0');
    std::uint64_t scaled = 0;
    if (!checked_mul(value, std::uint64_t{10}, scaled) ||
        !checked_add(scaled, digit, value)) {
      return Error(ReasonCode::ArithmeticOverflow, "integer literal out of range");
    }
  }
  return JsonValue::uinteger(value);
}

Result<JsonValue> JsonReader::parse_array(std::size_t depth) {
  if (!consume('[')) {
    return Error(ReasonCode::MalformedInput, "expected array");
  }
  JsonValue::Array values;
  Status status = skip_whitespace();
  if (!status) {
    return status.error();
  }
  if (consume(']')) {
    return JsonValue::array(std::move(values));
  }
  for (;;) {
    auto value = parse_value(depth + 1);
    if (!value) {
      return value.error();
    }
    values.push_back(value.take());
    status = skip_whitespace();
    if (!status) {
      return status.error();
    }
    if (consume(',')) {
      continue;
    }
    if (consume(']')) {
      return JsonValue::array(std::move(values));
    }
    return Error(ReasonCode::MalformedInput, "expected ',' or ']' in array");
  }
}

Result<JsonValue> JsonReader::parse_object(std::size_t depth) {
  if (!consume('{')) {
    return Error(ReasonCode::MalformedInput, "expected object");
  }
  JsonValue::Object members;
  Status status = skip_whitespace();
  if (!status) {
    return status.error();
  }
  if (consume('}')) {
    return JsonValue::object(std::move(members));
  }
  for (;;) {
    status = skip_whitespace();
    if (!status) {
      return status.error();
    }
    auto key = parse_raw_string();
    if (!key) {
      return key.error();
    }
    status = skip_whitespace();
    if (!status) {
      return status.error();
    }
    if (!consume(':')) {
      return Error(ReasonCode::MalformedInput, "expected ':' in object");
    }
    auto value = parse_value(depth + 1);
    if (!value) {
      return value.error();
    }
    members.emplace_back(key.take(), value.take());
    status = skip_whitespace();
    if (!status) {
      return status.error();
    }
    if (consume(',')) {
      continue;
    }
    if (consume('}')) {
      return JsonValue::object(std::move(members));
    }
    return Error(ReasonCode::MalformedInput, "expected ',' or '}' in object");
  }
}

Result<JsonValue> JsonReader::parse_value(std::size_t depth) {
  if (depth > max_depth_) {
    return Error(ReasonCode::OutOfRange, "json nesting depth exceeded");
  }
  Status status = skip_whitespace();
  if (!status) {
    return status.error();
  }
  if (position_ >= text_.size()) {
    return Error(ReasonCode::TruncatedInput, "unexpected end of json document");
  }
  const char c = text_[position_];
  if (c == '{') {
    return parse_object(depth);
  }
  if (c == '[') {
    return parse_array(depth);
  }
  if (c == '"') {
    return parse_string();
  }
  if (c == '-' || (c >= '0' && c <= '9')) {
    return parse_number();
  }
  if (text_.compare(position_, 4, "null") == 0) {
    position_ += 4;
    return JsonValue::null();
  }
  if (text_.compare(position_, 4, "true") == 0) {
    position_ += 4;
    return JsonValue::boolean(true);
  }
  if (text_.compare(position_, 5, "false") == 0) {
    position_ += 5;
    return JsonValue::boolean(false);
  }
  return Error(ReasonCode::MalformedInput, "unexpected json token");
}

Result<JsonValue> JsonReader::parse() {
  auto value = parse_value(0);
  if (!value) {
    return value.error();
  }
  Status status = skip_whitespace();
  if (!status) {
    return status.error();
  }
  if (position_ != text_.size()) {
    return Error(ReasonCode::MalformedInput, "trailing content after json document");
  }
  return value;
}

}  // namespace nof
