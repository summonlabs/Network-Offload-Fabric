#pragma once

#include <compare>
#include <cstdint>
#include <string>
#include <string_view>

#include "nof/checked.hpp"
#include "nof/error.hpp"

// Strongly typed identities. Nothing correctness-critical is passed around as
// a bare string, integer, or pair of integers: identity kind, units, and
// generation domains are encoded in the type so that a host identifier can
// never be used where a device identifier is required, and a topology
// generation can never be compared against a policy generation.
namespace nof {

namespace tokens {

inline constexpr std::size_t kMaxTokenLength = 64;
inline constexpr std::size_t kBootIdLength = 32;
inline constexpr std::size_t kMaxSelectorLength = 192;

// Canonical token rule: 1..64 characters, first character [a-z0-9], remaining
// characters [a-z0-9._:-]. Uppercase is refused rather than folded so that two
// spellings of the same identity can never coexist in durable state.
bool is_valid_token(std::string_view text) noexcept;

// Lowercase hexadecimal of an exact length.
bool is_lower_hex(std::string_view text, std::size_t length) noexcept;

// Canonical selector text: 1..192 characters from [a-z0-9._:=-].
bool is_valid_selector(std::string_view text) noexcept;

}  // namespace tokens

template <class Tag>
class Token {
 public:
  Token() = default;

  static Result<Token> parse(std::string_view text) {
    if (!tokens::is_valid_token(text)) {
      return Error(ReasonCode::InvalidIdentifier, std::string("invalid token"));
    }
    return Token(std::string(text));
  }

  // Precondition: text already satisfies the canonical token rule. Used by
  // trusted construction paths and by parsers that validated the token while
  // reading a record.
  static Token from_validated(std::string text) {
    Token out;
    out.value_ = std::move(text);
    return out;
  }

  const std::string& value() const noexcept { return value_; }
  std::string_view view() const noexcept { return value_; }
  bool empty() const noexcept { return value_.empty(); }
  bool is_set() const noexcept { return !value_.empty(); }

  friend bool operator==(const Token&, const Token&) = default;
  friend std::strong_ordering operator<=>(const Token&, const Token&) = default;

 private:
  explicit Token(std::string value) : value_(std::move(value)) {}

  std::string value_;
};

template <class Tag>
struct TokenHash {
  std::size_t operator()(const Token<Tag>& token) const noexcept {
    // FNV-1a 64 over the canonical token bytes. Hashing is used only for
    // lookup; every output ordering is established by canonical comparison.
    std::uint64_t h = 1469598103934665603ULL;
    for (const char c : token.value()) {
      h ^= static_cast<std::uint64_t>(static_cast<unsigned char>(c));
      h *= 1099511628211ULL;
    }
    return static_cast<std::size_t>(h);
  }
};

// Identity domains.
struct HostTag;
struct DeviceTag;
struct FunctionTag;
struct ScopeTag;
struct SourceTag;
struct AuthorityTag;
struct AssignmentTag;
struct RequestTag;
struct PolicyTag;
struct BootTag;
struct StoreTag;

using HostId = Token<HostTag>;
using DeviceId = Token<DeviceTag>;
using FunctionId = Token<FunctionTag>;
using ScopeId = Token<ScopeTag>;
using SourceId = Token<SourceTag>;
using AuthorityId = Token<AuthorityTag>;
using AssignmentId = Token<AssignmentTag>;
using RequestId = Token<RequestTag>;
using PolicyId = Token<PolicyTag>;
using StoreId = Token<StoreTag>;

// A boot identity is 32 lowercase hex characters generated once per process
// start. It is embedded in coordinator epochs and device incarnations so that
// authority minted before a restart can never be mistaken for current.
class BootId {
 public:
  BootId() = default;

  static Result<BootId> parse(std::string_view text) {
    if (!tokens::is_lower_hex(text, tokens::kBootIdLength)) {
      return Error(ReasonCode::InvalidIdentifier, "boot id must be 32 lowercase hex characters");
    }
    BootId out;
    out.value_ = std::string(text);
    return out;
  }

  static BootId from_validated(std::string text) {
    BootId out;
    out.value_ = std::move(text);
    return out;
  }

  static BootId generate(std::uint64_t entropy_a, std::uint64_t entropy_b);

  const std::string& value() const noexcept { return value_; }
  std::string_view view() const noexcept { return value_; }
  bool is_set() const noexcept { return value_.size() == tokens::kBootIdLength; }

  friend bool operator==(const BootId&, const BootId&) = default;
  friend std::strong_ordering operator<=>(const BootId&, const BootId&) = default;

 private:
  std::string value_;
};

// Generation domains. Generation value zero means "unset" and is never a
// current generation: an unset generation can therefore never authorize
// anything.
struct TopologyGenTag;
struct CapabilityGenTag;
struct PolicyGenTag;
struct AssignmentGenTag;
struct SchemaGenTag;
struct StoreGenTag;
struct LeaseGenTag;
struct AttemptGenTag;
struct IncarnationGenTag;

template <class Tag>
class Gen {
 public:
  Gen() = default;

  static Gen unset() noexcept { return Gen(); }

  static Result<Gen> from_u64(std::uint64_t value) {
    if (value == 0) {
      return Error(ReasonCode::OutOfRange, "generation zero is reserved for unset");
    }
    Gen out;
    out.value_ = value;
    return out;
  }

  static Gen from_validated(std::uint64_t value) noexcept {
    Gen out;
    out.value_ = value;
    return out;
  }

  bool is_set() const noexcept { return value_ != 0; }
  std::uint64_t value() const noexcept { return value_; }

  Result<Gen> next() const {
    std::uint64_t next_value = 0;
    if (!checked_add(value_, std::uint64_t{1}, next_value) || next_value == 0) {
      return Error(ReasonCode::ArithmeticOverflow, "generation exhausted");
    }
    return Gen::from_validated(next_value);
  }

  friend bool operator==(const Gen&, const Gen&) = default;
  friend std::strong_ordering operator<=>(const Gen&, const Gen&) = default;

 private:
  std::uint64_t value_ = 0;
};

using TopologyGeneration = Gen<TopologyGenTag>;
using CapabilityGeneration = Gen<CapabilityGenTag>;
using PolicyGeneration = Gen<PolicyGenTag>;
using AssignmentGeneration = Gen<AssignmentGenTag>;
using SchemaGeneration = Gen<SchemaGenTag>;
using StoreGeneration = Gen<StoreGenTag>;
using LeaseId = Gen<LeaseGenTag>;
using AttemptId = Gen<AttemptGenTag>;
using IncarnationGeneration = Gen<IncarnationGenTag>;

// Coordinator epoch: (durable boot counter, boot identity). The counter is
// persisted and advanced on every start, so an epoch from a previous process
// lifetime always orders strictly below the current epoch.
struct CoordinatorEpoch {
  std::uint64_t counter = 0;
  BootId boot{};

  bool is_set() const noexcept { return counter != 0 && boot.is_set(); }

  friend bool operator==(const CoordinatorEpoch&, const CoordinatorEpoch&) = default;
  friend std::strong_ordering operator<=>(const CoordinatorEpoch&, const CoordinatorEpoch&) = default;
};

// Fencing token: strictly ordered (epoch, sequence). Sequence restarts at 1 for
// each new epoch, and epochs strictly increase across restarts, so a token from
// a previous process lifetime can never compare greater than a current token.
struct FencingToken {
  std::uint64_t epoch = 0;
  std::uint64_t sequence = 0;

  bool is_set() const noexcept { return epoch != 0 && sequence != 0; }

  friend bool operator==(const FencingToken&, const FencingToken&) = default;
  friend std::strong_ordering operator<=>(const FencingToken&, const FencingToken&) = default;
};

// Device incarnation: the durable ordinal assigned by the device owner plus the
// boot identity of the device agent. A device that reboots presents a new boot
// id, hence a new incarnation, and all authority bound to the previous
// incarnation is stale even if the ordinal was reused by a broken reporter.
struct IncarnationId {
  IncarnationGeneration generation{};
  BootId boot{};

  bool is_set() const noexcept { return generation.is_set() && boot.is_set(); }

  friend bool operator==(const IncarnationId&, const IncarnationId&) = default;
  friend std::strong_ordering operator<=>(const IncarnationId&, const IncarnationId&) = default;
};

// Provenance of an evidence record: which adjacent runtime produced it and the
// monotonic sequence that runtime assigned. Sequence regression from the same
// source is refused so superseded evidence can never be replayed as current.
struct Provenance {
  SourceId source{};
  std::uint64_t sequence = 0;

  bool is_set() const noexcept { return source.is_set() && sequence != 0; }

  friend bool operator==(const Provenance&, const Provenance&) = default;
  friend std::strong_ordering operator<=>(const Provenance&, const Provenance&) = default;
};

// Digest type used by every canonical export, request fingerprint, and state
// fingerprint. Declared here to keep identity surfaces together.
struct Digest {
  std::uint8_t bytes[32] = {};

  static Digest zero() noexcept { return Digest{}; }
  bool is_zero() const noexcept;

  friend bool operator==(const Digest&, const Digest&) = default;
  friend std::strong_ordering operator<=>(const Digest&, const Digest&) = default;

  std::string hex() const;
  static Result<Digest> from_hex(std::string_view text);
};

}  // namespace nof
