#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "nof/error.hpp"
#include "nof/ids.hpp"

// Function identities and the semantics a function requires from a target.
// The fabric never infers a semantic from a device kind, a device name, or a
// sibling capability: only an explicit capability claim can satisfy an
// explicitly required semantic.
namespace nof {

enum class FunctionClass : std::uint16_t {
  RouteLookup = 1,
  AccessControl = 2,
  ConnectionTracking = 3,
  Encapsulation = 4,
  LoadBalancing = 5,
  CryptoOffload = 6,
  RateLimiting = 7,
  Timestamping = 8,
  PacketCapture = 9,
  QueueSteering = 10,
  MemoryRegistration = 11,
  ChecksumOffload = 12,
  TrafficMetering = 13,
  PacketFiltering = 14,
  HeaderRewrite = 15,
  ReplicationMirroring = 16,
};

const char* to_string(FunctionClass value) noexcept;
bool parse_function_class(std::string_view token, FunctionClass& out) noexcept;

// Execution semantics. Numeric values are durable: they appear in persisted
// capability records and in canonical exports.
enum class Semantic : std::uint8_t {
  LineRateDeterministic = 0,
  ProgrammablePipeline = 1,
  StatefulFlowTable = 2,
  PerFlowCounters = 3,
  HardwareTimestamps = 4,
  InlineCrypto = 5,
  RdmaCapable = 6,
  KernelBypass = 7,
  HeaderRewriteCapable = 8,
  MulticastReplication = 9,
  OrderingPreserving = 10,
  JumboFrames = 11,
  VlanAware = 12,
  TunnelEncapsulation = 13,
  TrafficShaping = 14,
  FailOpen = 15,
  PersistentAcrossReboot = 16,
  AtomicFlowUpdate = 17,
  FlowAgingOffload = 18,
  QueuePartitioning = 19,
  MemoryRegistrationCache = 20,
  ChecksumOffloadCapable = 21,
  LargeRuleCapacity = 22,
  SramTableLookup = 23,
  PerQueueRateLimit = 24,
  SampledMirroring = 25,
};

inline constexpr std::size_t kSemanticCount = 26;
static_assert(kSemanticCount <= 64, "semantics must fit in a 64-bit mask");

const char* to_string(Semantic value) noexcept;
bool parse_semantic(std::string_view token, Semantic& out) noexcept;

// A set of semantics. Iteration is always in ascending semantic order so that
// canonical encodings and explanations are stable.
class SemanticsMask {
 public:
  SemanticsMask() = default;

  static Result<SemanticsMask> from_tokens(const std::vector<std::string>& tokens);

  void set(Semantic value) noexcept { bits_ |= mask_of(value); }
  void clear(Semantic value) noexcept { bits_ &= ~mask_of(value); }
  void clear_all() noexcept { bits_ = 0; }
  bool test(Semantic value) const noexcept { return (bits_ & mask_of(value)) != 0; }
  bool empty() const noexcept { return bits_ == 0; }
  std::uint64_t bits() const noexcept { return bits_; }
  void set_bits(std::uint64_t bits) noexcept { bits_ = bits; }
  std::size_t count() const noexcept;
  std::vector<Semantic> values() const;

  // Bits present in this mask but not in `other`.
  SemanticsMask difference(const SemanticsMask& other) const noexcept {
    return from_bits(bits_ & ~other.bits_);
  }
  SemanticsMask intersection(const SemanticsMask& other) const noexcept {
    return from_bits(bits_ & other.bits_);
  }
  SemanticsMask unite(const SemanticsMask& other) const noexcept {
    return from_bits(bits_ | other.bits_);
  }
  bool is_subset_of(const SemanticsMask& other) const noexcept {
    return (bits_ & ~other.bits_) == 0;
  }
  bool contains_any(const SemanticsMask& other) const noexcept {
    return (bits_ & other.bits_) != 0;
  }

  static SemanticsMask from_bits(std::uint64_t bits) noexcept;

  friend bool operator==(const SemanticsMask&, const SemanticsMask&) = default;

 private:
  static constexpr std::uint64_t mask_of(Semantic value) noexcept {
    return std::uint64_t{1} << static_cast<std::uint64_t>(value);
  }

  std::uint64_t bits_ = 0;
};

struct SemanticVersion {
  std::uint16_t major = 0;
  std::uint16_t minor = 0;

  friend bool operator==(const SemanticVersion&, const SemanticVersion&) = default;
  friend std::strong_ordering operator<=>(const SemanticVersion&, const SemanticVersion&) = default;

  std::string to_string() const;
  static Result<SemanticVersion> parse(std::string_view text);
};

// Inclusive range of semantic versions a capability implementation supports.
struct VersionRange {
  SemanticVersion minimum{};
  SemanticVersion maximum{};

  bool admits(const SemanticVersion& version) const noexcept {
    return !(version < minimum) && !(version > maximum);
  }

  friend bool operator==(const VersionRange&, const VersionRange&) = default;
};

// A registered function: what it is, what it needs, and how exclusivity is
// derived for the scopes it governs.
struct FunctionDescriptor {
  FunctionId id{};
  FunctionClass cls = FunctionClass::RouteLookup;
  SemanticsMask required{};
  SemanticVersion required_version{};
  bool exclusive_by_default = true;

  friend bool operator==(const FunctionDescriptor&, const FunctionDescriptor&) = default;
};

}  // namespace nof
