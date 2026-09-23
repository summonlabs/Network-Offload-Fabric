#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <string>
#include <string_view>
#include <utility>

namespace nof {

// Stable, explicitly numbered reason codes. The numeric values are part of the
// durable contract: they appear in persistence records, on the wire, and in
// canonical exports. Values are never reused or renumbered.
//
// Bands:
//   0x00xx informational outcomes
//   0x01xx input validation / representation
//   0x02xx evidence, generation, freshness, provenance
//   0x03xx policy, authority, capability eligibility
//   0x04xx placement, conflict, bounded reassignment
//   0x05xx lifecycle, lease, fencing, enforcement effects
//   0x06xx persistence, integrity, recovery
//   0x07xx transport, framing, protocol
//   0x08xx runtime lifecycle and resource bounds
enum class ReasonCode : std::uint16_t {
  Ok = 0x0000,
  HostFallbackApplied = 0x0001,
  IdempotentDuplicate = 0x0002,
  AppliedVerified = 0x0003,
  AcknowledgedNotApplied = 0x0004,
  TruncatedResult = 0x0005,
  EvictedEntry = 0x0006,
  SupersededPlan = 0x0007,

  MalformedInput = 0x0100,
  TruncatedInput = 0x0101,
  OversizedInput = 0x0102,
  IntegrityFailure = 0x0103,
  IncompatibleVersion = 0x0104,
  SemanticsMismatch = 0x0105,
  UnsupportedValue = 0x0106,
  InvalidIdentifier = 0x0107,
  DuplicateIdentity = 0x0108,
  OutOfRange = 0x0109,
  ArithmeticOverflow = 0x010A,
  UnknownIdentity = 0x010B,
  NotFound = 0x010C,
  AlreadyExists = 0x010D,
  SequenceRegression = 0x010E,
  EmptyInput = 0x010F,

  EvidenceMissing = 0x0200,
  EvidenceStale = 0x0201,
  EvidenceSuperseded = 0x0202,
  EvidenceConflicting = 0x0203,
  EvidenceUnknown = 0x0204,
  GenerationMismatch = 0x0205,
  IncarnationMismatch = 0x0206,
  TopologyStale = 0x0207,
  PolicyStale = 0x0208,
  CapabilityStale = 0x0209,
  CapabilityUnknown = 0x020A,
  ProvenanceMismatch = 0x020B,
  LivenessUnknown = 0x020C,
  LivenessStale = 0x020D,
  ObservationExpired = 0x020E,
  LivenessDegraded = 0x020F,
  LivenessDead = 0x0210,

  CapabilityUnsupported = 0x0300,
  CapabilityIncompatible = 0x0301,
  RefusedByPolicy = 0x0302,
  AuthorityMissing = 0x0303,
  AuthorityExpired = 0x0304,
  AuthorityScopeMismatch = 0x0305,
  AuthorityWithdrawn = 0x0306,
  NotAuthorized = 0x0307,
  AntiAffinityViolation = 0x0308,
  AffinityUnsatisfied = 0x0309,
  CapacityExhausted = 0x030A,
  DependencyUnresolved = 0x030B,
  DependencyFailed = 0x030C,
  DependencyCycle = 0x030D,
  HostFallbackNotPermitted = 0x030E,
  FunctionClassNotPermitted = 0x030F,
  DeviceKindNotPermitted = 0x0310,

  NoEligibleTarget = 0x0400,
  ExclusiveConflict = 0x0401,
  TargetDisappeared = 0x0402,
  ReassignmentBudgetExhausted = 0x0403,
  ScopeConflict = 0x0404,
  PlanSuperseded = 0x0405,
  PlacementRefused = 0x0406,

  IllegalStateTransition = 0x0500,
  LeaseExpired = 0x0501,
  LeaseNotHeld = 0x0502,
  FencedAttempt = 0x0503,
  EpochStale = 0x0504,
  ReplayDetected = 0x0505,
  EffectRejected = 0x0506,
  EffectFailed = 0x0507,
  EffectUnknown = 0x0508,
  Revoked = 0x0509,
  Superseded = 0x050A,
  AttemptMismatch = 0x050B,
  AssignmentNotActive = 0x050C,
  FenceRegression = 0x050D,

  StoreUnavailable = 0x0600,
  StoreCorrupt = 0x0601,
  StoreTruncated = 0x0602,
  JournalTornTail = 0x0603,
  IncompatibleSemantics = 0x0604,
  CompactionRequired = 0x0605,
  RecoveryRequired = 0x0606,
  RestartAuthorityReset = 0x0607,
  ObservationStaleAfterRestart = 0x0608,
  CrashBoundaryInjected = 0x0609,
  StoreClosed = 0x060A,

  FrameInvalid = 0x0700,
  UnsupportedOpcode = 0x0701,
  ProtocolVersionMismatch = 0x0702,
  PayloadTooLarge = 0x0703,
  PeerClosed = 0x0704,
  ConnectionRefused = 0x0705,
  DuplicateDelivery = 0x0706,
  RequestDigestMismatch = 0x0707,
  EndpointInvalid = 0x0708,
  ConnectionLimitExceeded = 0x0709,
  ResponseTooLarge = 0x070A,

  Cancelled = 0x0800,
  ShuttingDown = 0x0801,
  LimitExceeded = 0x0802,
  QueueFull = 0x0803,
  InternalInvariant = 0x0804,
  UnsupportedOperation = 0x0805,
  WorkerUnavailable = 0x0806,
  InvalidConfiguration = 0x0807,
};

enum class ReasonCategory : std::uint8_t {
  Ok = 0,
  Informational = 1,
  Refusal = 2,
  Recovery = 3,
};

// Canonical SCREAMING_SNAKE token for a reason code. Stable across releases.
const char* to_string(ReasonCode code) noexcept;

// Canonical token for a reason category.
const char* to_string(ReasonCategory category) noexcept;

ReasonCategory category_of(ReasonCode code) noexcept;

// True when the code denotes a refusal (no state change was accepted).
bool is_refusal(ReasonCode code) noexcept;

// True when the code denotes a recovery classification rather than a refusal.
bool is_recovery_classification(ReasonCode code) noexcept;

// Strict parse of a canonical reason token. Refuses unknown tokens and
// non-canonical spellings; never guesses.
bool parse_reason_code(std::string_view token, ReasonCode& out) noexcept;

struct Error {
  ReasonCode code = ReasonCode::Ok;
  std::string detail;

  Error() = default;
  explicit Error(ReasonCode c) : code(c) {}
  Error(ReasonCode c, std::string d) : code(c), detail(std::move(d)) {}

  bool ok() const noexcept { return code == ReasonCode::Ok; }
  explicit operator bool() const noexcept { return !ok(); }
};

Error make_error(ReasonCode code, std::string detail);
Error make_error(ReasonCode code);

// Thrown when value() is called on a Result that holds a refusal. A refusal is
// not an empty value: reading one is a programming error, and it is reported as
// such instead of returning a default-constructed object.
class BadResultAccess : public std::logic_error {
 public:
  explicit BadResultAccess(const char* what) : std::logic_error(what) {}
};

// Canonical single-line rendering: "<CODE>: <detail>" or "<CODE>".
std::string to_string(const Error& err);

// Result<T>: value-or-error without exceptions in the control path.
template <class T>
class Result {
 public:
  // The value constructor is constrained so that Result<Error> remains
  // well-formed and so that a refusal can never be confused with a value.
  template <class U = T, class = std::enable_if_t<!std::is_same_v<U, Error>>>
  Result(T value) : value_(std::move(value)) {}          // NOLINT(google-explicit-constructor)
  Result(Error err) : error_(std::move(err)) {}          // NOLINT(google-explicit-constructor)

  bool ok() const noexcept { return value_.has_value(); }
  explicit operator bool() const noexcept { return ok(); }

  const T& value() const {
    if (!value_) {
      throw BadResultAccess("Result::value() called on a refusal");
    }
    return *value_;
  }
  T& value() {
    if (!value_) {
      throw BadResultAccess("Result::value() called on a refusal");
    }
    return *value_;
  }
  T&& take() {
    if (!value_) {
      throw BadResultAccess("Result::take() called on a refusal");
    }
    return std::move(*value_);
  }

  const Error& error() const noexcept { return error_; }

  const T& operator*() const { return value(); }
  T& operator*() { return value(); }
  const T* operator->() const { return &value(); }
  T* operator->() { return &value(); }

 private:
  std::optional<T> value_;
  Error error_;
};

template <>
class Result<void> {
 public:
  Result() = default;
  Result(Error err) : error_(std::move(err)) {}          // NOLINT(google-explicit-constructor)

  bool ok() const noexcept { return error_.code == ReasonCode::Ok; }
  explicit operator bool() const noexcept { return ok(); }

  const Error& error() const noexcept { return error_; }

 private:
  Error error_;
};

using Status = Result<void>;

inline Status ok_status() noexcept { return Status(); }

}  // namespace nof
