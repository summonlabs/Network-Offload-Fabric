#include "nof/error.hpp"

#include <cstdio>
#include <cstring>

namespace nof {

#define NOF_REASON_CODES(X)              \
  X(Ok, "OK")                            \
  X(HostFallbackApplied, "HOST_FALLBACK_APPLIED") \
  X(IdempotentDuplicate, "IDEMPOTENT_DUPLICATE") \
  X(AppliedVerified, "APPLIED_VERIFIED") \
  X(AcknowledgedNotApplied, "ACKNOWLEDGED_NOT_APPLIED") \
  X(TruncatedResult, "TRUNCATED_RESULT") \
  X(EvictedEntry, "EVICTED_ENTRY")       \
  X(SupersededPlan, "SUPERSEDED_PLAN")   \
  X(MalformedInput, "MALFORMED_INPUT")   \
  X(TruncatedInput, "TRUNCATED_INPUT")   \
  X(OversizedInput, "OVERSIZED_INPUT")   \
  X(IntegrityFailure, "INTEGRITY_FAILURE") \
  X(IncompatibleVersion, "INCOMPATIBLE_VERSION") \
  X(SemanticsMismatch, "SEMANTICS_MISMATCH") \
  X(UnsupportedValue, "UNSUPPORTED_VALUE") \
  X(InvalidIdentifier, "INVALID_IDENTIFIER") \
  X(DuplicateIdentity, "DUPLICATE_IDENTITY") \
  X(OutOfRange, "OUT_OF_RANGE")          \
  X(ArithmeticOverflow, "ARITHMETIC_OVERFLOW") \
  X(UnknownIdentity, "UNKNOWN_IDENTITY") \
  X(NotFound, "NOT_FOUND")               \
  X(AlreadyExists, "ALREADY_EXISTS")     \
  X(SequenceRegression, "SEQUENCE_REGRESSION") \
  X(EmptyInput, "EMPTY_INPUT")           \
  X(EvidenceMissing, "EVIDENCE_MISSING") \
  X(EvidenceStale, "EVIDENCE_STALE")     \
  X(EvidenceSuperseded, "EVIDENCE_SUPERSEDED") \
  X(EvidenceConflicting, "EVIDENCE_CONFLICTING") \
  X(EvidenceUnknown, "EVIDENCE_UNKNOWN") \
  X(GenerationMismatch, "GENERATION_MISMATCH") \
  X(IncarnationMismatch, "INCARNATION_MISMATCH") \
  X(TopologyStale, "TOPOLOGY_STALE")     \
  X(PolicyStale, "POLICY_STALE")         \
  X(CapabilityStale, "CAPABILITY_STALE") \
  X(CapabilityUnknown, "CAPABILITY_UNKNOWN") \
  X(ProvenanceMismatch, "PROVENANCE_MISMATCH") \
  X(LivenessUnknown, "LIVENESS_UNKNOWN") \
  X(LivenessStale, "LIVENESS_STALE")     \
  X(ObservationExpired, "OBSERVATION_EXPIRED") \
  X(LivenessDegraded, "LIVENESS_DEGRADED") \
  X(LivenessDead, "LIVENESS_DEAD") \
  X(CapabilityUnsupported, "CAPABILITY_UNSUPPORTED") \
  X(CapabilityIncompatible, "CAPABILITY_INCOMPATIBLE") \
  X(RefusedByPolicy, "REFUSED_BY_POLICY") \
  X(AuthorityMissing, "AUTHORITY_MISSING") \
  X(AuthorityExpired, "AUTHORITY_EXPIRED") \
  X(AuthorityScopeMismatch, "AUTHORITY_SCOPE_MISMATCH") \
  X(AuthorityWithdrawn, "AUTHORITY_WITHDRAWN") \
  X(NotAuthorized, "NOT_AUTHORIZED")     \
  X(AntiAffinityViolation, "ANTI_AFFINITY_VIOLATION") \
  X(AffinityUnsatisfied, "AFFINITY_UNSATISFIED") \
  X(CapacityExhausted, "CAPACITY_EXHAUSTED") \
  X(DependencyUnresolved, "DEPENDENCY_UNRESOLVED") \
  X(DependencyFailed, "DEPENDENCY_FAILED") \
  X(DependencyCycle, "DEPENDENCY_CYCLE") \
  X(HostFallbackNotPermitted, "HOST_FALLBACK_NOT_PERMITTED") \
  X(FunctionClassNotPermitted, "FUNCTION_CLASS_NOT_PERMITTED") \
  X(DeviceKindNotPermitted, "DEVICE_KIND_NOT_PERMITTED") \
  X(NoEligibleTarget, "NO_ELIGIBLE_TARGET") \
  X(ExclusiveConflict, "EXCLUSIVE_CONFLICT") \
  X(TargetDisappeared, "TARGET_DISAPPEARED") \
  X(ReassignmentBudgetExhausted, "REASSIGNMENT_BUDGET_EXHAUSTED") \
  X(ScopeConflict, "SCOPE_CONFLICT")     \
  X(PlanSuperseded, "PLAN_SUPERSEDED")   \
  X(PlacementRefused, "PLACEMENT_REFUSED") \
  X(IllegalStateTransition, "ILLEGAL_STATE_TRANSITION") \
  X(LeaseExpired, "LEASE_EXPIRED")       \
  X(LeaseNotHeld, "LEASE_NOT_HELD")      \
  X(FencedAttempt, "FENCED_ATTEMPT")     \
  X(EpochStale, "EPOCH_STALE")           \
  X(ReplayDetected, "REPLAY_DETECTED")   \
  X(EffectRejected, "EFFECT_REJECTED")   \
  X(EffectFailed, "EFFECT_FAILED")       \
  X(EffectUnknown, "EFFECT_UNKNOWN")     \
  X(Revoked, "REVOKED")                  \
  X(Superseded, "SUPERSEDED")            \
  X(AttemptMismatch, "ATTEMPT_MISMATCH") \
  X(AssignmentNotActive, "ASSIGNMENT_NOT_ACTIVE") \
  X(FenceRegression, "FENCE_REGRESSION") \
  X(StoreUnavailable, "STORE_UNAVAILABLE") \
  X(StoreCorrupt, "STORE_CORRUPT")       \
  X(StoreTruncated, "STORE_TRUNCATED")   \
  X(JournalTornTail, "JOURNAL_TORN_TAIL") \
  X(IncompatibleSemantics, "INCOMPATIBLE_SEMANTICS") \
  X(CompactionRequired, "COMPACTION_REQUIRED") \
  X(RecoveryRequired, "RECOVERY_REQUIRED") \
  X(RestartAuthorityReset, "RESTART_AUTHORITY_RESET") \
  X(ObservationStaleAfterRestart, "OBSERVATION_STALE_AFTER_RESTART") \
  X(CrashBoundaryInjected, "CRASH_BOUNDARY_INJECTED") \
  X(StoreClosed, "STORE_CLOSED")         \
  X(FrameInvalid, "FRAME_INVALID")       \
  X(UnsupportedOpcode, "UNSUPPORTED_OPCODE") \
  X(ProtocolVersionMismatch, "PROTOCOL_VERSION_MISMATCH") \
  X(PayloadTooLarge, "PAYLOAD_TOO_LARGE") \
  X(PeerClosed, "PEER_CLOSED")           \
  X(ConnectionRefused, "CONNECTION_REFUSED") \
  X(DuplicateDelivery, "DUPLICATE_DELIVERY") \
  X(RequestDigestMismatch, "REQUEST_DIGEST_MISMATCH") \
  X(EndpointInvalid, "ENDPOINT_INVALID") \
  X(ConnectionLimitExceeded, "CONNECTION_LIMIT_EXCEEDED") \
  X(ResponseTooLarge, "RESPONSE_TOO_LARGE") \
  X(Cancelled, "CANCELLED")              \
  X(ShuttingDown, "SHUTTING_DOWN")       \
  X(LimitExceeded, "LIMIT_EXCEEDED")     \
  X(QueueFull, "QUEUE_FULL")             \
  X(InternalInvariant, "INTERNAL_INVARIANT") \
  X(UnsupportedOperation, "UNSUPPORTED_OPERATION") \
  X(WorkerUnavailable, "WORKER_UNAVAILABLE") \
  X(InvalidConfiguration, "INVALID_CONFIGURATION")

const char* to_string(ReasonCode code) noexcept {
  switch (code) {
#define NOF_REASON_CASE(name, token) \
  case ReasonCode::name:             \
    return token;
    NOF_REASON_CODES(NOF_REASON_CASE)
#undef NOF_REASON_CASE
  }
  return "UNKNOWN_REASON";
}

const char* to_string(ReasonCategory category) noexcept {
  switch (category) {
    case ReasonCategory::Ok:
      return "OK";
    case ReasonCategory::Informational:
      return "INFORMATIONAL";
    case ReasonCategory::Refusal:
      return "REFUSAL";
    case ReasonCategory::Recovery:
      return "RECOVERY";
  }
  return "UNKNOWN_CATEGORY";
}

ReasonCategory category_of(ReasonCode code) noexcept {
  const std::uint16_t value = static_cast<std::uint16_t>(code);
  if (value == 0x0000u) {
    return ReasonCategory::Ok;
  }
  if (value < 0x0100u) {
    return ReasonCategory::Informational;
  }
  if (value >= 0x0600u && value < 0x0700u) {
    switch (code) {
      case ReasonCode::JournalTornTail:
      case ReasonCode::RestartAuthorityReset:
      case ReasonCode::ObservationStaleAfterRestart:
      case ReasonCode::CrashBoundaryInjected:
        return ReasonCategory::Recovery;
      default:
        return ReasonCategory::Refusal;
    }
  }
  return ReasonCategory::Refusal;
}

bool is_refusal(ReasonCode code) noexcept { return category_of(code) == ReasonCategory::Refusal; }

bool is_recovery_classification(ReasonCode code) noexcept {
  return category_of(code) == ReasonCategory::Recovery;
}

bool parse_reason_code(std::string_view token, ReasonCode& out) noexcept {
  struct Entry {
    const char* token;
    ReasonCode code;
  };
  static const Entry table[] = {
#define NOF_REASON_ENTRY(name, text) Entry{text, ReasonCode::name},
      NOF_REASON_CODES(NOF_REASON_ENTRY)
#undef NOF_REASON_ENTRY
  };
  for (const Entry& entry : table) {
    const std::string_view candidate(entry.token);
    if (candidate.size() == token.size() && candidate == token) {
      out = entry.code;
      return true;
    }
  }
  return false;
}

Error make_error(ReasonCode code, std::string detail) {
  Error error;
  error.code = code;
  error.detail = std::move(detail);
  return error;
}

Error make_error(ReasonCode code) { return Error(code); }

std::string to_string(const Error& err) {
  std::string out(to_string(err.code));
  if (!err.detail.empty()) {
    out += ": ";
    out += err.detail;
  }
  return out;
}

}  // namespace nof
