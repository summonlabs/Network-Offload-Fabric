#include "nof/assignment.hpp"

#include "nof/canonical.hpp"
#include "nof/wire.hpp"

namespace nof {

const char* to_string(Exclusivity value) noexcept {
  switch (value) {
    case Exclusivity::Shared:
      return "shared";
    case Exclusivity::Exclusive:
      return "exclusive";
  }
  return "unknown_exclusivity";
}

bool parse_exclusivity(std::string_view token, Exclusivity& out) noexcept {
  if (token == "shared") {
    out = Exclusivity::Shared;
  } else if (token == "exclusive") {
    out = Exclusivity::Exclusive;
  } else {
    return false;
  }
  return true;
}

const char* to_string(ExecutionMode value) noexcept {
  switch (value) {
    case ExecutionMode::Offloaded:
      return "offloaded";
    case ExecutionMode::HostFallback:
      return "host_fallback";
  }
  return "unknown_execution_mode";
}

bool parse_execution_mode(std::string_view token, ExecutionMode& out) noexcept {
  if (token == "offloaded") {
    out = ExecutionMode::Offloaded;
  } else if (token == "host_fallback") {
    out = ExecutionMode::HostFallback;
  } else {
    return false;
  }
  return true;
}

const char* to_string(AssignmentState value) noexcept {
  switch (value) {
    case AssignmentState::Planned:
      return "planned";
    case AssignmentState::Authorized:
      return "authorized";
    case AssignmentState::Dispatched:
      return "dispatched";
    case AssignmentState::Acknowledged:
      return "acknowledged";
    case AssignmentState::AppliedVerified:
      return "applied_verified";
    case AssignmentState::Degraded:
      return "degraded";
    case AssignmentState::Suspended:
      return "suspended";
    case AssignmentState::Revoked:
      return "revoked";
    case AssignmentState::Superseded:
      return "superseded";
    case AssignmentState::Rejected:
      return "rejected";
    case AssignmentState::Failed:
      return "failed";
  }
  return "unknown_assignment_state";
}

bool parse_assignment_state(std::string_view token, AssignmentState& out) noexcept {
  if (token == "planned") {
    out = AssignmentState::Planned;
  } else if (token == "authorized") {
    out = AssignmentState::Authorized;
  } else if (token == "dispatched") {
    out = AssignmentState::Dispatched;
  } else if (token == "acknowledged") {
    out = AssignmentState::Acknowledged;
  } else if (token == "applied_verified") {
    out = AssignmentState::AppliedVerified;
  } else if (token == "degraded") {
    out = AssignmentState::Degraded;
  } else if (token == "suspended") {
    out = AssignmentState::Suspended;
  } else if (token == "revoked") {
    out = AssignmentState::Revoked;
  } else if (token == "superseded") {
    out = AssignmentState::Superseded;
  } else if (token == "rejected") {
    out = AssignmentState::Rejected;
  } else if (token == "failed") {
    out = AssignmentState::Failed;
  } else {
    return false;
  }
  return true;
}

bool holds_authority(AssignmentState state) noexcept {
  switch (state) {
    case AssignmentState::Authorized:
    case AssignmentState::Dispatched:
    case AssignmentState::Acknowledged:
    case AssignmentState::AppliedVerified:
      return true;
    default:
      return false;
  }
}

bool is_live(AssignmentState state) noexcept {
  switch (state) {
    case AssignmentState::Authorized:
    case AssignmentState::Dispatched:
    case AssignmentState::Acknowledged:
    case AssignmentState::AppliedVerified:
    case AssignmentState::Degraded:
    case AssignmentState::Suspended:
    case AssignmentState::Planned:
      return true;
    default:
      return false;
  }
}

bool is_terminal(AssignmentState state) noexcept {
  switch (state) {
    case AssignmentState::Revoked:
    case AssignmentState::Superseded:
    case AssignmentState::Rejected:
    case AssignmentState::Failed:
      return true;
    default:
      return false;
  }
}

const char* to_string(EffectOutcome value) noexcept {
  switch (value) {
    case EffectOutcome::Applied:
      return "applied";
    case EffectOutcome::Rejected:
      return "rejected";
    case EffectOutcome::Failed:
      return "failed";
    case EffectOutcome::Unknown:
      return "unknown";
  }
  return "unknown_effect_outcome";
}

bool parse_effect_outcome(std::string_view token, EffectOutcome& out) noexcept {
  if (token == "applied") {
    out = EffectOutcome::Applied;
  } else if (token == "rejected") {
    out = EffectOutcome::Rejected;
  } else if (token == "failed") {
    out = EffectOutcome::Failed;
  } else if (token == "unknown") {
    out = EffectOutcome::Unknown;
  } else {
    return false;
  }
  return true;
}

Digest assignment_digest(const AssignmentRecord& record) {
  const Bounds bounds{};
  BinWriter writer(bounds.max_canonical_bytes);
  wire::encode_assignment(record, writer, bounds);
  return writer.fingerprint();
}

}  // namespace nof
