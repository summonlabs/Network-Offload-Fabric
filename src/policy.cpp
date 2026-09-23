#include "nof/policy.hpp"

#include <algorithm>

namespace nof {

const PolicyRule* PolicySnapshot::find_rule(FunctionClass cls) const noexcept {
  for (const PolicyRule& rule : rules) {
    if (rule.cls == cls) {
      return &rule;
    }
  }
  return nullptr;
}

namespace {

Status check_kind_list(const std::vector<DeviceKind>& kinds, const char* field) {
  if (kinds.empty()) {
    return Error(ReasonCode::MalformedInput, std::string(field) + " device kind list is empty");
  }
  for (std::size_t i = 1; i < kinds.size(); ++i) {
    if (!(kinds[i - 1] < kinds[i])) {
      return Error(ReasonCode::DuplicateIdentity,
                   std::string(field) + " device kinds must be sorted and unique");
    }
  }
  return ok_status();
}

}  // namespace

Status validate_policy_snapshot(const PolicySnapshot& snapshot, const Bounds& bounds) {
  if (!snapshot.generation.is_set()) {
    return Error(ReasonCode::OutOfRange, "policy generation is unset");
  }
  if (!snapshot.provenance.is_set()) {
    return Error(ReasonCode::ProvenanceMismatch, "policy provenance is unset");
  }
  if (snapshot.freshness.observed_at.value() <= 0) {
    return Error(ReasonCode::MalformedInput, "policy observation time is missing");
  }
  if (snapshot.freshness.valid_until.value() <= snapshot.freshness.observed_at.value()) {
    return Error(ReasonCode::MalformedInput, "policy validity interval is empty or inverted");
  }
  if (snapshot.rules.size() > bounds.max_functions) {
    return Error(ReasonCode::LimitExceeded, "policy rule count exceeds bound");
  }
  for (const PolicyRule& rule : snapshot.rules) {
    Status status = check_kind_list(rule.allowed_kinds, "policy rule");
    if (!status) {
      return status;
    }
    if (rule.reassignment_window_micros == 0) {
      return Error(ReasonCode::MalformedInput, "policy reassignment window must be non-zero");
    }
    if (rule.max_reassignments_per_scope == 0 ||
        rule.max_reassignments_per_scope > bounds.max_reassignments_per_scope) {
      return Error(ReasonCode::LimitExceeded,
                   "policy reassignment budget exceeds the configured bound");
    }
    if (rule.reassignment_window_micros > bounds.max_reassignment_window_micros) {
      return Error(ReasonCode::LimitExceeded,
                   "policy reassignment window exceeds the configured bound");
    }
    if (rule.max_assignments_per_device == 0 ||
        rule.max_assignments_per_device > bounds.max_active_assignments) {
      return Error(ReasonCode::LimitExceeded,
                   "policy device assignment ceiling exceeds the configured bound");
    }
  }
  for (std::size_t i = 1; i < snapshot.rules.size(); ++i) {
    const PolicyRule& previous = snapshot.rules[i - 1];
    const PolicyRule& current = snapshot.rules[i];
    if (previous.priority == current.priority && previous.cls == current.cls) {
      return Error(ReasonCode::DuplicateIdentity,
                   "policy rules must be ordered by priority then class without duplicates");
    }
    if (previous.priority > current.priority ||
        (previous.priority == current.priority && !(previous.cls < current.cls))) {
      return Error(ReasonCode::DuplicateIdentity,
                   "policy rules must be ordered by priority then class");
    }
  }
  return ok_status();
}

}  // namespace nof
