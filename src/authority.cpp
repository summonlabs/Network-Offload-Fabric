#include "nof/authority.hpp"

namespace nof {

const char* to_string(AuthorityAction value) noexcept {
  switch (value) {
    case AuthorityAction::Place:
      return "place";
    case AuthorityAction::Replace:
      return "replace";
    case AuthorityAction::Revoke:
      return "revoke";
    case AuthorityAction::Reauthorize:
      return "reauthorize";
  }
  return "unknown_authority_action";
}

bool parse_authority_action(std::string_view token, AuthorityAction& out) noexcept {
  if (token == "place") {
    out = AuthorityAction::Place;
  } else if (token == "replace") {
    out = AuthorityAction::Replace;
  } else if (token == "revoke") {
    out = AuthorityAction::Revoke;
  } else if (token == "reauthorize") {
    out = AuthorityAction::Reauthorize;
  } else {
    return false;
  }
  return true;
}

namespace {

template <class T>
Status check_sorted_unique(const std::vector<T>& values, const char* field) {
  if (values.empty()) {
    return Error(ReasonCode::MalformedInput, std::string(field) + " list is empty");
  }
  for (std::size_t i = 1; i < values.size(); ++i) {
    if (!(values[i - 1] < values[i])) {
      return Error(ReasonCode::DuplicateIdentity,
                   std::string(field) + " list must be sorted and unique");
    }
  }
  return ok_status();
}

}  // namespace

Status validate_authority_grant(const AuthorityGrant& grant, const Bounds& bounds) {
  if (grant.id.empty()) {
    return Error(ReasonCode::InvalidIdentifier, "authority grant identifier is empty");
  }
  Status status = check_sorted_unique(grant.classes, "authority class");
  if (!status) {
    return status;
  }
  status = check_sorted_unique(grant.kinds, "authority device kind");
  if (!status) {
    return status;
  }
  status = check_sorted_unique(grant.actions, "authority action");
  if (!status) {
    return status;
  }
  if (!grant.policy_generation.is_set()) {
    return Error(ReasonCode::PolicyStale, "authority grant is not bound to a policy generation");
  }
  if (grant.issued_at.value() <= 0) {
    return Error(ReasonCode::MalformedInput, "authority grant issue time is missing");
  }
  if (grant.expires_at.value() <= grant.issued_at.value()) {
    return Error(ReasonCode::MalformedInput, "authority grant validity interval is empty");
  }
  if (!grant.provenance.is_set()) {
    return Error(ReasonCode::ProvenanceMismatch, "authority grant provenance is unset");
  }
  if (grant.freshness.observed_at.value() <= 0 ||
      grant.freshness.valid_until.value() <= grant.freshness.observed_at.value()) {
    return Error(ReasonCode::MalformedInput, "authority grant freshness is not usable");
  }
  if (grant.freshness.valid_until.value() > grant.expires_at.value()) {
    return Error(ReasonCode::MalformedInput,
                 "authority grant freshness must not outlive the grant itself");
  }
  if (grant.max_uses != 0 && grant.used > grant.max_uses) {
    return Error(ReasonCode::OutOfRange, "authority grant use counter exceeds its budget");
  }
  if (grant.classes.size() > bounds.max_functions) {
    return Error(ReasonCode::LimitExceeded, "authority grant class list exceeds bound");
  }
  return ok_status();
}

AuthorityDecision authority_admits(const AuthorityGrant& grant, AuthorityAction action,
                                   FunctionClass cls, DeviceKind kind, const HostId& host,
                                   const ScopeId& scope, const SemanticsMask& semantics,
                                   PolicyGeneration policy_generation, Micros now) {
  AuthorityDecision decision;
  decision.grant = grant.id;
  if (grant.revoked) {
    decision.reason = ReasonCode::AuthorityWithdrawn;
    return decision;
  }
  if (!(grant.policy_generation == policy_generation)) {
    decision.reason = ReasonCode::PolicyStale;
    return decision;
  }
  if (now.value() >= grant.expires_at.value()) {
    decision.reason = ReasonCode::AuthorityExpired;
    return decision;
  }
  if (grant.freshness.is_expired(now)) {
    decision.reason = ReasonCode::EvidenceStale;
    return decision;
  }
  if (grant.max_uses != 0 && grant.used >= grant.max_uses) {
    decision.reason = ReasonCode::NotAuthorized;
    return decision;
  }
  if (std::find(grant.actions.begin(), grant.actions.end(), action) == grant.actions.end()) {
    decision.reason = ReasonCode::AuthorityScopeMismatch;
    return decision;
  }
  if (std::find(grant.classes.begin(), grant.classes.end(), cls) == grant.classes.end()) {
    decision.reason = ReasonCode::AuthorityScopeMismatch;
    return decision;
  }
  if (std::find(grant.kinds.begin(), grant.kinds.end(), kind) == grant.kinds.end()) {
    decision.reason = ReasonCode::AuthorityScopeMismatch;
    return decision;
  }
  if (grant.host_scope.is_set() && !(grant.host_scope == host)) {
    decision.reason = ReasonCode::AuthorityScopeMismatch;
    return decision;
  }
  if (grant.scope.is_set() && !(grant.scope == scope)) {
    decision.reason = ReasonCode::AuthorityScopeMismatch;
    return decision;
  }
  if (!grant.semantics_ceiling.empty() && !semantics.is_subset_of(grant.semantics_ceiling)) {
    decision.reason = ReasonCode::AuthorityScopeMismatch;
    return decision;
  }
  decision.admitted = true;
  decision.reason = ReasonCode::Ok;
  return decision;
}

}  // namespace nof
