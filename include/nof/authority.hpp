#pragma once

#include <vector>

#include "nof/bounds.hpp"
#include "nof/error.hpp"
#include "nof/function.hpp"
#include "nof/ids.hpp"
#include "nof/policy.hpp"
#include "nof/scope.hpp"
#include "nof/time.hpp"
#include "nof/topology.hpp"

// Authority grants. A recommendation is not an authorization: placement can
// only become an assignment when an explicit, current, in-scope grant exists.
namespace nof {

enum class AuthorityAction : std::uint8_t {
  Place = 1,
  Replace = 2,
  Revoke = 3,
  Reauthorize = 4,
};

const char* to_string(AuthorityAction value) noexcept;
bool parse_authority_action(std::string_view token, AuthorityAction& out) noexcept;

struct AuthorityGrant {
  AuthorityId id{};
  PolicyGeneration policy_generation{};
  std::vector<FunctionClass> classes{};       // canonical order; empty means none
  std::vector<DeviceKind> kinds{};            // canonical order; empty means none
  std::vector<AuthorityAction> actions{};     // canonical order; empty means none
  HostId host_scope{};                        // empty means network-wide
  ScopeId scope{};                            // empty means every scope
  SemanticsMask semantics_ceiling{};          // empty means no ceiling
  Micros issued_at{};
  Micros expires_at{};
  Provenance provenance{};
  Freshness freshness{};
  bool revoked = false;
  // 0 means unbounded; otherwise the grant may authorize at most this many
  // placements before it must be reissued.
  std::uint64_t max_uses = 0;
  std::uint64_t used = 0;

  friend bool operator==(const AuthorityGrant&, const AuthorityGrant&) = default;
};

struct AuthoritySet {
  PolicyGeneration generation{};
  std::vector<AuthorityGrant> grants{};
};

Status validate_authority_grant(const AuthorityGrant& grant, const Bounds& bounds);

struct AuthorityDecision {
  bool admitted = false;
  ReasonCode reason = ReasonCode::AuthorityMissing;
  AuthorityId grant{};

  explicit operator bool() const noexcept { return admitted; }
};

// Evaluates a grant against a concrete placement intent. Every dimension is
// checked: action, class, device kind, host scope, scope identity, semantics
// ceiling, policy generation binding, freshness, expiry, revocation, and the
// use budget.
AuthorityDecision authority_admits(const AuthorityGrant& grant, AuthorityAction action,
                                   FunctionClass cls, DeviceKind kind, const HostId& host,
                                   const ScopeId& scope, const SemanticsMask& semantics,
                                   PolicyGeneration policy_generation, Micros now);

}  // namespace nof
