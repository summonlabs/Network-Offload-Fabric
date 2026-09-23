#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "nof/bounds.hpp"
#include "nof/error.hpp"
#include "nof/function.hpp"
#include "nof/ids.hpp"
#include "nof/scope.hpp"
#include "nof/time.hpp"
#include "nof/topology.hpp"
#include "nof/units.hpp"

// Policy supplied by the policy authority. The fabric evaluates policy; it does
// not author it. Absence of a rule is a refusal when the snapshot is default
// deny, which is the only default the runtime accepts.
namespace nof {

struct PolicyRule {
  FunctionClass cls = FunctionClass::RouteLookup;
  // Semantics the policy additionally mandates for this class. The effective
  // requirement is request requirements united with policy requirements.
  SemanticsMask required{};
  std::vector<DeviceKind> allowed_kinds{};  // canonical order; empty means none
  ExclusiveKeyMode exclusive_key = ExclusiveKeyMode::PerClass;
  bool allow_host_fallback = false;
  bool require_authority = true;
  bool require_fresh_observation = true;
  bool require_capability = true;
  std::uint32_t priority = 0;  // lower value wins when several rules match
  std::size_t max_reassignments_per_scope = 4;
  std::uint64_t reassignment_window_micros = 3600000000ull;
  std::size_t max_assignments_per_device = 4096;
  DemandVector reserve{};

  friend bool operator==(const PolicyRule&, const PolicyRule&) = default;
};

struct PolicySnapshot {
  PolicyGeneration generation{};
  Provenance provenance{};
  Freshness freshness{};
  std::vector<PolicyRule> rules{};  // canonical order: (priority, class)
  bool default_deny = true;

  const PolicyRule* find_rule(FunctionClass cls) const noexcept;
};

Status validate_policy_snapshot(const PolicySnapshot& snapshot, const Bounds& bounds);

}  // namespace nof
