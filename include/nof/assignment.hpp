#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "nof/authority.hpp"
#include "nof/bounds.hpp"
#include "nof/cancel.hpp"
#include "nof/error.hpp"
#include "nof/function.hpp"
#include "nof/ids.hpp"
#include "nof/observation.hpp"
#include "nof/scope.hpp"
#include "nof/time.hpp"
#include "nof/units.hpp"

// Assignment: the durable record that binds one function on one governed scope
// to one exact device incarnation, capability generation, topology generation,
// policy generation, assignment generation, attempt, lease, and fencing token.
//
// Lifecycle: Planned -> Authorized -> Dispatched -> Acknowledged -> Applied
//                                                                 \-> Degraded / Failed
//            Suspended (restart or lost evidence) -> Authorized (re-authorized)
//            Revoked / Superseded (terminal)
namespace nof {

enum class Exclusivity : std::uint8_t {
  Shared = 1,
  Exclusive = 2,
};

const char* to_string(Exclusivity value) noexcept;
bool parse_exclusivity(std::string_view token, Exclusivity& out) noexcept;

enum class ExecutionMode : std::uint8_t {
  Offloaded = 1,     // executes on a NIC / SmartNIC / DPU
  HostFallback = 2,  // executes on the host networking stack, explicitly
};

const char* to_string(ExecutionMode value) noexcept;
bool parse_execution_mode(std::string_view token, ExecutionMode& out) noexcept;

enum class AssignmentState : std::uint8_t {
  Planned = 1,
  Authorized = 2,
  Dispatched = 3,
  Acknowledged = 4,
  AppliedVerified = 5,
  Degraded = 6,
  Suspended = 7,
  Revoked = 8,
  Superseded = 9,
  Rejected = 10,
  Failed = 11,
};

const char* to_string(AssignmentState value) noexcept;
bool parse_assignment_state(std::string_view token, AssignmentState& out) noexcept;

// States in which an assignment holds current authority over its scope.
bool holds_authority(AssignmentState state) noexcept;
// States that count against exclusivity and capacity.
bool is_live(AssignmentState state) noexcept;
bool is_terminal(AssignmentState state) noexcept;

enum class EffectOutcome : std::uint8_t {
  Applied = 1,
  Rejected = 2,
  Failed = 3,
  Unknown = 4,
};

const char* to_string(EffectOutcome value) noexcept;
bool parse_effect_outcome(std::string_view token, EffectOutcome& out) noexcept;

// The exact generations an assignment was made legal by. Any divergence between
// the binding and the current evidence invalidates the assignment's authority.
struct GenerationBinding {
  TopologyGeneration topology{};
  CapabilityGeneration capability{};
  PolicyGeneration policy{};
  AssignmentGeneration assignment{};
  SchemaGeneration schema{};

  friend bool operator==(const GenerationBinding&, const GenerationBinding&) = default;
};

struct TransitionRecord {
  AssignmentState from = AssignmentState::Planned;
  AssignmentState to = AssignmentState::Planned;
  ReasonCode reason = ReasonCode::Ok;
  Micros at{};
  FencingToken fence{};

  friend bool operator==(const TransitionRecord&, const TransitionRecord&) = default;
};

struct EffectRecord {
  AttemptId attempt{};
  FencingToken fence{};
  AssignmentGeneration generation{};
  IncarnationId incarnation{};
  CapabilityGeneration capability_generation{};
  EffectOutcome outcome = EffectOutcome::Unknown;
  ReasonCode reason = ReasonCode::Ok;
  Micros observed_at{};

  friend bool operator==(const EffectRecord&, const EffectRecord&) = default;
};

struct AssignmentRecord {
  AssignmentId id{};
  AssignmentGeneration generation{};
  FunctionId function{};
  FunctionClass cls = FunctionClass::RouteLookup;
  ScopeSpec scope{};
  ScopeId scope_id{};
  Exclusivity exclusivity = Exclusivity::Exclusive;
  ExclusiveKeyMode exclusive_key = ExclusiveKeyMode::PerClass;
  ExecutionMode mode = ExecutionMode::Offloaded;
  AssignmentState state = AssignmentState::Planned;

  DeviceId device{};
  HostId host{};
  DeviceKind kind = DeviceKind::Nic;
  IncarnationId incarnation{};
  DemandVector demand{};

  GenerationBinding binding{};
  AuthorityId authority{};
  LeaseId lease{};
  FencingToken fence{};
  AttemptId attempt{};
  Digest request_fingerprint{};

  Provenance provenance{};
  Freshness freshness{};
  ReasonCode state_reason = ReasonCode::Ok;
  Micros created_at{};
  Micros updated_at{};

  std::vector<TransitionRecord> history{};
  std::vector<EffectRecord> effects{};

  friend bool operator==(const AssignmentRecord&, const AssignmentRecord&) = default;
};

// Canonical digest of an assignment record (including history and effects).
Digest assignment_digest(const AssignmentRecord& record);

struct AssignmentFilter {
  FunctionId function{};
  ScopeId scope{};
  DeviceId device{};
  AssignmentState state = AssignmentState::Planned;
  bool filter_by_state = false;
  bool include_terminal = false;

  friend bool operator==(const AssignmentFilter&, const AssignmentFilter&) = default;
};

struct ScopeView {
  ScopeSpec spec{};
  ScopeId scope{};
  std::vector<AssignmentId> live{};
  // Every assignment that currently holds exclusive authority over this scope,
  // whether the claim is whole-scope or per function class. Canonical order.
  std::vector<AssignmentId> exclusive_claims{};
  // The whole-scope holder when one exists; otherwise the single claim when
  // exactly one exclusive claim is present.
  AssignmentId exclusive_holder{};
  bool exclusive_holder_is_whole_scope = false;
  bool exclusive_held = false;

  friend bool operator==(const ScopeView&, const ScopeView&) = default;
};

// Effect report from the enforcement plane. Acknowledgement is a report of
// reception; only an Applied report verified against the exact attempt,
// generation, incarnation, and fencing token becomes a verified application.
struct EffectReport {
  RequestId request_id{};
  AssignmentId assignment{};
  AttemptId attempt{};
  AssignmentGeneration generation{};
  FencingToken fence{};
  IncarnationId incarnation{};
  CapabilityGeneration capability_generation{};
  EffectOutcome outcome = EffectOutcome::Unknown;
  ReasonCode detail_reason = ReasonCode::Ok;
  Micros observed_at{};
  Provenance provenance{};

  friend bool operator==(const EffectReport&, const EffectReport&) = default;
};

struct RevokeRequest {
  RequestId request_id{};
  AssignmentId assignment{};
  ReasonCode reason = ReasonCode::Revoked;
  AuthorityId authority{};
  CancelToken* cancel = nullptr;
};

struct ReauthorizeRequest {
  RequestId request_id{};
  AssignmentId assignment{};
  AuthorityId authority{};
  CancelToken* cancel = nullptr;
};

struct RevalidationReport {
  std::size_t checked = 0;
  std::size_t suspended = 0;
  std::size_t degraded = 0;
  std::size_t failed = 0;
  std::size_t unchanged = 0;
  std::vector<AssignmentId> affected{};
  ReasonCode dominant_reason = ReasonCode::Ok;
  bool truncated = false;
};

}  // namespace nof
