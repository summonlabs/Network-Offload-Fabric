#pragma once

#include <deque>
#include <map>
#include <string>
#include <vector>

#include "nof/assignment.hpp"
#include "nof/authority.hpp"
#include "nof/bounds.hpp"
#include "nof/canonical.hpp"
#include "nof/capability.hpp"
#include "nof/error.hpp"
#include "nof/fabric.hpp"
#include "nof/function.hpp"
#include "nof/ids.hpp"
#include "nof/observation.hpp"
#include "nof/policy.hpp"
#include "nof/scope.hpp"
#include "nof/topology.hpp"
#include "nof/units.hpp"

// Internal state representation shared by the runtime, the canonical exporter,
// and the state-fingerprint surface. Ordered containers are used for every
// collection that participates in an exported document or a digest, so
// iteration order is canonical by construction rather than by convention.
namespace nof::detail {

// Which adjacent-runtime evidence stream a sequence number belongs to. Sequence
// numbers are only comparable inside one stream.
enum class EvidenceDomain : std::uint8_t {
  Topology = 1,
  Capability = 2,
  Policy = 3,
  Observation = 4,
  Authority = 5,
};

const char* to_string(EvidenceDomain value) noexcept;

struct CapabilityKey {
  DeviceId device{};
  FunctionClass cls = FunctionClass::RouteLookup;

  friend bool operator<(const CapabilityKey& left, const CapabilityKey& right) {
    if (left.device == right.device) {
      return left.cls < right.cls;
    }
    return left.device < right.device;
  }
  friend bool operator==(const CapabilityKey&, const CapabilityKey&) = default;
};

struct SourceKey {
  SourceId source{};
  EvidenceDomain domain = EvidenceDomain::Topology;

  friend bool operator<(const SourceKey& left, const SourceKey& right) {
    if (left.source == right.source) {
      return static_cast<std::uint8_t>(left.domain) < static_cast<std::uint8_t>(right.domain);
    }
    return left.source < right.source;
  }
  friend bool operator==(const SourceKey&, const SourceKey&) = default;
};

struct ExclusivityKeyLess {
  bool operator()(const ExclusivityKey& left, const ExclusivityKey& right) const noexcept {
    if (left.scope == right.scope) {
      return left.cls < right.cls;
    }
    return left.scope < right.scope;
  }
};

struct SourceState {
  std::uint64_t last_sequence = 0;
  Digest last_digest{};
  // Evidence at or below this sequence predates the most recent coordinator
  // start and is therefore never current, no matter how fresh it once was.
  std::uint64_t restart_floor = 0;
  bool seen = false;

  bool is_current(std::uint64_t sequence) const noexcept {
    return seen && sequence > restart_floor;
  }
};

struct IdempotencyEntry {
  Digest request_fingerprint{};
  ReasonCode outcome = ReasonCode::Ok;
  std::vector<std::byte> response{};
  Micros at{};
};

struct FabricState {
  CoordinatorEpoch epoch{};
  std::uint64_t epoch_counter = 0;
  std::uint64_t previous_epoch_counter = 0;
  std::uint64_t next_assignment_ordinal = 0;
  std::uint64_t next_lease = 0;
  std::uint64_t next_attempt = 0;
  std::uint64_t next_fence_sequence = 0;

  std::map<FunctionId, FunctionDescriptor> functions{};
  std::map<DeviceId, DeviceObservation> observations{};
  std::map<CapabilityKey, CapabilityRecord> capabilities{};
  bool has_topology = false;
  TopologySnapshot topology{};
  Digest topology_digest{};
  bool has_policy = false;
  PolicySnapshot policy{};
  Digest policy_digest{};
  std::map<AuthorityId, AuthorityGrant> authority{};
  std::map<AssignmentId, AssignmentRecord> assignments{};
  std::map<ExclusivityKey, AssignmentId, ExclusivityKeyLess> exclusive_by_class{};
  std::map<ScopeId, AssignmentId> exclusive_by_scope{};
  std::map<ScopeId, ScopeSpec> scope_specs{};
  std::map<DeviceId, DemandVector> committed{};
  std::map<SourceKey, SourceState> sources{};
  std::map<RequestId, IdempotencyEntry> idempotency{};
  std::deque<RequestId> idempotency_order{};
  std::map<ExclusivityKey, std::deque<Micros>, ExclusivityKeyLess> reassignments{};

  SourceState& source_state(const SourceId& source, EvidenceDomain domain);
  const SourceState* find_source(const SourceId& source, EvidenceDomain domain) const;
};

// Canonical encoding of the complete state. Used both as the compaction
// snapshot payload (round-trip proof) and as the input to the state digest.
Status encode_state(const FabricState& state, BinWriter& writer, const Bounds& bounds);
Result<FabricState> decode_state(BinReader& reader, const Bounds& bounds);

// Deterministic fingerprint over the canonical state encoding.
Digest compute_state_digest(const FabricState& state, const Bounds& bounds);

// Recomputes every derived index (exclusive claims, capacity accounting, scope
// registry) from the durable assignment records. Called after replay so that
// recovered state is derived exactly the way live state is.
void rebuild_indexes(FabricState& state);

// Canonical exporter surfaces.
Status export_state_json(const FabricState& state, const Bounds& bounds, std::string& out);
Status export_state_text(const FabricState& state, const Bounds& bounds, std::string& out);
Status collect_invariants(const FabricState& state, const Bounds& bounds, InvariantReport& report);

// Capacity accounting helper shared by placement and revalidation.
DemandVector committed_demand_for(const FabricState& state, const DeviceId& device);

}  // namespace nof::detail
