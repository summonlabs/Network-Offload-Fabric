#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "nof/assignment.hpp"
#include "nof/authority.hpp"
#include "nof/bounds.hpp"
#include "nof/canonical.hpp"
#include "nof/capability.hpp"
#include "nof/explanation.hpp"
#include "nof/fabric.hpp"
#include "nof/function.hpp"
#include "nof/observation.hpp"
#include "nof/policy.hpp"
#include "nof/scope.hpp"
#include "nof/topology.hpp"

// Canonical binary encoding of every domain object. The same routines back the
// durable journal, the service protocol, and every fingerprint, so a value that
// round-trips through persistence or the wire is bit-identical to the value
// that was accepted. Encoders return a refusal when the configured bound would
// be exceeded instead of producing a silently truncated document.
namespace nof::wire {

Status encode_provenance(const Provenance& value, BinWriter& writer);
Result<Provenance> decode_provenance(BinReader& reader);

Status encode_freshness(const Freshness& value, BinWriter& writer);
Result<Freshness> decode_freshness(BinReader& reader);

Status encode_incarnation(const IncarnationId& value, BinWriter& writer);
Result<IncarnationId> decode_incarnation(BinReader& reader);

Status encode_fence(const FencingToken& value, BinWriter& writer);
Result<FencingToken> decode_fence(BinReader& reader);

Status encode_epoch(const CoordinatorEpoch& value, BinWriter& writer);
Result<CoordinatorEpoch> decode_epoch(BinReader& reader);

Status encode_binding(const GenerationBinding& value, BinWriter& writer);
Result<GenerationBinding> decode_binding(BinReader& reader);

Status encode_demand(const DemandVector& value, BinWriter& writer);
Result<DemandVector> decode_demand(BinReader& reader);

Status encode_capacity(const CapacityVector& value, BinWriter& writer);
Result<CapacityVector> decode_capacity(BinReader& reader);

Status encode_semantics(const SemanticsMask& value, BinWriter& writer);
Result<SemanticsMask> decode_semantics(BinReader& reader);

Status encode_version(const SemanticVersion& value, BinWriter& writer);
Result<SemanticVersion> decode_version(BinReader& reader);

Status encode_version_range(const VersionRange& value, BinWriter& writer);
Result<VersionRange> decode_version_range(BinReader& reader);

Status encode_scope_spec(const ScopeSpec& value, BinWriter& writer);
Result<ScopeSpec> decode_scope_spec(BinReader& reader);

Status encode_host(const HostRecord& value, BinWriter& writer, const Bounds& bounds);
Result<HostRecord> decode_host(BinReader& reader, const Bounds& bounds);

Status encode_device(const DeviceRecord& value, BinWriter& writer, const Bounds& bounds);
Result<DeviceRecord> decode_device(BinReader& reader, const Bounds& bounds);

Status encode_link(const LinkRecord& value, BinWriter& writer);
Result<LinkRecord> decode_link(BinReader& reader);

Status encode_topology(const TopologySnapshot& value, BinWriter& writer, const Bounds& bounds);
Result<TopologySnapshot> decode_topology(BinReader& reader, const Bounds& bounds);

Status encode_function(const FunctionDescriptor& value, BinWriter& writer);
Result<FunctionDescriptor> decode_function(BinReader& reader, const Bounds& bounds);

Status encode_capability_record(const CapabilityRecord& value, BinWriter& writer, const Bounds& bounds);
Result<CapabilityRecord> decode_capability_record(BinReader& reader, const Bounds& bounds);

Status encode_capability_report(const CapabilityReport& value, BinWriter& writer, const Bounds& bounds);
Result<CapabilityReport> decode_capability_report(BinReader& reader, const Bounds& bounds);

Status encode_policy_rule(const PolicyRule& value, BinWriter& writer, const Bounds& bounds);
Result<PolicyRule> decode_policy_rule(BinReader& reader, const Bounds& bounds);

Status encode_policy(const PolicySnapshot& value, BinWriter& writer, const Bounds& bounds);
Result<PolicySnapshot> decode_policy(BinReader& reader, const Bounds& bounds);

Status encode_authority(const AuthorityGrant& value, BinWriter& writer, const Bounds& bounds);
Result<AuthorityGrant> decode_authority(BinReader& reader, const Bounds& bounds);

Status encode_observation(const DeviceObservation& value, BinWriter& writer);
Result<DeviceObservation> decode_observation(BinReader& reader);

Status encode_observation_report(const ObservationReport& value, BinWriter& writer, const Bounds& bounds);
Result<ObservationReport> decode_observation_report(BinReader& reader, const Bounds& bounds);

Status encode_transition(const TransitionRecord& value, BinWriter& writer);
Result<TransitionRecord> decode_transition(BinReader& reader);

Status encode_effect(const EffectRecord& value, BinWriter& writer);
Result<EffectRecord> decode_effect(BinReader& reader);

Status encode_assignment(const AssignmentRecord& value, BinWriter& writer, const Bounds& bounds);
Result<AssignmentRecord> decode_assignment(BinReader& reader, const Bounds& bounds);

Status encode_effect_report(const EffectReport& value, BinWriter& writer);
Result<EffectReport> decode_effect_report(BinReader& reader, const Bounds& bounds);

Status encode_placement_request(const PlacementRequest& value, BinWriter& writer, const Bounds& bounds);
Result<PlacementRequest> decode_placement_request(BinReader& reader, const Bounds& bounds);

Status encode_plan(const AssignmentPlan& value, BinWriter& writer, const Bounds& bounds);
Result<AssignmentPlan> decode_plan(BinReader& reader, const Bounds& bounds);

Status encode_candidate(const CandidateEvaluation& value, BinWriter& writer);
Result<CandidateEvaluation> decode_candidate(BinReader& reader, const Bounds& bounds);

Status encode_explanation(const Explanation& value, BinWriter& writer, const Bounds& bounds);
Result<Explanation> decode_explanation(BinReader& reader, const Bounds& bounds);

Status encode_plan_result(const PlanResult& value, BinWriter& writer, const Bounds& bounds);
Result<PlanResult> decode_plan_result(BinReader& reader, const Bounds& bounds);

Status encode_filter(const AssignmentFilter& value, BinWriter& writer);
Result<AssignmentFilter> decode_filter(BinReader& reader);

Status encode_scope_view(const ScopeView& value, BinWriter& writer, const Bounds& bounds);
Result<ScopeView> decode_scope_view(BinReader& reader, const Bounds& bounds);

Status encode_revalidation(const RevalidationReport& value, BinWriter& writer, const Bounds& bounds);
Result<RevalidationReport> decode_revalidation(BinReader& reader, const Bounds& bounds);

// Canonical digest of an encodable value.
template <class T, class EncodeFn>
Result<Digest> digest_with(const T& value, std::size_t max_bytes, EncodeFn encode_fn) {
  if (max_bytes == 0) {
    return Error(ReasonCode::InvalidConfiguration, "zero digest bound");
  }
  BinWriter writer(max_bytes);
  const Status status = encode_fn(value, writer);
  if (!status) {
    return status.error();
  }
  return writer.fingerprint();
}

}  // namespace nof::wire
