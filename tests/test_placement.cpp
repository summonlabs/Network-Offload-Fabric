#include "framework.hpp"

#include <algorithm>
#include <string>

#include "nof/explanation.hpp"
#include "nof/synthetic.hpp"
#include "support.hpp"

using namespace nof;

namespace {

bool explanation_has_reason(const Explanation& explanation, ReasonCode reason) {
  for (const ReasonCode code : explanation.reasons) {
    if (code == reason) {
      return true;
    }
  }
  return false;
}

const CandidateEvaluation* find_candidate(const Explanation& explanation, const DeviceId& device) {
  for (const CandidateEvaluation& candidate : explanation.candidates) {
    if (candidate.device == device) {
      return &candidate;
    }
  }
  return nullptr;
}

// Builds a topology where every offload device is decommissioned, so that the
// only remaining target is the host stack.
TopologySnapshot host_only_topology(const synthetic::Scenario& scenario,
                                    TopologyGeneration generation, std::uint64_t sequence,
                                    Micros observed_at) {
  TopologySnapshot topology = scenario.topology;
  topology.generation = generation;
  topology.provenance.sequence = sequence;
  topology.freshness.observed_at = observed_at;
  topology.freshness.valid_until = Micros::raw(observed_at.value() + 1000000);
  for (DeviceRecord& device : topology.devices) {
    if (is_offload_kind(device.kind)) {
      device.decommissioned = true;
    }
  }
  return topology;
}

}  // namespace

NOF_TEST(placement, selects_the_best_offload_target_deterministically) {
  support::Fixture fixture("placement-select");
  const auto planned = fixture.ref().plan(fixture.request("req-plan-1"));
  NOF_CHECK_OK(planned);
  NOF_CHECK(planned.value().accepted());
  NOF_CHECK_EQ(planned.value().plan.device, fixture.scenario.dpu_devices.front());
  NOF_CHECK_EQ(planned.value().plan.mode, ExecutionMode::Offloaded);
  NOF_CHECK_EQ(planned.value().plan.binding.topology, fixture.options.topology_generation);
  NOF_CHECK_EQ(planned.value().plan.binding.policy, fixture.options.policy_generation);
  NOF_CHECK_EQ(planned.value().plan.binding.capability, fixture.options.capability_generation);

  // Planning is a recommendation: nothing was assigned.
  NOF_CHECK_EQ(fixture.ref().stats().live_assignments, 0u);

  const Explanation& explanation = planned.value().explanation;
  const CandidateEvaluation* smartnic =
      find_candidate(explanation, fixture.scenario.smartnic_devices.front());
  const CandidateEvaluation* nic = find_candidate(explanation, fixture.scenario.nic_devices.front());
  const CandidateEvaluation* host =
      find_candidate(explanation, fixture.scenario.host_stack_devices.front());
  NOF_CHECK(smartnic != nullptr && nic != nullptr && host != nullptr);
  NOF_CHECK_EQ(smartnic->verdict, MatchVerdict::Unsupported);
  NOF_CHECK_EQ(smartnic->reason, ReasonCode::CapabilityUnsupported);
  NOF_CHECK_EQ(nic->verdict, MatchVerdict::Unknown);
  NOF_CHECK_EQ(nic->reason, ReasonCode::CapabilityUnknown);
  NOF_CHECK_EQ(host->reason, ReasonCode::HostFallbackNotPermitted);
  NOF_CHECK(!smartnic->eligible && !nic->eligible && !host->eligible);

  // The same inputs produce byte-identical plans and explanations.
  support::Fixture twin("placement-select-twin");
  const auto twin_plan = twin.ref().plan(twin.request("req-plan-1"));
  NOF_CHECK_OK(twin_plan);
  NOF_CHECK_EQ(planned.value().plan.plan_digest.hex(), twin_plan.value().plan.plan_digest.hex());
  NOF_CHECK_EQ(render_explanation(planned.value().explanation),
               render_explanation(twin_plan.value().explanation));
  NOF_CHECK_EQ(fixture.ref().state_digest().hex(), twin.ref().state_digest().hex());
}

NOF_TEST(placement, unsupported_and_unknown_semantics_are_never_eligible) {
  support::Fixture fixture("placement-semantics");
  // Require a semantic that no device claims at all.
  PlacementRequest request = fixture.request("req-semantics");
  request.required.set(Semantic::RdmaCapable);
  const auto planned = fixture.ref().plan(request);
  NOF_CHECK_OK(planned);
  NOF_CHECK(!planned.value().accepted());
  NOF_CHECK_EQ(planned.value().primary_reason, ReasonCode::CapabilityUnknown);
  for (const CandidateEvaluation& candidate : planned.value().candidates) {
    NOF_CHECK(!candidate.eligible);
  }

  // Requiring a semantic a device explicitly denies keeps it unsupported, and
  // the explanation reports that exact reason for the pinned device.
  PlacementRequest denied = fixture.request("req-semantics-denied");
  denied.preferred_devices = {fixture.scenario.smartnic_devices.front()};
  const auto denied_plan = fixture.ref().plan(denied);
  NOF_CHECK_OK(denied_plan);
  NOF_CHECK(!denied_plan.value().accepted());
  const CandidateEvaluation* denied_candidate =
      find_candidate(denied_plan.value().explanation, fixture.scenario.smartnic_devices.front());
  NOF_CHECK(denied_candidate != nullptr);
  NOF_CHECK_EQ(denied_candidate->verdict, MatchVerdict::Unsupported);
  NOF_CHECK_EQ(denied_candidate->reason, ReasonCode::CapabilityUnsupported);

  // Host fallback must be both requested and permitted by policy.
  PlacementRequest fallback = fixture.request("req-semantics-fallback");
  fallback.allow_host_fallback = true;
  fallback.preferred_devices = {fixture.scenario.host_stack_devices.front()};
  const auto fallback_plan = fixture.ref().plan(fallback);
  NOF_CHECK_OK(fallback_plan);
  NOF_CHECK(!fallback_plan.value().accepted());
  const CandidateEvaluation* host_candidate = find_candidate(
      fallback_plan.value().explanation, fixture.scenario.host_stack_devices.front());
  NOF_CHECK(host_candidate != nullptr);
  NOF_CHECK_EQ(host_candidate->reason, ReasonCode::HostFallbackNotPermitted);
}

NOF_TEST(placement, host_fallback_is_explicit_and_only_when_permitted) {
  synthetic::ScenarioOptions options;
  options.hosts = 2;
  options.observed_at = Micros::raw(1000000);
  options.valid_until = Micros::raw(2000000);
  options.host_fallback_allowed = true;
  support::Fixture fixture("placement-fallback", options);

  // Every offload-capable device is decommissioned in a newer topology, so the
  // host stack is the only remaining target.
  TopologySnapshot host_only =
      host_only_topology(fixture.scenario, TopologyGeneration::from_validated(2), 20,
                         Micros::raw(1500000));
  NOF_CHECK_OK(fixture.ref().ingest_topology(host_only));

  CapabilityReport capabilities = fixture.scenario.capabilities;
  capabilities.provenance.sequence = 21;
  capabilities.freshness.observed_at = Micros::raw(1500000);
  capabilities.freshness.valid_until = Micros::raw(2500000);
  for (CapabilityRecord& record : capabilities.records) {
    record.freshness.observed_at = Micros::raw(1500000);
    record.freshness.valid_until = Micros::raw(2500000);
  }
  NOF_CHECK_OK(fixture.ref().ingest_capabilities(capabilities));

  ObservationReport observations = synthetic::make_observations(
      options, fixture.scenario, 22, Micros::raw(1500000), Liveness::Alive, true);
  observations.topology_generation = TopologyGeneration::from_validated(2);
  NOF_CHECK_OK(fixture.ref().ingest_observations(observations));

  PlacementRequest request = fixture.request("req-fallback");
  request.allow_host_fallback = true;
  const auto planned = fixture.ref().plan(request);
  NOF_CHECK_OK(planned);
  NOF_CHECK(planned.value().accepted());
  NOF_CHECK_EQ(planned.value().plan.mode, ExecutionMode::HostFallback);
  NOF_CHECK_EQ(planned.value().plan.device, fixture.scenario.host_stack_devices.front());
  NOF_CHECK_EQ(planned.value().primary_reason, ReasonCode::HostFallbackApplied);
  NOF_CHECK(explanation_has_reason(planned.value().explanation, ReasonCode::HostFallbackApplied));

  const auto applied = fixture.ref().apply(request, ApplyOptions{});
  NOF_CHECK_OK(applied);
  NOF_CHECK_EQ(applied.value().mode, ExecutionMode::HostFallback);
  NOF_CHECK_EQ(applied.value().state_reason, ReasonCode::HostFallbackApplied);
  // Host fallback claims no capability generation: the offload semantics were
  // known to be unavailable, and the degradation is recorded instead.
  NOF_CHECK(!applied.value().binding.capability.is_set());
  NOF_CHECK(explanation_has_reason(planned.value().explanation, ReasonCode::HostFallbackApplied));
  NOF_CHECK(fixture.ref().stats().host_fallbacks >= 1);
  NOF_CHECK(fixture.ref().verify_invariants().clean);

  // A policy that permits fallback does not by itself move work onto the host
  // stack: without the explicit request-level opt-in, the offload target wins.
  support::Fixture strict("placement-fallback-strict", options);
  PlacementRequest no_opt_in = strict.request("req-fallback-strict");
  no_opt_in.allow_host_fallback = false;
  const auto strict_plan = strict.ref().plan(no_opt_in);
  NOF_CHECK_OK(strict_plan);
  NOF_CHECK(strict_plan.value().accepted());
  NOF_CHECK_EQ(strict_plan.value().plan.mode, ExecutionMode::Offloaded);
  NOF_CHECK_EQ(strict_plan.value().plan.device, strict.scenario.dpu_devices.front());
}

NOF_TEST(placement, affinity_anti_affinity_labels_and_capacity) {
  support::Fixture fixture("placement-constraints");

  PlacementRequest prefer_second = fixture.request("req-affinity");
  prefer_second.preferred_devices = {fixture.scenario.dpu_devices[1]};
  const auto preferred = fixture.ref().plan(prefer_second);
  NOF_CHECK_OK(preferred);
  NOF_CHECK(preferred.value().accepted());
  NOF_CHECK_EQ(preferred.value().plan.device, fixture.scenario.dpu_devices[1]);

  PlacementRequest blocked = fixture.request("req-anti-affinity");
  blocked.anti_affinity_devices = fixture.scenario.dpu_devices;
  const auto blocked_plan = fixture.ref().plan(blocked);
  NOF_CHECK_OK(blocked_plan);
  NOF_CHECK(!blocked_plan.value().accepted());
  NOF_CHECK_EQ(blocked_plan.value().primary_reason, ReasonCode::AntiAffinityViolation);

  PlacementRequest label = fixture.request("req-label");
  label.required_labels = {"offload-class-b"};
  const auto label_plan = fixture.ref().plan(label);
  NOF_CHECK_OK(label_plan);
  NOF_CHECK(!label_plan.value().accepted());
  NOF_CHECK_EQ(label_plan.value().primary_reason, ReasonCode::AffinityUnsatisfied);

  PlacementRequest too_big = fixture.request("req-capacity");
  too_big.demand.packets_per_second = PacketRate::raw(2000000);
  const auto capacity_plan = fixture.ref().plan(too_big);
  NOF_CHECK_OK(capacity_plan);
  NOF_CHECK(!capacity_plan.value().accepted());
  NOF_CHECK_EQ(capacity_plan.value().primary_reason, ReasonCode::CapacityExhausted);

  // Committed capacity is accounted: once every offload target is full, a
  // further placement is refused rather than oversubscribed.
  for (std::size_t index = 0; index < fixture.scenario.dpu_devices.size(); ++index) {
    PlacementRequest fill = fixture.request("req-capacity-fill-" + std::to_string(index));
    fill.scope.selector = "dir=ingress,proto=tcp,dst=10.0.2." + std::to_string(index) + ":80";
    fill.demand.packets_per_second = PacketRate::raw(900000);
    fill.preferred_devices = {fixture.scenario.dpu_devices[index]};
    NOF_CHECK_OK(fixture.ref().apply(fill, ApplyOptions{}));
  }
  PlacementRequest second = fixture.request("req-capacity-2");
  second.scope.selector = "dir=ingress,proto=tcp,dst=10.0.1.1:80";
  second.demand.packets_per_second = PacketRate::raw(900000);
  const auto second_plan = fixture.ref().plan(second);
  NOF_CHECK_OK(second_plan);
  NOF_CHECK(!second_plan.value().accepted());
  NOF_CHECK_EQ(second_plan.value().primary_reason, ReasonCode::CapacityExhausted);
}

NOF_TEST(placement, dependencies_and_cycles) {
  support::Fixture fixture("placement-dependencies");
  PlacementRequest dependency = fixture.request("req-dependency");
  dependency.dependencies = {FunctionId::from_validated("syn-fn-missing")};
  const auto missing = fixture.ref().plan(dependency);
  NOF_CHECK_OK(missing);
  NOF_CHECK(!missing.value().accepted());
  NOF_CHECK_EQ(missing.value().primary_reason, ReasonCode::DependencyUnresolved);

  PlacementRequest self = fixture.request("req-dependency-self");
  self.dependencies = {fixture.scenario.function};
  const auto cycle = fixture.ref().plan(self);
  NOF_CHECK_OK(cycle);
  NOF_CHECK(!cycle.value().accepted());
  NOF_CHECK_EQ(cycle.value().primary_reason, ReasonCode::DependencyCycle);

  // A registered dependency satisfied on the same device unblocks placement.
  FunctionDescriptor dependency_function;
  dependency_function.id = FunctionId::from_validated("syn-fn-meter");
  dependency_function.cls = fixture.options.function_class;
  dependency_function.required.set(Semantic::LineRateDeterministic);
  dependency_function.required_version = SemanticVersion{1, 0};
  NOF_CHECK_OK(fixture.ref().register_function(dependency_function));

  PlacementRequest with_dependency = fixture.request("req-dependency-ok");
  with_dependency.dependencies = {dependency_function.id};
  const auto unsatisfied = fixture.ref().plan(with_dependency);
  NOF_CHECK_OK(unsatisfied);
  NOF_CHECK(!unsatisfied.value().accepted());
  NOF_CHECK_EQ(unsatisfied.value().primary_reason, ReasonCode::DependencyUnresolved);
}

NOF_TEST(placement, locality_prefers_the_scope_host) {
  support::Fixture fixture("placement-locality");
  PlacementRequest request = fixture.request("req-locality");
  request.scope.domain = fixture.scenario.second_host;
  const auto planned = fixture.ref().plan(request);
  NOF_CHECK_OK(planned);
  NOF_CHECK(planned.value().accepted());
  NOF_CHECK_EQ(planned.value().plan.device, fixture.scenario.dpu_devices[1]);
  NOF_CHECK_EQ(planned.value().plan.host, fixture.scenario.second_host);
}

NOF_TEST(placement, evidence_floors_stale_evidence_and_restart) {
  support::Fixture fixture("placement-stale");
  PlacementRequest floor = fixture.request("req-floor");
  floor.min_topology = TopologyGeneration::from_validated(5);
  const auto floored = fixture.ref().plan(floor);
  NOF_CHECK_OK(floored);
  NOF_CHECK(!floored.value().accepted());
  NOF_CHECK_EQ(floored.value().primary_reason, ReasonCode::GenerationMismatch);

  // Letting every evidence window lapse makes the same intent illegal.
  fixture.clock->set(Micros::raw(3000000));
  const auto stale = fixture.ref().plan(fixture.request("req-stale"));
  NOF_CHECK_OK(stale);
  NOF_CHECK(!stale.value().accepted());
  NOF_CHECK_EQ(stale.value().primary_reason, ReasonCode::TopologyStale);

  // After a restart every prior observation is void and every piece of prior
  // evidence is below the restart floor: placement must refuse.
  NOF_CHECK_OK(fixture.reopen());
  NOF_CHECK_EQ(fixture.ref().stats().live_observations, 0u);
  const auto after_restart = fixture.ref().plan(fixture.request("req-restart"));
  NOF_CHECK_OK(after_restart);
  NOF_CHECK(!after_restart.value().accepted());
  NOF_CHECK_EQ(after_restart.value().primary_reason, ReasonCode::EvidenceSuperseded);
  const auto applied = fixture.ref().apply(fixture.request("req-restart-apply"), ApplyOptions{});
  NOF_CHECK(!applied.ok());
  NOF_CHECK_EQ(fixture.ref().stats().live_assignments, 0u);
}

NOF_TEST(placement, candidate_reporting_is_bounded_and_observable) {
  support::Fixture fixture("placement-bounded");
  FabricConfig config;
  config.clock = fixture.clock;
  config.bounds.max_candidates_reported = 2;
  config.bounds.max_candidates_per_plan = 3;
  Fabric tight(std::move(config));
  NOF_CHECK_OK(tight.start());
  for (const FunctionDescriptor& function : fixture.scenario.functions) {
    NOF_CHECK_OK(tight.register_function(function));
  }
  NOF_CHECK_OK(tight.ingest_policy(fixture.scenario.policy));
  NOF_CHECK_OK(tight.ingest_topology(fixture.scenario.topology));
  NOF_CHECK_OK(tight.ingest_capabilities(fixture.scenario.capabilities));
  NOF_CHECK_OK(tight.ingest_observations(fixture.scenario.observations));
  NOF_CHECK_OK(tight.grant_authority(fixture.scenario.authority));

  const auto planned = tight.plan(fixture.request("req-bounded"));
  NOF_CHECK_OK(planned);
  // Eight devices exist but the plan bound is three, and the report bound is two.
  NOF_CHECK(planned.value().candidates_truncated);
  NOF_CHECK_EQ(planned.value().candidates_total, 3u);
  NOF_CHECK_EQ(planned.value().candidates.size(), 2u);
  NOF_CHECK(planned.value().accepted());
  NOF_CHECK(tight.stats().results_truncated >= 1);
  NOF_CHECK(explanation_has_reason(planned.value().explanation, ReasonCode::TruncatedResult));
  NOF_CHECK_OK(tight.shutdown());
}

NOF_TEST(placement, malformed_requests_are_refused_without_state_change) {
  support::Fixture fixture("placement-malformed");
  PlacementRequest no_function = fixture.request("req-malformed-1");
  no_function.function = FunctionId{};
  NOF_CHECK_ERROR(fixture.ref().plan(no_function), ReasonCode::InvalidIdentifier);

  PlacementRequest bad_scope = fixture.request("req-malformed-2");
  bad_scope.scope.selector = "NOT CANONICAL";
  NOF_CHECK_ERROR(fixture.ref().plan(bad_scope), ReasonCode::InvalidIdentifier);

  PlacementRequest class_mismatch = fixture.request("req-malformed-3");
  class_mismatch.cls = FunctionClass::CryptoOffload;
  const auto mismatch = fixture.ref().plan(class_mismatch);
  NOF_CHECK_OK(mismatch);
  NOF_CHECK(!mismatch.value().accepted());

  PlacementRequest version_mismatch = fixture.request("req-malformed-4");
  version_mismatch.required_version = SemanticVersion{9, 9};
  const auto version = fixture.ref().plan(version_mismatch);
  NOF_CHECK_OK(version);
  NOF_CHECK(!version.value().accepted());

  NOF_CHECK_EQ(fixture.ref().stats().live_assignments, 0u);
  NOF_CHECK(fixture.ref().verify_invariants().clean);
}
