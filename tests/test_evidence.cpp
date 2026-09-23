#include "framework.hpp"

#include "nof/canonical.hpp"
#include "nof/capability.hpp"
#include "nof/policy.hpp"
#include "nof/synthetic.hpp"
#include "nof/topology.hpp"
#include "nof/wire.hpp"
#include "support.hpp"

using namespace nof;

namespace {

synthetic::ScenarioOptions deterministic_options() {
  synthetic::ScenarioOptions options;
  options.hosts = 2;
  options.observed_at = Micros::raw(1000000);
  options.valid_until = Micros::raw(2000000);
  return options;
}

}  // namespace

NOF_TEST(evidence, topology_validation_refusals) {
  const synthetic::ScenarioOptions options = deterministic_options();
  synthetic::Scenario scenario = synthetic::make_scenario(options);
  const Bounds bounds;
  NOF_CHECK_OK(validate_topology(scenario.topology, bounds));

  TopologySnapshot unsorted = scenario.topology;
  std::swap(unsorted.devices[0], unsorted.devices[1]);
  NOF_CHECK_REFUSED(validate_topology(unsorted, bounds), ReasonCode::DuplicateIdentity);

  TopologySnapshot duplicate = scenario.topology;
  duplicate.devices.push_back(duplicate.devices.front());
  NOF_CHECK_REFUSED(validate_topology(duplicate, bounds), ReasonCode::DuplicateIdentity);

  TopologySnapshot unknown_host = scenario.topology;
  unknown_host.devices[0].host = HostId::from_validated("syn-h9");
  NOF_CHECK_REFUSED(validate_topology(unknown_host, bounds), ReasonCode::UnknownIdentity);

  TopologySnapshot no_incarnation = scenario.topology;
  no_incarnation.devices[0].incarnation = IncarnationId{};
  NOF_CHECK_REFUSED(validate_topology(no_incarnation, bounds), ReasonCode::IncarnationMismatch);

  TopologySnapshot no_generation = scenario.topology;
  no_generation.generation = TopologyGeneration{};
  NOF_CHECK_REFUSED(validate_topology(no_generation, bounds), ReasonCode::OutOfRange);

  TopologySnapshot no_provenance = scenario.topology;
  no_provenance.provenance = Provenance{};
  NOF_CHECK_REFUSED(validate_topology(no_provenance, bounds), ReasonCode::ProvenanceMismatch);

  TopologySnapshot inverted_window = scenario.topology;
  inverted_window.freshness.valid_until = inverted_window.freshness.observed_at;
  NOF_CHECK_REFUSED(validate_topology(inverted_window, bounds), ReasonCode::MalformedInput);

  TopologySnapshot no_hosts = scenario.topology;
  no_hosts.hosts.clear();
  no_hosts.devices.clear();
  NOF_CHECK_REFUSED(validate_topology(no_hosts, bounds), ReasonCode::EmptyInput);

  TopologySnapshot bad_labels = scenario.topology;
  bad_labels.devices[0].labels = {"Zeta"};
  NOF_CHECK_REFUSED(validate_topology(bad_labels, bounds), ReasonCode::InvalidIdentifier);

  Bounds tight = bounds;
  tight.max_devices = 2;
  NOF_CHECK_REFUSED(validate_topology(scenario.topology, tight), ReasonCode::LimitExceeded);
}

NOF_TEST(evidence, capability_validation_and_exact_matching) {
  const synthetic::ScenarioOptions options = deterministic_options();
  synthetic::Scenario scenario = synthetic::make_scenario(options);
  const Bounds bounds;
  NOF_CHECK_OK(validate_capability_report(scenario.capabilities, bounds));

  CapabilityReport overlapping = scenario.capabilities;
  overlapping.records[0].unsupported.set(Semantic::LineRateDeterministic);
  NOF_CHECK_REFUSED(validate_capability_report(overlapping, bounds), ReasonCode::SemanticsMismatch);

  CapabilityReport duplicate_key = scenario.capabilities;
  duplicate_key.records.push_back(duplicate_key.records.front());
  NOF_CHECK_REFUSED(validate_capability_report(duplicate_key, bounds), ReasonCode::DuplicateIdentity);

  CapabilityReport no_freshness = scenario.capabilities;
  no_freshness.records[0].freshness = Freshness{};
  NOF_CHECK_REFUSED(validate_capability_report(no_freshness, bounds), ReasonCode::MalformedInput);

  CapabilityReport inverted = scenario.capabilities;
  inverted.records[0].version_range.minimum = SemanticVersion{5, 0};
  inverted.records[0].version_range.maximum = SemanticVersion{1, 0};
  NOF_CHECK_REFUSED(validate_capability_report(inverted, bounds), ReasonCode::MalformedInput);

  CapabilityReport empty;
  empty.provenance = scenario.capabilities.provenance;
  empty.freshness = scenario.capabilities.freshness;
  NOF_CHECK_REFUSED(validate_capability_report(empty, bounds), ReasonCode::EmptyInput);

  const FunctionDescriptor& function = scenario.functions.front();
  const Micros now = Micros::raw(1500000);

  const CapabilityRecord* dpu =
      scenario.capabilities.find(scenario.dpu_devices.front(), options.function_class);
  NOF_CHECK(dpu != nullptr);
  const CapabilityMatch dpu_match =
      match_capability(function, *dpu, dpu->incarnation, now);
  NOF_CHECK_EQ(dpu_match.verdict, MatchVerdict::Eligible);
  NOF_CHECK(dpu_match.eligible());

  // An explicit denial is UNSUPPORTED and can never satisfy the requirement.
  const CapabilityRecord* smartnic =
      scenario.capabilities.find(scenario.smartnic_devices.front(), options.function_class);
  NOF_CHECK(smartnic != nullptr);
  const CapabilityMatch smartnic_match =
      match_capability(function, *smartnic, smartnic->incarnation, now);
  NOF_CHECK_EQ(smartnic_match.verdict, MatchVerdict::Unsupported);
  NOF_CHECK(smartnic_match.denied.test(Semantic::ProgrammablePipeline));
  NOF_CHECK(!smartnic_match.eligible());

  // An explicit unknown is UNKNOWN, never support.
  const CapabilityRecord* nic =
      scenario.capabilities.find(scenario.nic_devices.front(), options.function_class);
  NOF_CHECK(nic != nullptr);
  const CapabilityMatch nic_match = match_capability(function, *nic, nic->incarnation, now);
  NOF_CHECK_EQ(nic_match.verdict, MatchVerdict::Unknown);
  NOF_CHECK(nic_match.unresolved.test(Semantic::ProgrammablePipeline));

  // Silence is not support either: drop the claim and the verdict stays UNKNOWN.
  CapabilityRecord silent = *dpu;
  silent.supported.clear(Semantic::ProgrammablePipeline);
  const CapabilityMatch silent_match = match_capability(function, silent, silent.incarnation, now);
  NOF_CHECK_EQ(silent_match.verdict, MatchVerdict::Unknown);
  NOF_CHECK(silent_match.unsatisfied.test(Semantic::ProgrammablePipeline));

  // Stale evidence is STALE, a different incarnation is a mismatch, and an
  // incompatible version is refused.
  const CapabilityMatch expired = match_capability(function, *dpu, dpu->incarnation,
                                                   Micros::raw(3000000));
  NOF_CHECK_EQ(expired.verdict, MatchVerdict::Stale);
  IncarnationId other_incarnation = dpu->incarnation;
  other_incarnation.generation = IncarnationGeneration::from_validated(2);
  NOF_CHECK_EQ(match_capability(function, *dpu, other_incarnation, now).verdict,
               MatchVerdict::IncarnationMismatch);
  CapabilityRecord narrow = *dpu;
  narrow.version_range.minimum = SemanticVersion{5, 0};
  narrow.version_range.maximum = SemanticVersion{6, 0};
  NOF_CHECK_EQ(match_capability(function, narrow, narrow.incarnation, now).verdict,
               MatchVerdict::VersionIncompatible);
  CapabilityRecord revoked = *dpu;
  revoked.revoked = true;
  NOF_CHECK_EQ(match_capability(function, revoked, revoked.incarnation, now).verdict,
               MatchVerdict::Revoked);

  NOF_CHECK(capability_records_conflict(*dpu, revoked));
  NOF_CHECK(!capability_records_conflict(*dpu, *dpu));
}

NOF_TEST(evidence, policy_validation_refusals) {
  const synthetic::ScenarioOptions options = deterministic_options();
  synthetic::Scenario scenario = synthetic::make_scenario(options);
  const Bounds bounds;
  NOF_CHECK_OK(validate_policy_snapshot(scenario.policy, bounds));

  // A repeated rule key is refused.
  PolicySnapshot duplicated = scenario.policy;
  duplicated.rules.push_back(duplicated.rules.front());
  NOF_CHECK_REFUSED(validate_policy_snapshot(duplicated, bounds), ReasonCode::DuplicateIdentity);

  // Rules must be ordered by priority then class.
  PolicySnapshot misordered = scenario.policy;
  PolicyRule later_class = misordered.rules.front();
  later_class.cls = FunctionClass::CryptoOffload;
  misordered.rules.insert(misordered.rules.begin(), later_class);
  NOF_CHECK_REFUSED(validate_policy_snapshot(misordered, bounds), ReasonCode::DuplicateIdentity);

  PolicySnapshot no_kinds = scenario.policy;
  no_kinds.rules[0].allowed_kinds.clear();
  NOF_CHECK_REFUSED(validate_policy_snapshot(no_kinds, bounds), ReasonCode::MalformedInput);

  PolicySnapshot bad_budget = scenario.policy;
  bad_budget.rules[0].max_reassignments_per_scope = bounds.max_reassignments_per_scope + 1;
  NOF_CHECK_REFUSED(validate_policy_snapshot(bad_budget, bounds), ReasonCode::LimitExceeded);

  PolicySnapshot zero_window = scenario.policy;
  zero_window.rules[0].reassignment_window_micros = 0;
  NOF_CHECK_REFUSED(validate_policy_snapshot(zero_window, bounds), ReasonCode::MalformedInput);

  PolicySnapshot no_generation = scenario.policy;
  no_generation.generation = PolicyGeneration{};
  NOF_CHECK_REFUSED(validate_policy_snapshot(no_generation, bounds), ReasonCode::OutOfRange);

  NOF_CHECK(scenario.policy.find_rule(FunctionClass::RouteLookup) != nullptr);
  NOF_CHECK(scenario.policy.find_rule(FunctionClass::CryptoOffload) == nullptr);
}

NOF_TEST(evidence, authority_validation_and_admission_matrix) {
  const synthetic::ScenarioOptions options = deterministic_options();
  synthetic::Scenario scenario = synthetic::make_scenario(options);
  const Bounds bounds;
  NOF_CHECK_OK(validate_authority_grant(scenario.authority, bounds));

  AuthorityGrant no_classes = scenario.authority;
  no_classes.classes.clear();
  NOF_CHECK_REFUSED(validate_authority_grant(no_classes, bounds), ReasonCode::MalformedInput);

  AuthorityGrant no_policy = scenario.authority;
  no_policy.policy_generation = PolicyGeneration{};
  NOF_CHECK_REFUSED(validate_authority_grant(no_policy, bounds), ReasonCode::PolicyStale);

  AuthorityGrant inverted = scenario.authority;
  inverted.expires_at = inverted.issued_at;
  NOF_CHECK_REFUSED(validate_authority_grant(inverted, bounds), ReasonCode::MalformedInput);

  AuthorityGrant over_used = scenario.authority;
  over_used.max_uses = 2;
  over_used.used = 3;
  NOF_CHECK_REFUSED(validate_authority_grant(over_used, bounds), ReasonCode::OutOfRange);

  AuthorityGrant longer_freshness = scenario.authority;
  longer_freshness.freshness.valid_until = Micros::raw(longer_freshness.expires_at.value() + 1);
  NOF_CHECK_REFUSED(validate_authority_grant(longer_freshness, bounds), ReasonCode::MalformedInput);

  const Micros now = Micros::raw(1500000);
  const SemanticsMask semantics = scenario.functions.front().required;
  const AuthorityDecision admitted =
      authority_admits(scenario.authority, AuthorityAction::Place, options.function_class,
                       DeviceKind::Dpu, scenario.first_host, ScopeId{}, semantics,
                       options.policy_generation, now);
  NOF_CHECK(admitted.admitted);

  NOF_CHECK(!authority_admits(scenario.authority, AuthorityAction::Revoke, options.function_class,
                              DeviceKind::Dpu, scenario.first_host, ScopeId{}, semantics,
                              options.policy_generation, Micros::raw(4000000000))
                  .admitted);
  NOF_CHECK_EQ(authority_admits(scenario.authority, AuthorityAction::Place, options.function_class,
                                DeviceKind::Dpu, scenario.first_host, ScopeId{}, semantics,
                                options.policy_generation, Micros::raw(4000000000))
                   .reason,
               ReasonCode::AuthorityExpired);
  NOF_CHECK_EQ(authority_admits(scenario.authority, AuthorityAction::Place, options.function_class,
                                DeviceKind::HostStack, scenario.first_host, ScopeId{}, semantics,
                                options.policy_generation, now)
                   .reason,
               ReasonCode::AuthorityScopeMismatch);
  NOF_CHECK_EQ(authority_admits(scenario.authority, AuthorityAction::Place,
                                FunctionClass::CryptoOffload, DeviceKind::Dpu, scenario.first_host,
                                ScopeId{}, semantics, options.policy_generation, now)
                   .reason,
               ReasonCode::AuthorityScopeMismatch);
  NOF_CHECK_EQ(authority_admits(scenario.authority, AuthorityAction::Place, options.function_class,
                                DeviceKind::Dpu, scenario.first_host, ScopeId{}, semantics,
                                PolicyGeneration::from_validated(9), now)
                   .reason,
               ReasonCode::PolicyStale);
  AuthorityGrant revoked = scenario.authority;
  revoked.revoked = true;
  NOF_CHECK_EQ(authority_admits(revoked, AuthorityAction::Place, options.function_class,
                                DeviceKind::Dpu, scenario.first_host, ScopeId{}, semantics,
                                options.policy_generation, now)
                   .reason,
               ReasonCode::AuthorityWithdrawn);
  AuthorityGrant spent = scenario.authority;
  spent.max_uses = 1;
  spent.used = 1;
  NOF_CHECK_EQ(authority_admits(spent, AuthorityAction::Place, options.function_class,
                                DeviceKind::Dpu, scenario.first_host, ScopeId{}, semantics,
                                options.policy_generation, now)
                   .reason,
               ReasonCode::NotAuthorized);
  AuthorityGrant ceiling = scenario.authority;
  ceiling.semantics_ceiling.set(Semantic::LineRateDeterministic);
  NOF_CHECK_EQ(authority_admits(ceiling, AuthorityAction::Place, options.function_class,
                                DeviceKind::Dpu, scenario.first_host, ScopeId{}, semantics,
                                options.policy_generation, now)
                   .reason,
               ReasonCode::AuthorityScopeMismatch);
}

NOF_TEST(evidence, observation_validation_refusals) {
  const synthetic::ScenarioOptions options = deterministic_options();
  synthetic::Scenario scenario = synthetic::make_scenario(options);
  const Bounds bounds;
  NOF_CHECK_OK(validate_observation_report(scenario.observations, bounds));

  ObservationReport unsorted = scenario.observations;
  std::swap(unsorted.devices[0], unsorted.devices[1]);
  NOF_CHECK_REFUSED(validate_observation_report(unsorted, bounds), ReasonCode::DuplicateIdentity);

  ObservationReport no_topology = scenario.observations;
  no_topology.topology_generation = TopologyGeneration{};
  NOF_CHECK_REFUSED(validate_observation_report(no_topology, bounds), ReasonCode::TopologyStale);

  ObservationReport no_provenance = scenario.observations;
  no_provenance.provenance = Provenance{};
  NOF_CHECK_REFUSED(validate_observation_report(no_provenance, bounds), ReasonCode::ProvenanceMismatch);

  ObservationReport bad_window = scenario.observations;
  bad_window.freshness.valid_until = bad_window.freshness.observed_at;
  NOF_CHECK_REFUSED(validate_observation_report(bad_window, bounds), ReasonCode::MalformedInput);

  ObservationReport empty = scenario.observations;
  empty.devices.clear();
  NOF_CHECK_REFUSED(validate_observation_report(empty, bounds), ReasonCode::EmptyInput);

  NOF_CHECK(scenario.observations.find(scenario.dpu_devices.front()) != nullptr);
  NOF_CHECK(scenario.observations.find(DeviceId::from_validated("syn-h9-dpu")) == nullptr);
}

NOF_TEST(evidence, wire_round_trip_preserves_every_field) {
  const synthetic::ScenarioOptions options = deterministic_options();
  synthetic::Scenario scenario = synthetic::make_scenario(options);
  const Bounds bounds;

  BinWriter writer(bounds.max_canonical_bytes);
  NOF_CHECK_OK(wire::encode_topology(scenario.topology, writer, bounds));
  BinReader reader(writer.data(), bounds.max_text_bytes);
  auto decoded = wire::decode_topology(reader, bounds);
  NOF_CHECK_OK(decoded);
  NOF_CHECK(decoded.value().hosts == scenario.topology.hosts);
  NOF_CHECK(decoded.value().devices == scenario.topology.devices);
  NOF_CHECK(decoded.value().generation == scenario.topology.generation);
  NOF_CHECK(decoded.value().provenance == scenario.topology.provenance);
  NOF_CHECK(decoded.value().freshness == scenario.topology.freshness);
  NOF_CHECK(reader.at_end());

  BinWriter policy_writer(bounds.max_canonical_bytes);
  NOF_CHECK_OK(wire::encode_policy(scenario.policy, policy_writer, bounds));
  BinReader policy_reader(policy_writer.data(), bounds.max_text_bytes);
  auto policy = wire::decode_policy(policy_reader, bounds);
  NOF_CHECK_OK(policy);
  NOF_CHECK(policy.value().rules == scenario.policy.rules);
  NOF_CHECK(policy.value().generation == scenario.policy.generation);

  BinWriter authority_writer(bounds.max_canonical_bytes);
  NOF_CHECK_OK(wire::encode_authority(scenario.authority, authority_writer, bounds));
  BinReader authority_reader(authority_writer.data(), bounds.max_text_bytes);
  auto authority = wire::decode_authority(authority_reader, bounds);
  NOF_CHECK_OK(authority);
  NOF_CHECK(authority.value() == scenario.authority);

  // A truncated record is refused rather than partially decoded into a value.
  BinReader truncated(std::span<const std::byte>(writer.data().data(), writer.size() / 2),
                      bounds.max_text_bytes);
  NOF_CHECK_ERROR(wire::decode_topology(truncated, bounds), ReasonCode::TruncatedInput);

  // An unknown enum value inside a record is refused.
  BinWriter bad_device(bounds.max_canonical_bytes);
  NOF_CHECK_OK(bad_device.token("syn-h0-dpu"));
  NOF_CHECK_OK(bad_device.token("syn-h0"));
  NOF_CHECK_OK(bad_device.u8(99));
  BinReader bad_reader(bad_device.data(), bounds.max_text_bytes);
  NOF_CHECK_ERROR(wire::decode_device(bad_reader, bounds), ReasonCode::UnsupportedValue);
}

NOF_TEST(evidence, ingest_paths_refuse_stale_and_superseded_evidence) {
  support::Fixture fixture("evidence-provenance");
  const synthetic::ScenarioOptions options = deterministic_options();

  // The fixture ingested topology sequence 1 at generation 1.
  NOF_CHECK_EQ(fixture.ref().stats().topology_accepted, 1u);
  NOF_CHECK_OK(fixture.ref().ingest_topology(fixture.scenario.topology));
  NOF_CHECK(fixture.ref().stats().duplicate_deliveries_idempotent >= 1);

  // The same sequence with a different payload is a conflict.
  TopologySnapshot conflicting = fixture.scenario.topology;
  conflicting.devices[0].capacity.flows = FlowCount::raw(7);
  NOF_CHECK_REFUSED(fixture.ref().ingest_topology(conflicting), ReasonCode::EvidenceConflicting);

  // A newer generation with changed content is accepted.
  TopologySnapshot newer = fixture.scenario.topology;
  newer.provenance.sequence = 5;
  newer.generation = TopologyGeneration::from_validated(2);
  newer.freshness.observed_at = Micros::raw(1500000);
  newer.freshness.valid_until = Micros::raw(2500000);
  newer.devices[0].capacity.flows = FlowCount::raw(7);
  NOF_CHECK_OK(fixture.ref().ingest_topology(newer));
  NOF_CHECK_EQ(fixture.ref().stats().topology_accepted, 2u);

  // A regressed sequence cannot justify anything, whatever it carries.
  TopologySnapshot regressed = newer;
  regressed.provenance.sequence = 3;
  regressed.generation = TopologyGeneration::from_validated(3);
  NOF_CHECK_REFUSED(fixture.ref().ingest_topology(regressed), ReasonCode::SequenceRegression);

  // An older generation is superseded even with a fresh sequence.
  TopologySnapshot older = fixture.scenario.topology;
  older.provenance.sequence = 6;
  NOF_CHECK_REFUSED(fixture.ref().ingest_topology(older), ReasonCode::EvidenceSuperseded);

  // Capability evidence: accept generation 2, then refuse a regression and a
  // conflicting report at the same generation.
  CapabilityReport bumped = fixture.scenario.capabilities;
  bumped.provenance.sequence = 10;
  bumped.freshness.observed_at = Micros::raw(1500000);
  bumped.freshness.valid_until = Micros::raw(2500000);
  for (CapabilityRecord& record : bumped.records) {
    record.generation = CapabilityGeneration::from_validated(2);
    record.freshness.observed_at = Micros::raw(1500000);
    record.freshness.valid_until = Micros::raw(2500000);
  }
  NOF_CHECK_OK(fixture.ref().ingest_capabilities(bumped));

  CapabilityReport regressed_capabilities = bumped;
  regressed_capabilities.provenance.sequence = 11;
  regressed_capabilities.records[0].generation = CapabilityGeneration::from_validated(1);
  NOF_CHECK_REFUSED(fixture.ref().ingest_capabilities(regressed_capabilities),
                    ReasonCode::EvidenceSuperseded);

  CapabilityReport conflicting_capabilities = bumped;
  conflicting_capabilities.provenance.sequence = 12;
  conflicting_capabilities.records[0].supported.set(Semantic::VlanAware);
  NOF_CHECK_REFUSED(fixture.ref().ingest_capabilities(conflicting_capabilities),
                    ReasonCode::EvidenceConflicting);

  // Observations must target the current topology generation and incarnation.
  ObservationReport wrong_topology = fixture.scenario.observations;
  wrong_topology.provenance.sequence = 13;
  wrong_topology.topology_generation = TopologyGeneration::from_validated(9);
  NOF_CHECK_REFUSED(fixture.ref().ingest_observations(wrong_topology), ReasonCode::TopologyStale);

  ObservationReport wrong_incarnation =
      synthetic::make_observations(options, fixture.scenario, 14, Micros::raw(1500000),
                                   Liveness::Alive, true);
  wrong_incarnation.topology_generation = TopologyGeneration::from_validated(2);
  wrong_incarnation.devices[0].incarnation.generation = IncarnationGeneration::from_validated(3);
  NOF_CHECK_REFUSED(fixture.ref().ingest_observations(wrong_incarnation),
                    ReasonCode::IncarnationMismatch);

  // Malformed input is refused and changes nothing.
  TopologySnapshot malformed = newer;
  malformed.provenance.sequence = 20;
  malformed.generation = TopologyGeneration::from_validated(3);
  malformed.devices[3].host = HostId::from_validated("nope");
  NOF_CHECK_REFUSED(fixture.ref().ingest_topology(malformed), ReasonCode::UnknownIdentity);
  NOF_CHECK_EQ(fixture.ref().stats().topology_accepted, 2u);
  NOF_CHECK(fixture.ref().verify_invariants().clean);
}

NOF_TEST(evidence, authority_requires_current_policy_and_unique_identity) {
  support::Fixture fixture("evidence-authority");
  AuthorityGrant stale_policy = fixture.scenario.authority;
  stale_policy.id = AuthorityId::from_validated("syn-authority-2");
  stale_policy.policy_generation = PolicyGeneration::from_validated(9);
  stale_policy.provenance.sequence = 100;
  NOF_CHECK_REFUSED(fixture.ref().grant_authority(stale_policy), ReasonCode::PolicyStale);

  AuthorityGrant duplicate = fixture.scenario.authority;
  duplicate.max_uses = 5;
  duplicate.provenance.sequence = 101;
  NOF_CHECK_REFUSED(fixture.ref().grant_authority(duplicate), ReasonCode::AlreadyExists);

  AuthorityGrant fresh = fixture.scenario.authority;
  fresh.id = AuthorityId::from_validated("syn-authority-3");
  fresh.provenance.sequence = 102;
  NOF_CHECK_OK(fixture.ref().grant_authority(fresh));

  NOF_CHECK(fixture.ref().withdraw_authority(AuthorityId::from_validated("syn-authority-9"),
                                             ReasonCode::AuthorityWithdrawn)
                .error()
                .code == ReasonCode::NotFound);
  NOF_CHECK_OK(fixture.ref().withdraw_authority(fresh.id, ReasonCode::AuthorityWithdrawn));
  // Withdrawal is idempotent.
  NOF_CHECK_OK(fixture.ref().withdraw_authority(fresh.id, ReasonCode::AuthorityWithdrawn));
}
