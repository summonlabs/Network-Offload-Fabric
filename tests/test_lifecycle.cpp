#include "framework.hpp"

#include <string>
#include <thread>
#include <vector>

#include "nof/cancel.hpp"
#include "nof/canonical.hpp"
#include "nof/synthetic.hpp"
#include "support.hpp"

using namespace nof;

namespace {

EffectReport make_effect(const AssignmentRecord& record, EffectOutcome outcome,
                         const std::string& request_id, Micros at) {
  EffectReport report;
  report.request_id = RequestId::from_validated(request_id);
  report.assignment = record.id;
  report.attempt = record.attempt;
  report.generation = record.generation;
  report.fence = record.fence;
  report.incarnation = record.incarnation;
  report.capability_generation = record.binding.capability;
  report.outcome = outcome;
  report.observed_at = at;
  report.provenance.source = SourceId::from_validated("syn-enforcement");
  report.provenance.sequence = 1;
  return report;
}

// Re-ingests a complete, current evidence set with fresh sequences and
// generations so that a re-authorized assignment can be legal again after a
// restart. Replayed sequences are refused by the restart floor, and a changed
// payload at the same generation is a conflict, so both must advance.
synthetic::Scenario refresh_evidence(support::Fixture& fixture, std::uint64_t base_sequence,
                                     TopologyGeneration topology_generation) {
  synthetic::ScenarioOptions options = fixture.options;
  options.observed_at = fixture.clock->now();
  options.valid_until = Micros::raw(fixture.clock->now().value() + 1000000);
  const synthetic::Scenario fresh =
      support::fresh_scenario(options, base_sequence, topology_generation);
  NOF_CHECK_OK(fixture.ref().ingest_policy(fresh.policy));
  NOF_CHECK_OK(fixture.ref().ingest_topology(fresh.topology));
  NOF_CHECK_OK(fixture.ref().ingest_capabilities(fresh.capabilities));
  NOF_CHECK_OK(fixture.ref().ingest_observations(fresh.observations));
  NOF_CHECK_OK(fixture.ref().grant_authority(fresh.authority));
  return fresh;
}

}  // namespace

NOF_TEST(lifecycle, dispatched_is_not_applied_until_verified) {
  support::Fixture fixture("lifecycle-effect");
  const auto applied = fixture.apply("req-effect-1");
  NOF_CHECK_OK(applied);
  NOF_CHECK_EQ(applied.value().state, AssignmentState::Dispatched);
  NOF_CHECK_EQ(applied.value().generation.value(), 1u);
  NOF_CHECK(applied.value().fence.is_set());
  NOF_CHECK_EQ(applied.value().fence.epoch, fixture.ref().epoch().counter);

  // An unknown outcome is recorded but never becomes a verified application.
  const auto unknown = fixture.ref().report_effect(
      make_effect(applied.value(), EffectOutcome::Unknown, "eff-unknown", fixture.clock->now()));
  NOF_CHECK_OK(unknown);
  NOF_CHECK_EQ(unknown.value().state, AssignmentState::Dispatched);
  NOF_CHECK_EQ(unknown.value().state_reason, ReasonCode::EffectUnknown);
  NOF_CHECK_EQ(fixture.ref().stats().effects_applied, 0u);

  // The verified application requires the exact attempt, fence, and generation.
  NOF_CHECK_OK(fixture.effect(applied.value(), EffectOutcome::Applied, "eff-applied"));
  const auto verified = fixture.ref().get_assignment(applied.value().id);
  NOF_CHECK_OK(verified);
  NOF_CHECK_EQ(verified.value().state, AssignmentState::AppliedVerified);
  NOF_CHECK_EQ(fixture.ref().stats().effects_applied, 1u);

  // The same effect report again is an idempotent duplicate.
  NOF_CHECK_OK(fixture.effect(applied.value(), EffectOutcome::Applied, "eff-applied-dup"));
  const auto again = fixture.ref().get_assignment(applied.value().id);
  NOF_CHECK_OK(again);
  NOF_CHECK_EQ(again.value().state, AssignmentState::AppliedVerified);
  NOF_CHECK(fixture.ref().stats().effects_duplicate >= 1);
  NOF_CHECK(fixture.ref().verify_invariants().clean);
}

NOF_TEST(lifecycle, exclusive_scope_cannot_have_two_holders) {
  support::Fixture fixture("lifecycle-exclusive");
  const auto first = fixture.apply("req-exclusive-1");
  NOF_CHECK_OK(first);

  PlacementRequest second_request = fixture.request("req-exclusive-2");
  second_request.scope.selector = "dir=ingress,proto=udp,dst=10.0.0.9:53";
  // Same scope, same class, second intent for the identical selector.
  PlacementRequest conflict = fixture.request("req-exclusive-3");
  const auto refused = fixture.ref().apply(conflict, ApplyOptions{});
  NOF_CHECK(!refused.ok());
  NOF_CHECK_EQ(refused.error().code, ReasonCode::ExclusiveConflict);
  NOF_CHECK(fixture.ref().stats().exclusive_conflicts >= 1);
  NOF_CHECK_EQ(fixture.ref().stats().live_assignments, 1u);

  // A different scope is fine, and so is a shared assignment on the same scope.
  PlacementRequest shared = second_request;
  shared.exclusivity = Exclusivity::Shared;
  const auto shared_record = fixture.ref().apply(shared, ApplyOptions{});
  NOF_CHECK_OK(shared_record);

  // Revocation releases the governed scope for a new exclusive claim.
  RevokeRequest revoke;
  revoke.request_id = RequestId::from_validated("req-revoke-1");
  revoke.assignment = first.value().id;
  revoke.reason = ReasonCode::Revoked;
  revoke.authority = first.value().authority;
  const auto revoked = fixture.ref().revoke(revoke);
  NOF_CHECK_OK(revoked);
  NOF_CHECK_EQ(revoked.value().state, AssignmentState::Revoked);

  // A fresh request identifier is required: the refused attempt above was
  // recorded, so replaying it returns the identical refusal.
  PlacementRequest retry = fixture.request("req-exclusive-4");
  const auto reapply = fixture.ref().apply(retry, ApplyOptions{});
  NOF_CHECK_OK(reapply);
  NOF_CHECK(!(reapply.value().id == first.value().id));
  NOF_CHECK(fixture.ref().verify_invariants().clean);
}

NOF_TEST(lifecycle, duplicate_delivery_is_idempotent_or_fenced) {
  support::Fixture fixture("lifecycle-idempotency");
  const auto first = fixture.apply("req-idempotent");
  NOF_CHECK_OK(first);
  const auto duplicate = fixture.apply("req-idempotent");
  NOF_CHECK_OK(duplicate);
  NOF_CHECK_EQ(first.value().id, duplicate.value().id);
  NOF_CHECK_EQ(first.value().fence.sequence, duplicate.value().fence.sequence);
  NOF_CHECK(fixture.ref().stats().duplicate_deliveries_idempotent >= 1);
  NOF_CHECK_EQ(fixture.ref().stats().live_assignments, 1u);

  // The same request identifier with a different payload is fenced, not merged.
  PlacementRequest reused = fixture.request("req-idempotent");
  reused.demand.flows = FlowCount::raw(7);
  const auto fenced = fixture.ref().apply(reused, ApplyOptions{});
  NOF_CHECK(!fenced.ok());
  NOF_CHECK_EQ(fenced.error().code, ReasonCode::DuplicateDelivery);
  NOF_CHECK(fixture.ref().stats().duplicate_deliveries_fenced >= 1);
  NOF_CHECK_EQ(fixture.ref().stats().live_assignments, 1u);
}

NOF_TEST(lifecycle, fencing_refuses_replays_and_mismatches) {
  support::Fixture fixture("lifecycle-fencing");
  const auto applied = fixture.apply("req-fence");
  NOF_CHECK_OK(applied);
  const AssignmentRecord record = applied.value();

  EffectReport stale_fence = make_effect(record, EffectOutcome::Applied, "eff-fence-1",
                                         fixture.clock->now());
  stale_fence.fence.sequence += 1;
  NOF_CHECK_ERROR(fixture.ref().report_effect(stale_fence), ReasonCode::FencedAttempt);

  EffectReport old_epoch = make_effect(record, EffectOutcome::Applied, "eff-fence-2",
                                       fixture.clock->now());
  old_epoch.fence.epoch = 99;
  NOF_CHECK_ERROR(fixture.ref().report_effect(old_epoch), ReasonCode::FencedAttempt);

  EffectReport wrong_attempt = make_effect(record, EffectOutcome::Applied, "eff-fence-3",
                                           fixture.clock->now());
  wrong_attempt.attempt = AttemptId::from_validated(record.attempt.value() + 5);
  NOF_CHECK_ERROR(fixture.ref().report_effect(wrong_attempt), ReasonCode::AttemptMismatch);

  EffectReport wrong_generation = make_effect(record, EffectOutcome::Applied, "eff-fence-4",
                                              fixture.clock->now());
  wrong_generation.generation = AssignmentGeneration::from_validated(7);
  NOF_CHECK_ERROR(fixture.ref().report_effect(wrong_generation), ReasonCode::GenerationMismatch);

  EffectReport wrong_incarnation = make_effect(record, EffectOutcome::Applied, "eff-fence-5",
                                               fixture.clock->now());
  wrong_incarnation.incarnation.generation = IncarnationGeneration::from_validated(4);
  NOF_CHECK_ERROR(fixture.ref().report_effect(wrong_incarnation), ReasonCode::IncarnationMismatch);

  EffectReport wrong_capability = make_effect(record, EffectOutcome::Applied, "eff-fence-6",
                                              fixture.clock->now());
  wrong_capability.capability_generation = CapabilityGeneration::from_validated(9);
  NOF_CHECK_ERROR(fixture.ref().report_effect(wrong_capability), ReasonCode::GenerationMismatch);

  EffectReport unknown_assignment = make_effect(record, EffectOutcome::Applied, "eff-fence-7",
                                                fixture.clock->now());
  unknown_assignment.assignment = AssignmentId::from_validated("as-00000000000000ff");
  NOF_CHECK_ERROR(fixture.ref().report_effect(unknown_assignment), ReasonCode::NotFound);

  // None of the fenced reports changed anything.
  const auto unchanged = fixture.ref().get_assignment(record.id);
  NOF_CHECK_OK(unchanged);
  NOF_CHECK_EQ(unchanged.value().state, AssignmentState::Dispatched);
  NOF_CHECK(unchanged.value().effects.empty());
  NOF_CHECK(fixture.ref().stats().effects_fenced >= 6);
}

NOF_TEST(lifecycle, rejection_and_failure_are_terminal) {
  support::Fixture fixture("lifecycle-terminal");
  const auto rejected = fixture.apply("req-rejected");
  NOF_CHECK_OK(rejected);
  const auto rejected_effect = fixture.ref().report_effect(make_effect(
      rejected.value(), EffectOutcome::Rejected, "eff-rejected", fixture.clock->now()));
  NOF_CHECK_OK(rejected_effect);
  NOF_CHECK_EQ(rejected_effect.value().state, AssignmentState::Rejected);
  // A terminal assignment refuses further effect reports.
  NOF_CHECK_ERROR(fixture.ref().report_effect(make_effect(rejected.value(), EffectOutcome::Applied,
                                                          "eff-rejected-2", fixture.clock->now())),
                  ReasonCode::IllegalStateTransition);

  PlacementRequest second = fixture.request("req-failed");
  second.scope.selector = "dir=ingress,proto=tcp,dst=10.0.0.44:80";
  const auto failed = fixture.ref().apply(second, ApplyOptions{});
  NOF_CHECK_OK(failed);
  const auto failed_effect = fixture.ref().report_effect(
      make_effect(failed.value(), EffectOutcome::Failed, "eff-failed", fixture.clock->now()));
  NOF_CHECK_OK(failed_effect);
  NOF_CHECK_EQ(failed_effect.value().state, AssignmentState::Failed);
  NOF_CHECK(fixture.ref().verify_invariants().clean);
}

NOF_TEST(lifecycle, replace_is_bounded_and_supersedes_the_previous_holder) {
  support::Fixture fixture("lifecycle-replace");
  const auto first = fixture.apply("req-replace-1");
  NOF_CHECK_OK(first);

  for (int index = 0; index < 3; ++index) {
    ReplaceRequest replace;
    replace.request_id = RequestId::from_validated("req-replace-" + std::to_string(index + 2));
    replace.current = fixture.ref().get_assignment(first.value().id).value().id;
    replace.placement = fixture.request(replace.request_id.value(), true);
    const auto replaced = fixture.ref().replace(replace);
    NOF_CHECK_OK(replaced);
    const auto previous = fixture.ref().get_assignment(replace.current);
    NOF_CHECK_OK(previous);
    NOF_CHECK_EQ(previous.value().state, AssignmentState::Superseded);
    // Exactly one live exclusive holder remains.
    const auto scope_view = fixture.ref().get_scope(replaced.value().scope_id);
    NOF_CHECK_OK(scope_view);
    NOF_CHECK(scope_view.value().exclusive_held);
    NOF_CHECK_EQ(scope_view.value().exclusive_holder, replaced.value().id);
    replace.current = replaced.value().id;
  }

  // The bounded reassignment budget is exhausted: the fourth replacement is
  // refused and the current holder is untouched.
  ReplaceRequest exhausted;
  exhausted.request_id = RequestId::from_validated("req-replace-5");
  exhausted.current = fixture.ref().list_assignments(AssignmentFilter{}, 0, 64, *new bool(false))
                          .value()
                          .back()
                          .id;
  exhausted.placement = fixture.request("req-replace-5", true);
  const auto refused = fixture.ref().replace(exhausted);
  NOF_CHECK(!refused.ok());
  NOF_CHECK_EQ(refused.error().code, ReasonCode::ReassignmentBudgetExhausted);
  NOF_CHECK(fixture.ref().stats().reassignment_budget_refusals >= 1);
  NOF_CHECK(fixture.ref().verify_invariants().clean);
}

NOF_TEST(lifecycle, revalidation_suspends_authority_when_evidence_moves) {
  support::Fixture fixture("lifecycle-revalidate");
  const auto applied = fixture.apply("req-revalidate");
  NOF_CHECK_OK(applied);

  // The device disappears from the topology: the assignment must not keep
  // authority over a target that no longer exists.
  TopologySnapshot shrunk = fixture.scenario.topology;
  shrunk.generation = TopologyGeneration::from_validated(2);
  shrunk.provenance.sequence = 40;
  shrunk.freshness.observed_at = Micros::raw(1500000);
  shrunk.freshness.valid_until = Micros::raw(2500000);
  shrunk.devices.erase(std::remove_if(shrunk.devices.begin(), shrunk.devices.end(),
                                      [&](const DeviceRecord& device) {
                                        return device.id == applied.value().device;
                                      }),
                       shrunk.devices.end());
  NOF_CHECK_OK(fixture.ref().ingest_topology(shrunk));

  const auto suspended = fixture.ref().get_assignment(applied.value().id);
  NOF_CHECK_OK(suspended);
  NOF_CHECK_EQ(suspended.value().state, AssignmentState::Suspended);
  NOF_CHECK_EQ(suspended.value().state_reason, ReasonCode::TargetDisappeared);
  NOF_CHECK(!holds_authority(suspended.value().state));

  const auto scope_view = fixture.ref().get_scope(applied.value().scope_id);
  NOF_CHECK_OK(scope_view);
  NOF_CHECK(!scope_view.value().exclusive_held);

  // Authority is not silently current: a fresh intent cannot reuse the dead
  // target, and the fabric places it on a surviving target instead.
  const auto replan = fixture.ref().plan(fixture.request("req-revalidate-2"));
  NOF_CHECK_OK(replan);
  NOF_CHECK(replan.value().accepted());
  NOF_CHECK(!(replan.value().plan.device == applied.value().device));
  bool truncated = false;
  const auto all = fixture.ref().list_assignments(AssignmentFilter{}, 0, 16, truncated);
  NOF_CHECK_OK(all);
  bool saw_suspended = false;
  for (const AssignmentRecord& entry : all.value()) {
    if (entry.id == applied.value().id) {
      NOF_CHECK_EQ(entry.state, AssignmentState::Suspended);
      saw_suspended = true;
    }
  }
  NOF_CHECK(saw_suspended);
  NOF_CHECK(fixture.ref().verify_invariants().clean);
}

NOF_TEST(lifecycle, capability_policy_and_authority_changes_suspend_assignments) {
  {
    support::Fixture fixture("lifecycle-capability-change");
    const auto applied = fixture.apply("req-capability-change");
    NOF_CHECK_OK(applied);
    CapabilityReport bumped = fixture.scenario.capabilities;
    bumped.provenance.sequence = 50;
    bumped.freshness.observed_at = Micros::raw(1500000);
    bumped.freshness.valid_until = Micros::raw(2500000);
    for (CapabilityRecord& record : bumped.records) {
      record.generation = CapabilityGeneration::from_validated(2);
      record.freshness.observed_at = Micros::raw(1500000);
      record.freshness.valid_until = Micros::raw(2500000);
    }
    NOF_CHECK_OK(fixture.ref().ingest_capabilities(bumped));
    const auto record = fixture.ref().get_assignment(applied.value().id);
    NOF_CHECK_OK(record);
    NOF_CHECK_EQ(record.value().state, AssignmentState::Suspended);
    NOF_CHECK_EQ(record.value().state_reason, ReasonCode::CapabilityStale);
  }
  {
    support::Fixture fixture("lifecycle-policy-change");
    const auto applied = fixture.apply("req-policy-change");
    NOF_CHECK_OK(applied);
    PolicySnapshot bumped = fixture.scenario.policy;
    bumped.generation = PolicyGeneration::from_validated(2);
    bumped.provenance.sequence = 51;
    bumped.freshness.observed_at = Micros::raw(1500000);
    bumped.freshness.valid_until = Micros::raw(2500000);
    NOF_CHECK_OK(fixture.ref().ingest_policy(bumped));
    const auto record = fixture.ref().get_assignment(applied.value().id);
    NOF_CHECK_OK(record);
    NOF_CHECK_EQ(record.value().state, AssignmentState::Suspended);
    NOF_CHECK_EQ(record.value().state_reason, ReasonCode::PolicyStale);
  }
  {
    support::Fixture fixture("lifecycle-authority-withdraw");
    const auto applied = fixture.apply("req-authority-withdraw");
    NOF_CHECK_OK(applied);
    NOF_CHECK_OK(
        fixture.ref().withdraw_authority(applied.value().authority, ReasonCode::AuthorityWithdrawn));
    const auto record = fixture.ref().get_assignment(applied.value().id);
    NOF_CHECK_OK(record);
    NOF_CHECK_EQ(record.value().state, AssignmentState::Suspended);
    const ReasonCode reason = record.value().state_reason;
    NOF_CHECK(reason == ReasonCode::AuthorityWithdrawn || reason == ReasonCode::EvidenceSuperseded);
  }
  {
    support::Fixture fixture("lifecycle-liveness");
    const auto applied = fixture.apply("req-liveness");
    NOF_CHECK_OK(applied);
    // The observation window lapses while topology and policy are still
    // current, so the refusal names liveness rather than the topology.
    ObservationReport short_window = synthetic::make_observations(
        fixture.options, fixture.scenario, 70, Micros::raw(1500000), Liveness::Alive, true);
    for (DeviceObservation& observation : short_window.devices) {
      observation.freshness.valid_until = Micros::raw(1600000);
    }
    NOF_CHECK_OK(fixture.ref().ingest_observations(short_window));
    fixture.clock->set(Micros::raw(1700000));
    NOF_CHECK_OK(fixture.ref().revalidate(nullptr));
    const auto record = fixture.ref().get_assignment(applied.value().id);
    NOF_CHECK_OK(record);
    NOF_CHECK_EQ(record.value().state, AssignmentState::Suspended);
    NOF_CHECK_EQ(record.value().state_reason, ReasonCode::LivenessStale);
  }
  {
    support::Fixture fixture("lifecycle-degraded");
    const auto applied = fixture.apply("req-degraded");
    NOF_CHECK_OK(applied);
    ObservationReport degraded = synthetic::make_observations(
        fixture.options, fixture.scenario, 60, Micros::raw(1500000), Liveness::Degraded, true);
    NOF_CHECK_OK(fixture.ref().ingest_observations(degraded));
    const auto record = fixture.ref().get_assignment(applied.value().id);
    NOF_CHECK_OK(record);
    NOF_CHECK_EQ(record.value().state, AssignmentState::Degraded);
    NOF_CHECK_EQ(record.value().state_reason, ReasonCode::LivenessDegraded);
    // A degraded target may still verify an effect it already acknowledged.
    NOF_CHECK_OK(fixture.effect(record.value(), EffectOutcome::Applied, "eff-degraded"));
  }
}

NOF_TEST(lifecycle, cancellation_prevents_publication) {
  support::Fixture fixture("lifecycle-cancel");
  CancelToken token;
  token.cancel();
  PlacementRequest request = fixture.request("req-cancel");
  ApplyOptions options;
  options.request_id = request.request_id;
  options.cancel = &token;
  const auto cancelled = fixture.ref().apply(request, options);
  NOF_CHECK(!cancelled.ok());
  NOF_CHECK_EQ(cancelled.error().code, ReasonCode::Cancelled);
  NOF_CHECK_EQ(fixture.ref().stats().live_assignments, 0u);
  NOF_CHECK(fixture.ref().stats().cancellations >= 1);

  const auto planned = fixture.ref().plan(request, &token);
  NOF_CHECK(!planned.ok());
  NOF_CHECK_EQ(planned.error().code, ReasonCode::Cancelled);

  // Cancelling after the commit does not retroactively undo the assignment.
  CancelToken late;
  ApplyOptions late_options;
  late_options.request_id = request.request_id;
  late_options.cancel = &late;
  const auto applied = fixture.ref().apply(request, late_options);
  NOF_CHECK_OK(applied);
  late.cancel();
  const auto record = fixture.ref().get_assignment(applied.value().id);
  NOF_CHECK_OK(record);
  NOF_CHECK_EQ(record.value().state, AssignmentState::Dispatched);
}

NOF_TEST(lifecycle, restart_fences_pre_restart_authority_and_reauthorization_restores_it) {
  support::Fixture fixture("lifecycle-restart");
  const auto applied = fixture.apply("req-restart-reauth");
  NOF_CHECK_OK(applied);
  NOF_CHECK_OK(fixture.effect(applied.value(), EffectOutcome::Applied, "eff-restart"));
  const Digest before = fixture.ref().state_digest();

  NOF_CHECK_OK(fixture.reopen());
  const RecoveryReport& recovery = fixture.ref().recovery_report();
  NOF_CHECK_EQ(recovery.previous_epoch, 1u);
  NOF_CHECK_EQ(recovery.epoch.counter, 2u);
  NOF_CHECK(!recovery.authority_restored);
  NOF_CHECK(recovery.assignments_suspended >= 1);
  NOF_CHECK_EQ(recovery.leases_voided, 1u);

  const auto suspended = fixture.ref().get_assignment(applied.value().id);
  NOF_CHECK_OK(suspended);
  NOF_CHECK_EQ(suspended.value().state, AssignmentState::Suspended);
  NOF_CHECK_EQ(suspended.value().state_reason, ReasonCode::RestartAuthorityReset);
  NOF_CHECK(!holds_authority(suspended.value().state));

  // A pre-restart effect report is fenced by the epoch change. Either an
  // outright fence mismatch or a stale epoch is acceptable; both refuse.
  const auto replay = fixture.ref().report_effect(make_effect(
      suspended.value(), EffectOutcome::Applied, "eff-restart-replay", fixture.clock->now()));
  NOF_CHECK(!replay.ok());
  NOF_CHECK(replay.error().code == ReasonCode::FencedAttempt ||
            replay.error().code == ReasonCode::EpochStale);

  // Re-authorization needs current evidence: the pre-restart grants and
  // observations are below the restart floor.
  ReauthorizeRequest premature;
  premature.request_id = RequestId::from_validated("req-reauth-premature");
  premature.assignment = suspended.value().id;
  premature.authority = suspended.value().authority;
  const auto premature_result = fixture.ref().reauthorize(premature);
  NOF_CHECK(!premature_result.ok());
  NOF_CHECK(premature_result.error().code == ReasonCode::PolicyStale ||
            premature_result.error().code == ReasonCode::EvidenceSuperseded);

  const synthetic::Scenario refreshed =
      refresh_evidence(fixture, 500, TopologyGeneration::from_validated(2));
  fixture.clock->set(Micros::raw(1500000));
  ReauthorizeRequest reauthorize;
  reauthorize.request_id = RequestId::from_validated("req-reauth");
  reauthorize.assignment = suspended.value().id;
  // Re-authorization must name a grant that is itself current.
  reauthorize.authority = refreshed.authority.id;
  const auto reauthorized = fixture.ref().reauthorize(reauthorize);
  NOF_CHECK_OK(reauthorized);
  NOF_CHECK_EQ(reauthorized.value().state, AssignmentState::Dispatched);
  NOF_CHECK_EQ(reauthorized.value().fence.epoch, 2u);
  // Fencing tokens order by (epoch, sequence): the epoch advanced, so the new
  // token dominates every pre-restart token even though its sequence restarted.
  NOF_CHECK(reauthorized.value().fence > suspended.value().fence);
  NOF_CHECK(reauthorized.value().attempt.value() > suspended.value().attempt.value());
  NOF_CHECK(!(before == fixture.ref().state_digest()));
  NOF_CHECK(fixture.ref().verify_invariants().clean);
  NOF_CHECK_EQ(fixture.ref().stats().reauthorizations_accepted, 1u);
}

NOF_TEST(lifecycle, explanations_expose_the_legal_basis) {
  support::Fixture fixture("lifecycle-explain");
  const auto planned = fixture.ref().plan(fixture.request("req-explain"));
  NOF_CHECK_OK(planned);
  const Explanation& explanation = planned.value().explanation;
  NOF_CHECK_EQ(explanation.decision, Decision::Accept);
  NOF_CHECK_EQ(explanation.binding.topology, fixture.options.topology_generation);
  NOF_CHECK_EQ(explanation.binding.policy, fixture.options.policy_generation);
  NOF_CHECK_EQ(explanation.binding.capability, fixture.options.capability_generation);
  NOF_CHECK_EQ(explanation.authority, fixture.scenario.authority.id);
  NOF_CHECK(!explanation.input_digest.is_zero());
  NOF_CHECK(!explanation.decision_digest.is_zero());
  const std::string rendered = render_explanation(explanation);
  NOF_CHECK(rendered.find("decision=accept") != std::string::npos);
  NOF_CHECK(rendered.find("authority=syn-authority-1") != std::string::npos);
  std::string json;
  NOF_CHECK_OK(explanation_to_json(explanation, json, 65536));
  NOF_CHECK(json.find("\"primary_reason\":\"OK\"") != std::string::npos);
  auto parsed = JsonReader(json).parse();
  NOF_CHECK_OK(parsed);

  const auto applied = fixture.ref().apply(fixture.request("req-explain"), ApplyOptions{});
  NOF_CHECK_OK(applied);
  const auto assigned_explanation = fixture.ref().explain_assignment(applied.value().id);
  NOF_CHECK_OK(assigned_explanation);
  NOF_CHECK_EQ(assigned_explanation.value().decision, Decision::Accept);
  NOF_CHECK_EQ(assigned_explanation.value().assignment, applied.value().id);
  const auto missing = fixture.ref().explain_assignment(AssignmentId::from_validated("as-00000000000000aa"));
  NOF_CHECK_ERROR(missing, ReasonCode::NotFound);
}
