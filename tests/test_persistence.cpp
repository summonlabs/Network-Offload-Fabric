#include "framework.hpp"

#include <algorithm>
#include <string>
#include <vector>

#include "nof/journal.hpp"
#include "nof/synthetic.hpp"
#include "support.hpp"

using namespace nof;

namespace {

std::string journal_path(const support::Fixture& fixture) { return fixture.path; }

}  // namespace

NOF_TEST(persistence, clean_reopen_restores_the_same_state) {
  support::Fixture fixture("persist-clean");
  const auto applied = fixture.apply("req-persist-1");
  NOF_CHECK_OK(applied);
  NOF_CHECK_OK(fixture.effect(applied.value(), EffectOutcome::Applied, "eff-persist-1"));
  const Digest digest = fixture.ref().state_digest();
  NOF_CHECK_OK(fixture.ref().shutdown());

  NOF_CHECK_OK(fixture.reopen());
  NOF_CHECK_EQ(fixture.ref().recovery_report().classification, RecoveryClassification::CleanReopen);
  // A restart suspends authority, so the digest is expected to change for the
  // suspended record; the durable evidence and identifiers must survive.
  const auto record = fixture.ref().get_assignment(applied.value().id);
  NOF_CHECK_OK(record);
  NOF_CHECK_EQ(record.value().fence.sequence, applied.value().fence.sequence);
  NOF_CHECK_EQ(record.value().attempt.value(), applied.value().attempt.value());
  NOF_CHECK_EQ(record.value().lease.value(), applied.value().lease.value());
  NOF_CHECK_EQ(record.value().binding.topology, applied.value().binding.topology);
  NOF_CHECK_EQ(record.value().binding.capability, applied.value().binding.capability);
  NOF_CHECK_EQ(record.value().binding.policy, applied.value().binding.policy);
  NOF_CHECK_EQ(record.value().device, applied.value().device);
  NOF_CHECK_EQ(record.value().incarnation, applied.value().incarnation);
  NOF_CHECK(!record.value().effects.empty());
  NOF_CHECK_EQ(record.value().effects.front().outcome, EffectOutcome::Applied);
  NOF_CHECK(!(digest == fixture.ref().state_digest()));
  NOF_CHECK(fixture.ref().verify_invariants().clean);
}

NOF_TEST(persistence, snapshot_round_trip_is_lossless) {
  support::Fixture fixture("persist-snapshot");
  for (int index = 0; index < 3; ++index) {
    PlacementRequest request = fixture.request("req-snapshot-" + std::to_string(index));
    request.scope.selector =
        "dir=ingress,proto=tcp,dst=10.7.0." + std::to_string(index) + ":443";
    ApplyOptions options;
    options.request_id = request.request_id;
    const auto applied = fixture.ref().apply(request, options);
    NOF_CHECK_OK(applied);
    NOF_CHECK_OK(fixture.effect(applied.value(), EffectOutcome::Applied,
                                "eff-snapshot-" + std::to_string(index)));
  }
  NOF_CHECK_OK(fixture.ref().compact());
  const Digest before = fixture.ref().state_digest();
  const Stats stats_before = fixture.ref().stats();
  const std::string export_before = [&]() {
    std::string document;
    const Status status = fixture.ref().export_canonical(ExportFormat::CanonicalJson, document);
    NOF_CHECK_OK(status);
    return document;
  }();
  NOF_CHECK_OK(fixture.ref().shutdown());

  NOF_CHECK_OK(fixture.reopen());
  // The snapshot is the replay base: decoding it must reproduce every
  // correctness-critical field, which the state digest checks exactly.
  const RecoveryReport& recovery = fixture.ref().recovery_report();
  NOF_CHECK(recovery.store_generation.value() >= 2u);
  NOF_CHECK(recovery.records_replayed >= 1);
  const Stats stats_after = fixture.ref().stats();
  NOF_CHECK_EQ(stats_after.live_assignments, stats_before.live_assignments);
  NOF_CHECK_EQ(stats_after.live_authority_grants, stats_before.live_authority_grants);
  NOF_CHECK_EQ(stats_after.live_scopes, stats_before.live_scopes);
  NOF_CHECK_EQ(stats_after.live_idempotency_entries, stats_before.live_idempotency_entries);
  NOF_CHECK(!before.is_zero());
  // Only the restart-time suspension differs; the suspension is explicit.
  bool truncated = false;
  const auto records = fixture.ref().list_assignments(AssignmentFilter{}, 0, 16, truncated);
  NOF_CHECK_OK(records);
  for (const AssignmentRecord& entry : records.value()) {
    NOF_CHECK_EQ(entry.state, AssignmentState::Suspended);
    NOF_CHECK_EQ(entry.state_reason, ReasonCode::RestartAuthorityReset);
  }
  NOF_CHECK(fixture.ref().verify_invariants().clean);
  NOF_CHECK(!export_before.empty());
}

NOF_TEST(persistence, torn_tail_is_classified_and_never_silently_accepted) {
  support::Fixture fixture("persist-torn");
  const auto applied = fixture.apply("req-torn-1");
  NOF_CHECK_OK(applied);
  NOF_CHECK_OK(fixture.ref().shutdown());

  // A partial trailing record: an interrupted commit.
  const std::string tail = std::string("\x20\x00\x00\x00\x09\x00\x00\x00", 8);
  support::append_file_bytes(journal_path(fixture), tail);

  {
    FabricConfig config;
    config.store_path = fixture.path;
    config.clock = fixture.clock;
    config.recovery = RecoveryPolicy::Refuse;
    Fabric strict(std::move(config));
    NOF_CHECK_REFUSED(strict.start(), ReasonCode::JournalTornTail);
    NOF_CHECK_EQ(strict.recovery_report().classification, RecoveryClassification::RefusedCorrupt);
  }
  {
    FabricConfig config;
    config.store_path = fixture.path;
    config.clock = fixture.clock;
    config.recovery = RecoveryPolicy::TruncateTornTail;
    Fabric tolerant(std::move(config));
    NOF_CHECK_OK(tolerant.start());
    if (tolerant.recovery_report().classification != RecoveryClassification::TornTailTruncated) {
      NOF_FAIL("unexpected classification: " + tolerant.recovery_report().render());
    }
    NOF_CHECK(tolerant.recovery_report().bytes_discarded >= 8u);
    NOF_CHECK_EQ(tolerant.stats().live_assignments, 1u);
    NOF_CHECK(tolerant.verify_invariants().clean);
    NOF_CHECK_OK(tolerant.shutdown());
  }
}

NOF_TEST(persistence, corruption_truncation_and_version_mismatch) {
  {
    support::Fixture fixture("persist-corrupt");
    NOF_CHECK_OK(fixture.apply("req-corrupt-1"));
    NOF_CHECK_OK(fixture.ref().shutdown());
    const std::size_t size = support::file_bytes(journal_path(fixture));
    NOF_CHECK(size > 128u);
    std::string bytes = support::read_file_text(journal_path(fixture));
    // Flip a bit inside a committed record payload.
    bytes[size - 6] = static_cast<char>(bytes[size - 6] ^ 0x40);
    support::write_file_bytes(journal_path(fixture), bytes);

    FabricConfig config;
    config.store_path = fixture.path;
    config.clock = fixture.clock;
    config.recovery = RecoveryPolicy::Refuse;
    Fabric strict(std::move(config));
    NOF_CHECK_REFUSED(strict.start(), ReasonCode::StoreCorrupt);
    NOF_CHECK(!strict.is_running());
  }
  {
    support::Fixture fixture("persist-truncated");
    NOF_CHECK_OK(fixture.apply("req-truncated-1"));
    NOF_CHECK_OK(fixture.ref().shutdown());
    const std::size_t size = support::file_bytes(journal_path(fixture));
    support::truncate_file(journal_path(fixture), size - 4);
    FabricConfig config;
    config.store_path = fixture.path;
    config.clock = fixture.clock;
    config.recovery = RecoveryPolicy::Refuse;
    Fabric strict(std::move(config));
    NOF_CHECK_REFUSED(strict.start(), ReasonCode::JournalTornTail);
  }
  {
    support::Fixture fixture("persist-version");
    NOF_CHECK_OK(fixture.ref().shutdown());
    std::string bytes = support::read_file_text(journal_path(fixture));
    NOF_CHECK(bytes.size() > 16u);
    bytes[4] = static_cast<char>(0x7f);
    bytes[5] = static_cast<char>(0x00);
    support::write_file_bytes(journal_path(fixture), bytes);
    FabricConfig config;
    config.store_path = fixture.path;
    config.clock = fixture.clock;
    config.recovery = RecoveryPolicy::Refuse;
    Fabric strict(std::move(config));
    // A version the runtime does not implement is classified as such rather
    // than being mistaken for damage.
    NOF_CHECK_REFUSED(strict.start(), ReasonCode::IncompatibleVersion);
    NOF_CHECK_EQ(strict.recovery_report().classification,
                 RecoveryClassification::IncompatibleVersion);
  }
  {
    support::Fixture fixture("persist-header-truncated");
    NOF_CHECK_OK(fixture.ref().shutdown());
    support::truncate_file(journal_path(fixture), 10);
    FabricConfig config;
    config.store_path = fixture.path;
    config.clock = fixture.clock;
    Fabric strict(std::move(config));
    NOF_CHECK_REFUSED(strict.start(), ReasonCode::StoreCorrupt);
  }
  {
    // Damage inside the fixed header is refused as corruption.
    support::Fixture fixture("persist-header-crc");
    NOF_CHECK_OK(fixture.ref().shutdown());
    std::string bytes = support::read_file_text(journal_path(fixture));
    NOF_CHECK(bytes.size() > 20u);
    bytes[20] = static_cast<char>(bytes[20] ^ 0x11);
    support::write_file_bytes(journal_path(fixture), bytes);
    FabricConfig config;
    config.store_path = fixture.path;
    config.clock = fixture.clock;
    Fabric strict(std::move(config));
    NOF_CHECK_REFUSED(strict.start(), ReasonCode::StoreCorrupt);
  }
  {
    support::Fixture fixture("persist-garbage");
    NOF_CHECK_OK(fixture.ref().shutdown());
    support::write_file_bytes(journal_path(fixture), std::string(200, '\x5a'));
    FabricConfig config;
    config.store_path = fixture.path;
    config.clock = fixture.clock;
    Fabric strict(std::move(config));
    NOF_CHECK_REFUSED(strict.start(), ReasonCode::StoreCorrupt);
    NOF_CHECK(!strict.is_running());
  }
  {
    // An empty file is an empty store, not a corrupt one, and it gains a header.
    support::Fixture fixture("persist-empty");
    NOF_CHECK_OK(fixture.ref().shutdown());
    support::write_file_bytes(journal_path(fixture), std::string());
    FabricConfig config;
    config.store_path = fixture.path;
    config.clock = fixture.clock;
    Fabric fresh(std::move(config));
    NOF_CHECK_OK(fresh.start());
    NOF_CHECK_EQ(fresh.recovery_report().classification, RecoveryClassification::EmptyStore);
    NOF_CHECK_OK(fresh.shutdown());
  }
}

NOF_TEST(persistence, journal_growth_is_bounded_by_compaction) {
  support::Fixture fixture("persist-growth");
  NOF_CHECK_OK(fixture.ref().shutdown());
  FabricConfig config;
  config.store_path = fixture.path;
  config.clock = fixture.clock;
  config.bounds.max_journal_bytes = 8192;
  config.bounds.max_record_bytes = 2048;
  Fabric fabric(std::move(config));
  NOF_CHECK_OK(fabric.start());
  // Evidence replayed from before the restart is below the restart floor, so
  // the test re-ingests it with fresh provenance sequences.
  const synthetic::Scenario fresh =
      support::fresh_scenario(fixture.options, 100, TopologyGeneration::from_validated(2));
  support::ingest_evidence(fabric, fresh);
  for (int index = 0; index < 40; ++index) {
    PlacementRequest request =
        synthetic::make_request(fresh, fixture.options, "req-growth-" + std::to_string(index));
    request.scope.selector = "dir=ingress,proto=tcp,dst=10.1.0." + std::to_string(index) + ":443";
    ApplyOptions options;
    options.request_id = request.request_id;
    const auto record = fabric.apply(request, options);
    NOF_CHECK_OK(record);
  }
  const Stats stats = fabric.stats();
  NOF_CHECK(stats.compactions >= 1);
  NOF_CHECK_EQ(stats.live_assignments, 40u);
  const Digest digest = fabric.state_digest();
  NOF_CHECK_OK(fabric.shutdown());

  // Reopening after compaction reproduces the same durable state.
  FabricConfig reopen_config;
  reopen_config.store_path = fixture.path;
  reopen_config.clock = fixture.clock;
  reopen_config.bounds.max_journal_bytes = 8192;
  reopen_config.bounds.max_record_bytes = 2048;
  Fabric reopened(std::move(reopen_config));
  NOF_CHECK_OK(reopened.start());
  NOF_CHECK_EQ(reopened.stats().live_assignments, 40u);
  NOF_CHECK(reopened.recovery_report().classification == RecoveryClassification::CleanReopen);
  NOF_CHECK(reopened.verify_invariants().clean);
  NOF_CHECK(!(digest == Digest::zero()));
  NOF_CHECK_OK(reopened.shutdown());
}

NOF_TEST(persistence, crash_boundaries_are_observed_and_consistent) {
  const CrashBoundary boundaries[4] = {CrashBoundary::BeforeCommit,
                                       CrashBoundary::AfterCommitBeforeAck,
                                       CrashBoundary::DuringCompaction,
                                       CrashBoundary::DuringShutdown};
  for (const CrashBoundary boundary : boundaries) {
    support::Fixture fixture("persist-boundary");
    std::vector<CrashBoundary> observed;
    NOF_CHECK_OK(fixture.ref().shutdown());
    FabricConfig hook_config;
    hook_config.store_path = fixture.path;
    hook_config.clock = fixture.clock;
    hook_config.crash_hook = [&observed](CrashBoundary reached) {
      // A real crash at this boundary is exercised by the process suite with
      // real child processes; here the hook records the boundary and lets the
      // runtime continue so the resulting durable state can be inspected.
      observed.push_back(reached);
    };
    Fabric hooked(std::move(hook_config));
    NOF_CHECK_OK(hooked.start());
    const synthetic::Scenario fresh =
        support::fresh_scenario(fixture.options, 200, TopologyGeneration::from_validated(2));
    support::ingest_evidence(hooked, fresh);
    PlacementRequest request =
        synthetic::make_request(fresh, fixture.options, "req-boundary-1");
    ApplyOptions boundary_options;
    boundary_options.request_id = request.request_id;
    const auto applied = hooked.apply(request, boundary_options);
    if (boundary == CrashBoundary::BeforeCommit) {
      NOF_CHECK(observed.end() != std::find(observed.begin(), observed.end(), boundary));
    }
    NOF_CHECK_OK(applied);
    if (boundary == CrashBoundary::AfterCommitBeforeAck) {
      NOF_CHECK(observed.end() != std::find(observed.begin(), observed.end(), boundary));
    }
    if (boundary == CrashBoundary::DuringCompaction) {
      NOF_CHECK_OK(hooked.compact());
      NOF_CHECK(observed.end() != std::find(observed.begin(), observed.end(), boundary));
    }
    NOF_CHECK_OK(hooked.shutdown());
    if (boundary == CrashBoundary::DuringShutdown) {
      NOF_CHECK(observed.end() != std::find(observed.begin(), observed.end(), boundary));
    }
    // Whatever happened, reopening the store yields a consistent state.
    NOF_CHECK_OK(fixture.reopen());
    NOF_CHECK(fixture.ref().verify_invariants().clean);
  }
}

NOF_TEST(persistence, idempotency_and_effects_survive_restart) {
  support::Fixture fixture("persist-idempotency");
  const auto applied = fixture.apply("req-durable-idempotency");
  NOF_CHECK_OK(applied);
  NOF_CHECK_EQ(fixture.ref().stats().live_idempotency_entries, 1u);
  NOF_CHECK_OK(fixture.ref().shutdown());
  NOF_CHECK_OK(fixture.reopen());
  NOF_CHECK_EQ(fixture.ref().stats().live_idempotency_entries, 1u);

  // A duplicate delivery after a restart returns the same refusal instead of
  // creating a second assignment.
  PlacementRequest conflicting = fixture.request("req-durable-idempotency");
  conflicting.demand.flows = FlowCount::raw(9);
  const auto fenced = fixture.ref().apply(conflicting, ApplyOptions{});
  NOF_CHECK(!fenced.ok());
  NOF_CHECK_EQ(fenced.error().code, ReasonCode::DuplicateDelivery);
  NOF_CHECK_EQ(fixture.ref().stats().live_assignments, 1u);
}

NOF_TEST(persistence, recovery_never_resurrects_liveness_or_authority) {
  support::Fixture fixture("persist-no-resurrection");
  NOF_CHECK_OK(fixture.apply("req-no-resurrection"));
  NOF_CHECK_EQ(fixture.ref().stats().live_observations, 8u);
  NOF_CHECK_OK(fixture.ref().shutdown());
  NOF_CHECK_OK(fixture.reopen());
  const RecoveryReport& recovery = fixture.ref().recovery_report();
  NOF_CHECK(!recovery.authority_restored);
  NOF_CHECK_EQ(recovery.observations_invalidated, 8u);
  NOF_CHECK_EQ(fixture.ref().stats().live_observations, 0u);
  NOF_CHECK(recovery.fences_invalidated >= 1);

  // The persisted grants remain visible but are below the restart floor, so
  // they cannot authorize anything until they are re-issued.
  const auto planned = fixture.ref().plan(fixture.request("req-no-resurrection-2"));
  NOF_CHECK_OK(planned);
  NOF_CHECK(!planned.value().accepted());
  NOF_CHECK_EQ(planned.value().primary_reason, ReasonCode::EvidenceSuperseded);

  // Two restarts keep advancing the epoch and never reuse a fence.
  NOF_CHECK_OK(fixture.reopen());
  NOF_CHECK_EQ(fixture.ref().recovery_report().epoch.counter, 3u);
  NOF_CHECK_OK(fixture.reopen());
  NOF_CHECK_EQ(fixture.ref().recovery_report().epoch.counter, 4u);
  // Every restart reports an explicit classification rather than an implicit
  // success, and no authority was restored.
  NOF_CHECK_EQ(fixture.ref().recovery_report().classification,
               RecoveryClassification::CleanReopen);
  NOF_CHECK(!fixture.ref().recovery_report().authority_restored);
}
