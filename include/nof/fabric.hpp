#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "nof/assignment.hpp"
#include "nof/authority.hpp"
#include "nof/bounds.hpp"
#include "nof/cancel.hpp"
#include "nof/capability.hpp"
#include "nof/explanation.hpp"
#include "nof/function.hpp"
#include "nof/ids.hpp"
#include "nof/observation.hpp"
#include "nof/policy.hpp"
#include "nof/scope.hpp"
#include "nof/time.hpp"
#include "nof/topology.hpp"

// Public library API of the Network Offload Fabric runtime.
//
// The fabric owns assignment intent and authority for eligible forwarding and
// offload functions. It does not program hardware, forward packets, compute
// routes, or collect telemetry: those belong to the adjacent enforcement plane,
// which reports effects back through report_effect().
namespace nof {

enum class RecoveryPolicy : std::uint8_t {
  // Refuse to open a store whose tail is damaged. Safest default.
  Refuse = 0,
  // Accept a partial trailing record (interrupted commit) and truncate it.
  TruncateTornTail = 1,
  // Accept any damage at or after the last valid record boundary, not just a
  // partial trailing record, and truncate it. Requires an explicit operator
  // decision because damage inside a committed record cannot be proven to be a
  // tail-only event.
  TruncateDamagedTail = 2,
};

const char* to_string(RecoveryPolicy value) noexcept;
bool parse_recovery_policy(std::string_view token, RecoveryPolicy& out) noexcept;

// Durable crash boundaries honoured by the runtime. A hook installed at a
// boundary is expected to terminate the process; the runtime never continues
// past a boundary it reported, so crash safety is proven with real processes
// rather than argued about.
enum class CrashBoundary : std::uint8_t {
  BeforeCommit = 1,
  AfterCommitBeforeAck = 2,
  AfterAckBeforeEffect = 3,
  DuringShutdown = 4,
  DuringCompaction = 5,
  BeforeRecovery = 6,
};

const char* to_string(CrashBoundary value) noexcept;
bool parse_crash_boundary(std::string_view token, CrashBoundary& out) noexcept;

struct FabricConfig {
  Bounds bounds{};
  // Empty store path means purely in-memory operation: nothing is durable and
  // restart recovery is unavailable. The CLI and service always configure a
  // path; the library allows memory-only mode for embedded use.
  std::string store_path{};
  RecoveryPolicy recovery = RecoveryPolicy::Refuse;
  // Boot identity. Empty means "generate one"; tests pin it for determinism.
  BootId boot_id{};
  // Store identity. Empty means "adopt the identity in the store header" or
  // "generate one" for a fresh store.
  StoreId store_id{};
  // Injected clock. Null means SystemClock.
  std::shared_ptr<Clock> clock{};
  // fsync on every commit. Disabling weakens durability; the runtime reports
  // the effective mode in stats() so a weakened configuration is observable.
  bool durable_commit = true;
  // Recover automatically on start(); when false the runtime recovers but
  // refuses every mutating operation until accept_recovery() confirms that the
  // recovery classification was reviewed.
  bool auto_accept_recovery = true;
  // Crash-injection hook used by the validation suite and by crash tooling.
  std::function<void(CrashBoundary)> crash_hook{};
};

// A placement intent. This is what the fabric decides on: it is not an order to
// any device.
struct PlacementRequest {
  RequestId request_id{};
  FunctionId function{};
  FunctionClass cls = FunctionClass::RouteLookup;
  ScopeSpec scope{};
  SemanticsMask required{};
  SemanticVersion required_version{};
  Exclusivity exclusivity = Exclusivity::Exclusive;
  DemandVector demand{};
  std::vector<DeviceId> preferred_devices{};
  std::vector<HostId> preferred_hosts{};
  std::vector<DeviceId> anti_affinity_devices{};
  std::vector<HostId> anti_affinity_hosts{};
  std::vector<std::string> required_labels{};
  std::vector<FunctionId> dependencies{};
  TopologyGeneration min_topology{};
  CapabilityGeneration min_capability{};
  PolicyGeneration min_policy{};
  // Request-level opt-in for host fallback. Policy must also allow it; a
  // request can never widen policy.
  bool allow_host_fallback = false;
  // 0 means "use the policy value".
  std::size_t max_reassignments = 0;
  // When true the intent is to replace the currently live assignment for this
  // scope rather than to refuse because one already exists.
  bool request_replacement = false;
};

// A concrete, fully bound placement recommendation. It is not an authorization:
// apply_plan() re-validates it against current evidence and requires authority
// before anything becomes an assignment.
struct AssignmentPlan {
  RequestId request_id{};
  FunctionId function{};
  FunctionClass cls = FunctionClass::RouteLookup;
  ScopeSpec scope{};
  ScopeId scope_id{};
  Exclusivity exclusivity = Exclusivity::Exclusive;
  ExclusiveKeyMode exclusive_key = ExclusiveKeyMode::PerClass;
  ExecutionMode mode = ExecutionMode::Offloaded;

  DeviceId device{};
  HostId host{};
  DeviceKind kind = DeviceKind::Nic;
  IncarnationId incarnation{};
  DemandVector demand{};

  GenerationBinding binding{};
  AuthorityId authority{};
  SemanticsMask effective_requirement{};
  Digest plan_digest{};

  friend bool operator==(const AssignmentPlan&, const AssignmentPlan&) = default;
};

struct PlanResult {
  Decision decision = Decision::Refuse;
  ReasonCode primary_reason = ReasonCode::NoEligibleTarget;
  std::vector<CandidateEvaluation> candidates{};
  std::size_t candidates_total = 0;
  bool candidates_truncated = false;
  AssignmentPlan plan{};
  Explanation explanation{};

  bool accepted() const noexcept { return decision == Decision::Accept; }
};

struct ApplyOptions {
  RequestId request_id{};
  CancelToken* cancel = nullptr;
  // When set, a live assignment for the same governed scope is superseded by
  // this placement instead of the placement being refused.
  bool allow_replacement = false;
};

struct ReplaceRequest {
  RequestId request_id{};
  AssignmentId current{};
  PlacementRequest placement{};
  CancelToken* cancel = nullptr;
};

enum class ExportFormat : std::uint8_t {
  CanonicalJson = 1,
  CanonicalText = 2,
  CanonicalBinary = 3,
};

const char* to_string(ExportFormat value) noexcept;
bool parse_export_format(std::string_view token, ExportFormat& out) noexcept;

struct InvariantViolation {
  std::string invariant{};
  std::string detail{};
};

struct InvariantReport {
  bool clean = true;
  std::size_t checked = 0;
  std::vector<InvariantViolation> violations{};

  std::string render() const;
};

// Explicit recovery classification. A store is never opened "successfully" in
// the face of unclassified damage.
enum class RecoveryClassification : std::uint8_t {
  FreshStore = 1,
  CleanReopen = 2,
  TornTailTruncated = 3,
  DamagedTailTruncated = 4,
  RefusedCorrupt = 5,
  IncompatibleVersion = 6,
  IncompatibleSemantics = 7,
  EmptyStore = 8,
  MemoryOnly = 9,
};

const char* to_string(RecoveryClassification value) noexcept;

struct RecoveryReport {
  RecoveryClassification classification = RecoveryClassification::MemoryOnly;
  ReasonCode reason = ReasonCode::Ok;
  StoreGeneration store_generation{};
  std::uint64_t records_replayed = 0;
  std::uint64_t records_discarded = 0;
  std::uint64_t bytes_discarded = 0;
  CoordinatorEpoch epoch{};
  std::uint64_t previous_epoch = 0;
  std::size_t assignments_suspended = 0;
  std::size_t observations_invalidated = 0;
  std::size_t authority_invalidated = 0;
  std::size_t leases_voided = 0;
  std::uint64_t fences_invalidated = 0;
  // Authority is never restored as current across a restart.
  bool authority_restored = false;
  std::string render() const;
};

struct Stats {
  std::uint64_t topology_accepted = 0;
  std::uint64_t topology_refused = 0;
  std::uint64_t capability_reports_accepted = 0;
  std::uint64_t capability_reports_refused = 0;
  std::uint64_t capability_conflicts = 0;
  std::uint64_t policy_accepted = 0;
  std::uint64_t policy_refused = 0;
  std::uint64_t observations_accepted = 0;
  std::uint64_t observations_refused = 0;
  std::uint64_t authority_granted = 0;
  std::uint64_t authority_refused = 0;
  std::uint64_t authority_withdrawn = 0;
  std::uint64_t functions_registered = 0;
  std::uint64_t functions_refused = 0;

  std::uint64_t plans_accepted = 0;
  std::uint64_t plans_refused = 0;
  std::uint64_t applies_accepted = 0;
  std::uint64_t applies_refused = 0;
  std::uint64_t revokes_accepted = 0;
  std::uint64_t revokes_refused = 0;
  std::uint64_t replaces_accepted = 0;
  std::uint64_t replaces_refused = 0;
  std::uint64_t reauthorizations_accepted = 0;
  std::uint64_t reauthorizations_refused = 0;

  std::uint64_t effects_applied = 0;
  std::uint64_t effects_acknowledged = 0;
  std::uint64_t effects_rejected = 0;
  std::uint64_t effects_failed = 0;
  std::uint64_t effects_unknown = 0;
  std::uint64_t effects_fenced = 0;
  std::uint64_t effects_duplicate = 0;

  std::uint64_t exclusive_conflicts = 0;
  std::uint64_t reassignment_budget_refusals = 0;
  std::uint64_t reassignments = 0;
  std::uint64_t host_fallbacks = 0;
  std::uint64_t revalidations = 0;
  std::uint64_t assignments_suspended = 0;
  std::uint64_t assignments_degraded = 0;
  std::uint64_t cancellations = 0;
  std::uint64_t refusals_after_cancel = 0;

  std::uint64_t evidence_superseded = 0;
  std::uint64_t evidence_conflicting = 0;
  std::uint64_t evidence_stale_refusals = 0;
  std::uint64_t sequence_regressions = 0;
  std::uint64_t duplicate_deliveries_idempotent = 0;
  std::uint64_t duplicate_deliveries_fenced = 0;

  std::uint64_t results_truncated = 0;
  std::uint64_t entries_evicted = 0;
  std::uint64_t journal_records_appended = 0;
  std::uint64_t journal_bytes_appended = 0;
  std::uint64_t compactions = 0;
  std::uint64_t commits = 0;
  std::uint64_t commit_failures = 0;
  std::uint64_t recovery_events = 0;

  std::uint64_t frames_accepted = 0;
  std::uint64_t frames_refused = 0;
  std::uint64_t connections_accepted = 0;
  std::uint64_t connections_refused = 0;
  std::uint64_t requests_handled = 0;
  std::uint64_t requests_refused = 0;
  std::uint64_t shutdowns = 0;

  // Live accounting: every one of these must return to its baseline after a
  // full close, which is asserted by the resource-closure tests.
  std::size_t live_hosts = 0;
  std::size_t live_devices = 0;
  std::size_t live_functions = 0;
  std::size_t live_scopes = 0;
  std::size_t live_assignments = 0;
  std::size_t live_authority_grants = 0;
  std::size_t live_observations = 0;
  std::size_t live_idempotency_entries = 0;
  std::size_t live_journal_records = 0;
  std::size_t open_connections = 0;
  std::size_t in_flight_requests = 0;

  std::string render() const;
};

// Deterministic multi-line rendering of an assignment record. Part of the
// tooling surface: identical records always render to identical text.
std::string render_assignment(const AssignmentRecord& record);

// The runtime.
class Fabric {
 public:
  explicit Fabric(FabricConfig config);
  ~Fabric();

  Fabric(const Fabric&) = delete;
  Fabric& operator=(const Fabric&) = delete;
  Fabric(Fabric&&) = delete;
  Fabric& operator=(Fabric&&) = delete;

  // Opens the store (if configured), advances the coordinator epoch, replays
  // the journal, and applies conservative restart semantics: no lease, fence,
  // observation, or authority survives as current.
  Status start();
  Status shutdown();
  // Accepts the recovery classification produced by start(). Required before
  // mutating operations when FabricConfig::auto_accept_recovery is false.
  Status accept_recovery();
  bool is_running() const noexcept;
  bool is_shutting_down() const noexcept;

  CoordinatorEpoch epoch() const;
  const RecoveryReport& recovery_report() const;
  const Bounds& bounds() const noexcept;
  const FabricConfig& config() const noexcept;

  // --- evidence ingestion -------------------------------------------------
  Status register_function(const FunctionDescriptor& function);
  Status ingest_topology(const TopologySnapshot& snapshot);
  Status ingest_capabilities(const CapabilityReport& report);
  Status ingest_policy(const PolicySnapshot& snapshot);
  Status ingest_observations(const ObservationReport& report);
  Status grant_authority(const AuthorityGrant& grant);
  Status withdraw_authority(const AuthorityId& id, ReasonCode reason);
  Result<AssignmentRecord> report_effect(const EffectReport& report);

  // --- intent -------------------------------------------------------------
  Result<PlanResult> plan(const PlacementRequest& request) const;
  Result<PlanResult> plan(const PlacementRequest& request, const CancelToken* cancel) const;
  Result<AssignmentRecord> apply(const PlacementRequest& request, const ApplyOptions& options);
  Result<AssignmentRecord> apply_plan(const PlanResult& plan, const ApplyOptions& options);
  Result<AssignmentRecord> revoke(const RevokeRequest& request);
  Result<AssignmentRecord> replace(const ReplaceRequest& request);
  Result<AssignmentRecord> reauthorize(const ReauthorizeRequest& request);
  // Re-evaluates every live assignment against current evidence: disappeared
  // targets, stale capability/topology generations, expired observations,
  // withdrawn authority, and expired leases all suspend or degrade authority.
  Result<RevalidationReport> revalidate(const CancelToken* cancel);

  // --- query --------------------------------------------------------------
  Result<AssignmentRecord> get_assignment(const AssignmentId& id) const;
  Result<std::vector<AssignmentRecord>> list_assignments(const AssignmentFilter& filter,
                                                         std::size_t offset, std::size_t limit,
                                                         bool& truncated) const;
  Result<ScopeView> get_scope(const ScopeId& scope) const;
  Result<Explanation> explain_assignment(const AssignmentId& id) const;
  Result<Explanation> explain_request(const PlacementRequest& request) const;

  // --- determinism, export, persistence -----------------------------------
  Digest state_digest() const;
  Status export_canonical(ExportFormat format, std::string& out) const;
  Status compact();
  Stats stats() const;
  InvariantReport verify_invariants() const;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace nof
