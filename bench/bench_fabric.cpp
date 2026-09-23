// Benchmarks measure completed work: every timed loop counts an operation only
// after the runtime reported success, and every phase asserts the completion it
// claims. Enqueue latency is never reported as throughput.
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include "nof/synthetic.hpp"
#include "nof/version.hpp"

namespace {

using Clock = std::chrono::steady_clock;

double seconds_between(Clock::time_point start, Clock::time_point end) {
  return std::chrono::duration<double>(end - start).count();
}

struct Phase {
  const char* name = "";
  std::uint64_t completed = 0;
  double seconds = 0.0;

  double per_second() const { return seconds > 0.0 ? static_cast<double>(completed) / seconds : 0.0; }
};

std::string benchmark_store(const std::string& name) { return "nof-bench-" + name + ".nofjournal"; }

void remove_store(const std::string& path) {
  (void)std::remove(path.c_str());
  (void)std::remove((path + ".snapshot").c_str());
  (void)std::remove((path + ".tmp").c_str());
}

bool check(bool condition, const char* message) {
  if (!condition) {
    std::fprintf(stderr, "benchmark assertion failed: %s\n", message);
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  std::size_t hosts = 8;
  std::size_t placements = 2000;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument == "--hosts" && index + 1 < argc) {
      hosts = static_cast<std::size_t>(std::stoull(argv[++index]));
    } else if (argument == "--placements" && index + 1 < argc) {
      placements = static_cast<std::size_t>(std::stoull(argv[++index]));
    }
  }

  nof::synthetic::ScenarioOptions options;
  options.hosts = hosts;
  options.observed_at = nof::Micros::raw(1000000);
  options.valid_until = nof::Micros::raw(2000000000);
  // The policy ceiling is a bound, not a surprise: size it for the workload.
  options.max_assignments_per_device = placements + 1;
  const nof::synthetic::Scenario scenario = nof::synthetic::make_scenario(options);
  nof::Bounds bounds;

  std::vector<Phase> phases;
  bool ok = true;

  // --- evidence ingestion -------------------------------------------------
  const std::string ingest_path = benchmark_store("ingest");
  remove_store(ingest_path);
  {
    nof::FabricConfig config;
    config.store_path = ingest_path;
    config.clock = std::make_shared<nof::ManualClock>(nof::Micros::raw(1500000));
    config.boot_id = nof::BootId::from_validated("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    nof::Fabric fabric(std::move(config));
    ok = check(fabric.start().ok(), "fabric start") && ok;

    Phase phase{"evidence_ingest", 0, 0.0};
    const auto start = Clock::now();
    for (const nof::FunctionDescriptor& function : scenario.functions) {
      if (fabric.register_function(function).ok()) {
        phase.completed += 1;
      }
    }
    if (fabric.ingest_policy(scenario.policy).ok()) {
      phase.completed += 1;
    }
    if (fabric.ingest_topology(scenario.topology).ok()) {
      phase.completed += 1;
    }
    if (fabric.ingest_capabilities(scenario.capabilities).ok()) {
      phase.completed += 1;
    }
    if (fabric.ingest_observations(scenario.observations).ok()) {
      phase.completed += 1;
    }
    if (fabric.grant_authority(scenario.authority).ok()) {
      phase.completed += 1;
    }
    phase.seconds = seconds_between(start, Clock::now());
    phases.push_back(phase);
    ok = check(phase.completed == 5 + scenario.functions.size(), "all evidence ingested") && ok;

    // --- planning ---------------------------------------------------------
    Phase plan_phase{"placement_plan", 0, 0.0};
    std::uint64_t plan_digest_checksum = 0;
    const auto plan_start = Clock::now();
    for (std::size_t index = 0; index < placements; ++index) {
      nof::PlacementRequest request = nof::synthetic::make_request(
          scenario, options, "bench-plan-" + std::to_string(index));
      request.scope.selector =
          "dir=ingress,proto=tcp,dst=10.20." + std::to_string(index / 250) + "." +
          std::to_string(index % 250) + ":443";
      const auto planned = fabric.plan(request);
      if (planned.ok() && planned.value().accepted()) {
        plan_phase.completed += 1;
        plan_digest_checksum ^= planned.value().plan.plan_digest.bytes[0];
      }
    }
    plan_phase.seconds = seconds_between(plan_start, Clock::now());
    phases.push_back(plan_phase);
    ok = check(plan_phase.completed == placements, "every placement was planned") && ok;

    // --- durable assignment + verified effect -----------------------------
    Phase apply_phase{"assignment_commit", 0, 0.0};
    Phase effect_phase{"effect_verified", 0, 0.0};
    const auto apply_start = Clock::now();
    for (std::size_t index = 0; index < placements; ++index) {
      nof::PlacementRequest request = nof::synthetic::make_request(
          scenario, options, "bench-apply-" + std::to_string(index));
      request.scope.selector =
          "dir=ingress,proto=tcp,dst=10.30." + std::to_string(index / 250) + "." +
          std::to_string(index % 250) + ":443";
      nof::ApplyOptions apply_options;
      apply_options.request_id = request.request_id;
      const auto applied = fabric.apply(request, apply_options);
      if (!applied.ok()) {
        continue;
      }
      apply_phase.completed += 1;
      nof::EffectReport effect;
      effect.request_id = nof::RequestId::from_validated("bench-eff-" + std::to_string(index));
      effect.assignment = applied.value().id;
      effect.attempt = applied.value().attempt;
      effect.generation = applied.value().generation;
      effect.fence = applied.value().fence;
      effect.incarnation = applied.value().incarnation;
      effect.capability_generation = applied.value().binding.capability;
      effect.outcome = nof::EffectOutcome::Applied;
      effect.observed_at = nof::Micros::raw(1500000);
      effect.provenance.source = nof::SourceId::from_validated("syn-enforcement");
      effect.provenance.sequence = static_cast<std::uint64_t>(index + 1);
      const auto verified = fabric.report_effect(effect);
      if (verified.ok() && verified.value().state == nof::AssignmentState::AppliedVerified) {
        effect_phase.completed += 1;
      }
    }
    const auto apply_end = Clock::now();
    apply_phase.seconds = seconds_between(apply_start, apply_end);
    effect_phase.seconds = apply_phase.seconds;
    phases.push_back(apply_phase);
    phases.push_back(effect_phase);
    ok = check(apply_phase.completed == placements, "every assignment committed") && ok;
    ok = check(effect_phase.completed == placements, "every effect verified as applied") && ok;

    const nof::Stats stats = fabric.stats();
    ok = check(stats.live_assignments == placements, "live assignment count matches") && ok;
    ok = check(stats.effects_applied == placements, "applied effect count matches") && ok;
    ok = check(fabric.verify_invariants().clean, "invariants hold after the workload") && ok;
    ok = check(!fabric.state_digest().is_zero(), "state fingerprint is present") && ok;

    // --- compaction -------------------------------------------------------
    Phase compact_phase{"compaction", 0, 0.0};
    const auto compact_start = Clock::now();
    if (fabric.compact().ok()) {
      compact_phase.completed = 1;
    }
    compact_phase.seconds = seconds_between(compact_start, Clock::now());
    phases.push_back(compact_phase);
    ok = check(compact_phase.completed == 1, "compaction completed") && ok;
    ok = check(fabric.shutdown().ok(), "fabric shutdown") && ok;
    (void)plan_digest_checksum;
  }

  // --- concurrent committed work ------------------------------------------
  const std::string parallel_path = benchmark_store("parallel");
  remove_store(parallel_path);
  {
    nof::FabricConfig config;
    config.store_path = parallel_path;
    config.clock = std::make_shared<nof::ManualClock>(nof::Micros::raw(1500000));
    config.boot_id = nof::BootId::from_validated("ffffffffffffffffffffffffffffffff");
    nof::Fabric fabric(std::move(config));
    ok = check(fabric.start().ok(), "parallel fabric start") && ok;
    for (const nof::FunctionDescriptor& function : scenario.functions) {
      (void)fabric.register_function(function);
    }
    (void)fabric.ingest_policy(scenario.policy);
    (void)fabric.ingest_topology(scenario.topology);
    (void)fabric.ingest_capabilities(scenario.capabilities);
    (void)fabric.ingest_observations(scenario.observations);
    (void)fabric.grant_authority(scenario.authority);

    constexpr std::size_t kThreads = 4;
    const std::size_t per_thread = placements / kThreads;
    std::vector<std::uint64_t> completed(kThreads, 0);
    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    Phase parallel_phase{"concurrent_commit", 0, 0.0};
    const auto start = Clock::now();
    for (std::size_t thread_index = 0; thread_index < kThreads; ++thread_index) {
      threads.emplace_back([&, thread_index]() {
        for (std::size_t index = 0; index < per_thread; ++index) {
          const std::size_t ordinal = thread_index * per_thread + index;
          nof::PlacementRequest request = nof::synthetic::make_request(
              scenario, options, "bench-par-" + std::to_string(ordinal));
          request.scope.selector = "dir=ingress,proto=tcp,dst=10.40." +
                                   std::to_string(ordinal / 250) + "." +
                                   std::to_string(ordinal % 250) + ":443";
          nof::ApplyOptions apply_options;
          apply_options.request_id = request.request_id;
          if (fabric.apply(request, apply_options).ok()) {
            completed[thread_index] += 1;
          }
        }
      });
    }
    for (std::thread& thread : threads) {
      thread.join();
    }
    parallel_phase.seconds = seconds_between(start, Clock::now());
    for (const std::uint64_t count : completed) {
      parallel_phase.completed += count;
    }
    phases.push_back(parallel_phase);
    ok = check(parallel_phase.completed == per_thread * kThreads, "all concurrent work completed") && ok;
    ok = check(fabric.verify_invariants().clean, "invariants hold after concurrent work") && ok;
    ok = check(fabric.shutdown().ok(), "parallel fabric shutdown") && ok;
  }

  // --- restart recovery ---------------------------------------------------
  {
    Phase recovery_phase{"restart_recovery", 0, 0.0};
    const auto start = Clock::now();
    nof::FabricConfig config;
    config.store_path = parallel_path;
    config.clock = std::make_shared<nof::ManualClock>(nof::Micros::raw(1500000));
    nof::Fabric fabric(std::move(config));
    if (fabric.start().ok()) {
      recovery_phase.completed = 1;
    }
    recovery_phase.seconds = seconds_between(start, Clock::now());
    phases.push_back(recovery_phase);
    ok = check(recovery_phase.completed == 1, "restart recovery completed") && ok;
    ok = check(fabric.stats().live_assignments == placements, "recovered assignment count matches") && ok;
    ok = check(fabric.verify_invariants().clean, "invariants hold after recovery") && ok;
    ok = check(!fabric.recovery_report().authority_restored, "no authority restored") && ok;
    (void)fabric.shutdown();
  }

  std::printf("network-offload-fabric benchmarks %s (hosts=%zu, placements=%zu)\n",
              std::string(nof::version_string()).c_str(), hosts, placements);
  for (const Phase& phase : phases) {
    std::printf("  %-20s completed=%-8llu seconds=%.4f per_second=%.1f\n", phase.name,
                static_cast<unsigned long long>(phase.completed), phase.seconds, phase.per_second());
  }
  remove_store(ingest_path);
  remove_store(parallel_path);
  std::printf("benchmarks %s\n", ok ? "completed with all assertions satisfied" : "FAILED");
  return ok ? 0 : 1;
}
