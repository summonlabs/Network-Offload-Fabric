#include "framework.hpp"

#include <algorithm>
#include <atomic>
#include <string>
#include <thread>
#include <vector>

#include "nof/service.hpp"
#include "nof/synthetic.hpp"
#include "support.hpp"

using namespace nof;

namespace {

std::string scope_selector(int index) {
  return "dir=ingress,proto=tcp,dst=10.9.0." + std::to_string(index) + ":443";
}

}  // namespace

NOF_TEST(concurrency, competing_exclusive_claims_leave_exactly_one_holder) {
  support::Fixture fixture("conc-exclusive");
  constexpr int kThreads = 6;
  std::atomic<int> successes{0};
  std::atomic<int> conflicts{0};
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int index = 0; index < kThreads; ++index) {
    threads.emplace_back([&, index]() {
      PlacementRequest request = fixture.request("conc-exclusive-" + std::to_string(index));
      ApplyOptions options;
      options.request_id = request.request_id;
      const auto record = fixture.ref().apply(request, options);
      if (record.ok()) {
        successes.fetch_add(1);
      } else if (record.error().code == ReasonCode::ExclusiveConflict) {
        conflicts.fetch_add(1);
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  NOF_CHECK_EQ(successes.load(), 1);
  NOF_CHECK_EQ(conflicts.load(), kThreads - 1);
  NOF_CHECK_EQ(fixture.ref().stats().live_assignments, 1u);
  bool truncated = false;
  const auto live = fixture.ref().list_assignments(AssignmentFilter{}, 0, 16, truncated);
  NOF_CHECK_OK(live);
  NOF_CHECK_EQ(live.value().size(), 1u);
  NOF_CHECK(fixture.ref().verify_invariants().clean);
}

namespace {

// Canonical, order-independent summary of every live assignment: the same
// accepted decisions must appear whether the work was submitted serially or
// concurrently. Identifiers and issued tokens are deliberately excluded: their
// issuance order follows submission completion order.
std::string decision_summary(Fabric& fabric) {
  bool truncated = false;
  const auto records = fabric.list_assignments(AssignmentFilter{}, 0, 64, truncated);
  std::vector<std::string> lines;
  for (const AssignmentRecord& record : records.value()) {
    lines.push_back(record.scope_id.value() + "|" + record.device.value() + "|" +
                    to_string(record.state) + "|" + to_string(record.mode) + "|" +
                    to_string(record.exclusivity) + "|" + record.function.value() + "|" +
                    std::to_string(record.binding.topology.value()) + "|" +
                    std::to_string(record.binding.capability.value()) + "|" +
                    std::to_string(record.binding.policy.value()));
  }
  std::sort(lines.begin(), lines.end());
  std::string out;
  for (const std::string& line : lines) {
    out += line;
    out += "\n";
  }
  return out;
}

}  // namespace

NOF_TEST(concurrency, parallel_placement_matches_serial_placement) {
  constexpr int kCount = 8;
  std::string serial_summary;
  {
    support::Fixture fixture("conc-serial");
    for (int index = 0; index < kCount; ++index) {
      PlacementRequest request = fixture.request("serial-" + std::to_string(index));
      request.scope.selector = scope_selector(index);
      ApplyOptions options;
      options.request_id = request.request_id;
      NOF_CHECK_OK(fixture.ref().apply(request, options));
    }
    serial_summary = decision_summary(fixture.ref());
  }
  {
    support::Fixture fixture("conc-parallel");
    std::vector<std::thread> threads;
    threads.reserve(kCount);
    for (int index = 0; index < kCount; ++index) {
      threads.emplace_back([&, index]() {
        PlacementRequest request = fixture.request("parallel-" + std::to_string(index));
        request.scope.selector = scope_selector(index);
        ApplyOptions options;
        options.request_id = request.request_id;
        const auto record = fixture.ref().apply(request, options);
        NOF_CHECK(record.ok());
      });
    }
    for (std::thread& thread : threads) {
      thread.join();
    }
    NOF_CHECK_EQ(fixture.ref().stats().live_assignments, kCount);
    NOF_CHECK(fixture.ref().verify_invariants().clean);
    // Distinct scopes have no ordering dependency, so the concurrent run
    // accepts exactly the same decisions as the serial run.
    NOF_CHECK_EQ(decision_summary(fixture.ref()), serial_summary);
  }
}

NOF_TEST(concurrency, concurrent_ingest_query_and_intent) {
  support::Fixture fixture("conc-mixed");
  std::atomic<bool> stop{false};
  std::atomic<int> ingests{0};
  std::atomic<int> plans{0};
  std::vector<std::thread> threads;

  threads.emplace_back([&]() {
    for (int sequence = 100; sequence < 160; ++sequence) {
      ObservationReport report = synthetic::make_observations(
          fixture.options, fixture.scenario, static_cast<std::uint64_t>(sequence),
          Micros::raw(1500000), Liveness::Alive, true);
      if (fixture.ref().ingest_observations(report).ok()) {
        ingests.fetch_add(1);
      }
    }
  });
  threads.emplace_back([&]() {
    for (int index = 0; index < 60; ++index) {
      const auto planned = fixture.ref().plan(fixture.request("conc-plan-" + std::to_string(index)));
      if (planned.ok()) {
        plans.fetch_add(1);
      }
    }
  });
  threads.emplace_back([&]() {
    for (int index = 0; index < 20; ++index) {
      PlacementRequest request = fixture.request("conc-apply-" + std::to_string(index));
      request.scope.selector = scope_selector(index);
      ApplyOptions options;
      options.request_id = request.request_id;
      (void)fixture.ref().apply(request, options);
      (void)fixture.ref().stats();
      (void)fixture.ref().state_digest();
    }
  });
  for (std::thread& thread : threads) {
    thread.join();
  }
  NOF_CHECK(ingests.load() >= 1);
  NOF_CHECK_EQ(plans.load(), 60);
  NOF_CHECK(fixture.ref().verify_invariants().clean);
  NOF_CHECK(!stop.load());
}

NOF_TEST(concurrency, duplicate_delivery_races_create_one_assignment) {
  support::Fixture fixture("conc-duplicate");
  PlacementRequest request = fixture.request("conc-duplicate-1");
  constexpr int kThreads = 4;
  std::vector<AssignmentId> ids(kThreads);
  std::vector<std::thread> threads;
  threads.reserve(kThreads);
  for (int index = 0; index < kThreads; ++index) {
    threads.emplace_back([&, index]() {
      ApplyOptions options;
      options.request_id = request.request_id;
      const auto record = fixture.ref().apply(request, options);
      if (record.ok()) {
        ids[static_cast<std::size_t>(index)] = record.value().id;
      }
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  for (const AssignmentId& id : ids) {
    NOF_CHECK(!id.empty());
    NOF_CHECK_EQ(id.value(), ids[0].value());
  }
  NOF_CHECK_EQ(fixture.ref().stats().live_assignments, 1u);
  NOF_CHECK(fixture.ref().stats().duplicate_deliveries_idempotent >= 1);
}

NOF_TEST(concurrency, cancellation_observed_from_another_thread) {
  support::Fixture fixture("conc-cancel");
  CancelToken token;
  PlacementRequest request = fixture.request("conc-cancel-1");
  ApplyOptions options;
  options.request_id = request.request_id;
  options.cancel = &token;
  std::thread canceller([&]() { token.cancel(); });
  canceller.join();
  const auto cancelled = fixture.ref().apply(request, options);
  NOF_CHECK(!cancelled.ok());
  NOF_CHECK_EQ(cancelled.error().code, ReasonCode::Cancelled);
  NOF_CHECK_EQ(fixture.ref().stats().live_assignments, 0u);

  // The same intent without cancellation succeeds afterwards.
  PlacementRequest retry = fixture.request("conc-cancel-2");
  ApplyOptions retry_options;
  retry_options.request_id = retry.request_id;
  NOF_CHECK_OK(fixture.ref().apply(retry, retry_options));
}

NOF_TEST(concurrency, server_lifecycle_with_work_in_flight) {
  support::Fixture fixture("conc-server");
  service::ServerConfig config;
  config.bind_address = "127.0.0.1";
  config.port = 0;
  config.max_workers = 3;
  config.max_connections = 8;
  config.max_queue_depth = 8;

  for (int cycle = 0; cycle < 3; ++cycle) {
    service::Server server(fixture.ref(), config);
    NOF_CHECK_OK(server.start());
    const std::uint16_t port = server.port();
    NOF_CHECK(port != 0);
    const Bounds bounds;
    std::atomic<int> responses{0};
    std::atomic<bool> stop{false};
    std::vector<std::thread> clients;
    for (int index = 0; index < 4; ++index) {
      clients.emplace_back([&]() {
        auto client = service::Client::connect("127.0.0.1", port, bounds);
        if (!client.ok()) {
          return;
        }
        while (!stop.load()) {
          service::Frame request;
          request.opcode = service::Opcode::Ping;
          request.request_id = 1;
          const auto response = client.value()->call(request);
          if (!response.ok()) {
            break;
          }
          responses.fetch_add(1);
        }
        (void)client.value()->close();
      });
    }
    // Let the clients produce completed work before stopping the server.
    while (responses.load() < 8) {
      std::this_thread::yield();
    }
    NOF_CHECK_OK(server.stop());
    stop.store(true);
    for (std::thread& thread : clients) {
      thread.join();
    }
    NOF_CHECK(responses.load() >= 8);
    const service::ServerStats stats = server.stats();
    NOF_CHECK_EQ(stats.open_connections, 0u);
    NOF_CHECK_EQ(stats.in_flight_requests, 0u);
    NOF_CHECK(!server.running());
    // Stopping twice is idempotent.
    NOF_CHECK_OK(server.stop());
  }
  const Stats fabric_stats = fixture.ref().stats();
  NOF_CHECK_EQ(fabric_stats.open_connections, 0u);
  NOF_CHECK_EQ(fabric_stats.in_flight_requests, 0u);
  NOF_CHECK(fixture.ref().verify_invariants().clean);
}

NOF_TEST(concurrency, resource_accounting_returns_to_baseline) {
  const std::string path = support::store_path("conc-closure");
  support::remove_store(path);
  for (int cycle = 0; cycle < 5; ++cycle) {
    FabricConfig config;
    config.store_path = path;
    config.clock = std::make_shared<ManualClock>(Micros::raw(1500000));
    config.boot_id = BootId::from_validated("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    Fabric fabric(std::move(config));
    NOF_CHECK_OK(fabric.start());
    const Stats baseline = fabric.stats();
    NOF_CHECK_EQ(baseline.in_flight_requests, 0u);
    NOF_CHECK_EQ(baseline.open_connections, 0u);
    NOF_CHECK_OK(fabric.shutdown());
    const Stats closed = fabric.stats();
    NOF_CHECK_EQ(closed.live_journal_records, 0u);
    NOF_CHECK_OK(fabric.shutdown());
  }
  support::remove_store(path);
}
