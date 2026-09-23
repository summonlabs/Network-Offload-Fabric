// nofd -- the Network Offload Fabric coordinator service.
//
// One process owns one durable store. The service is a real socket endpoint so
// that multiprocess behaviour can be exercised with independent OS processes
// rather than with threads pretending to be processes.
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "nof/journal.hpp"
#include "nof/service.hpp"
#include "nof/synthetic.hpp"
#include "nof/version.hpp"

namespace {

std::atomic<bool> g_stop_requested{false};
std::mutex g_stop_mutex;
std::condition_variable g_stop_cv;

void request_stop() {
  g_stop_requested.store(true, std::memory_order_release);
  g_stop_cv.notify_all();
}

void handle_signal(int) {
  // Best-effort wakeup. A hard kill is equally safe: the store is crash-safe by
  // construction, and every commit is complete or explicitly classified.
  request_stop();
}

struct Options {
  std::map<std::string, std::string> flags{};

  bool has(const std::string& key) const { return flags.find(key) != flags.end(); }

  std::string get(const std::string& key, const std::string& fallback = std::string()) const {
    const auto it = flags.find(key);
    if (it == flags.end()) {
      return fallback;
    }
    return it->second;
  }

  std::size_t number(const std::string& key, std::size_t fallback) const {
    const auto it = flags.find(key);
    if (it == flags.end()) {
      return fallback;
    }
    try {
      return static_cast<std::size_t>(std::stoull(it->second));
    } catch (...) {
      return fallback;
    }
  }
};

void usage() {
  std::printf(
      "nofd %s -- Network Offload Fabric coordinator service\n"
      "\n"
      "usage: nofd --store PATH [options]\n"
      "\n"
      "options:\n"
      "  --bind ADDRESS          listen address (default 127.0.0.1)\n"
      "  --port PORT             listen port, 0 selects an ephemeral port (default 0)\n"
      "  --workers N             worker threads (default 2)\n"
      "  --max-connections N     concurrent connection ceiling (default 8)\n"
      "  --queue N               pending connection queue depth (default 16)\n"
      "  --recovery MODE         refuse|truncate_torn_tail|truncate_damaged_tail\n"
      "  --no-durable            disable fsync on commit (weakened durability)\n"
      "  --seed                  ingest the synthetic fixture scenario at startup\n",
      std::string(nof::version_string()).c_str());
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument.rfind("--", 0) != 0) {
      continue;
    }
    if (index + 1 < argc && std::strncmp(argv[index + 1], "--", 2) != 0) {
      options.flags[argument] = argv[index + 1];
      ++index;
    } else {
      options.flags[argument] = "1";
    }
  }
  if (options.has("--help")) {
    usage();
    return 0;
  }
  nof::FabricConfig config;
  config.store_path = options.get("--store");
  if (config.store_path.empty()) {
    usage();
    std::fprintf(stderr, "nofd: --store is required\n");
    return 1;
  }
  if (!nof::parse_recovery_policy(options.get("--recovery", "refuse"), config.recovery)) {
    std::fprintf(stderr, "nofd: unknown recovery policy\n");
    return 1;
  }
  config.durable_commit = !options.has("--no-durable");

  nof::Fabric fabric(std::move(config));
  nof::Status status = fabric.start();
  if (!status) {
    std::fprintf(stderr, "nofd: start failed: %s\n", nof::to_string(status.error()).c_str());
    return 2;
  }
  if (options.has("--seed")) {
    nof::synthetic::ScenarioOptions scenario_options;
    const nof::synthetic::Scenario scenario = nof::synthetic::make_scenario(scenario_options);
    for (const nof::FunctionDescriptor& function : scenario.functions) {
      (void)fabric.register_function(function);
    }
    (void)fabric.ingest_policy(scenario.policy);
    (void)fabric.ingest_topology(scenario.topology);
    (void)fabric.ingest_capabilities(scenario.capabilities);
    (void)fabric.ingest_observations(scenario.observations);
    (void)fabric.grant_authority(scenario.authority);
  }

  nof::service::ServerConfig server_config;
  server_config.bind_address = options.get("--bind", "127.0.0.1");
  server_config.port = static_cast<std::uint16_t>(options.number("--port", 0));
  server_config.max_workers = options.number("--workers", 2);
  server_config.max_connections = options.number("--max-connections", 8);
  server_config.max_queue_depth = options.number("--queue", 16);
  server_config.shutdown_hook = []() { request_stop(); };

  nof::service::Server server(fabric, server_config);
  status = server.start();
  if (!status) {
    std::fprintf(stderr, "nofd: listen failed: %s\n", nof::to_string(status.error()).c_str());
    (void)fabric.shutdown();
    return 2;
  }
  std::signal(SIGINT, handle_signal);
  std::printf("nofd listening on %s\n", server.endpoint().c_str());
  std::printf("nofd store=%s\n", options.get("--store").c_str());
  std::printf("nofd ready\n");
  std::fflush(stdout);

  {
    std::unique_lock<std::mutex> lock(g_stop_mutex);
    g_stop_cv.wait(lock, []() { return g_stop_requested.load(std::memory_order_acquire); });
  }
  (void)server.stop();
  status = fabric.shutdown();
  const nof::service::ServerStats stats = server.stats();
  std::printf("nofd stopped connections=%llu requests=%llu refusals=%llu\n",
              static_cast<unsigned long long>(stats.connections_accepted),
              static_cast<unsigned long long>(stats.requests_handled),
              static_cast<unsigned long long>(stats.requests_refused));
  std::fflush(stdout);
  return status ? 0 : 2;
}
