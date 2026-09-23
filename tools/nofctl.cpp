// nofctl -- inspection and control tooling for the Network Offload Fabric.
//
// The tool never invents an enforcement plane: it ingests synthetic evidence,
// asks the fabric what it decided, and renders the durable state that resulted.
#include <cstdio>
#if defined(_WIN32)
#include <share.h>
#endif
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "nof/journal.hpp"
#include "nof/service.hpp"
#include "nof/synthetic.hpp"
#include "nof/version.hpp"

namespace {

using nof::Bounds;
using nof::Error;
using nof::Fabric;
using nof::FabricConfig;
using nof::RecoveryPolicy;
using nof::ReasonCode;
using nof::Status;

struct Options {
  std::map<std::string, std::string> flags{};
  std::vector<std::string> positional{};

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
      "nofctl %s -- Network Offload Fabric inspection tooling\n"
      "\n"
      "usage: nofctl <command> [options]\n"
      "\n"
      "commands:\n"
      "  version                     print the runtime version\n"
      "  inspect   --store PATH      recover the store and print canonical state\n"
      "  export    --store PATH      export canonical state (--format json|text|binary)\n"
      "  verify    --store PATH      integrity scan plus the full invariant check\n"
      "  digest    --store PATH      print the state fingerprint\n"
      "  scenario  --store PATH      run a deterministic synthetic workload\n"
      "  crash     --store PATH      crash at a durable boundary (crash-safety proof)\n"
      "  stats     --endpoint H:P    query a running coordinator\n"
      "  invariants--endpoint H:P    query a running coordinator\n"
      "  recovery  --endpoint H:P    query a running coordinator\n"
      "  assignment--endpoint H:P --id ID\n"
      "  explain   --endpoint H:P --id ID\n"
      "\n"
      "common options:\n"
      "  --recovery refuse|truncate_torn_tail|truncate_damaged_tail   (default refuse)\n"
      "  --out FILE                  write command output to a file\n"
      "  --hosts N                   synthetic host count (default 2)\n"
      "  --applies N                 synthetic placement count (default 2)\n"
      "  --boundary B                before_commit|after_commit_before_ack|after_ack_before_effect|\n"
      "                              during_shutdown|during_compaction|before_recovery\n"
      "  --endpoint HOST:PORT        transport endpoint\n"
      "  --id ID                     assignment identifier\n",
      std::string(nof::version_string()).c_str());
}

int fail(const char* message, int code = 2) {
  std::fprintf(stderr, "nofctl: %s\n", message);
  return code;
}

int fail(const Status& status, int code = 2) {
  std::fprintf(stderr, "nofctl: %s\n", nof::to_string(status.error()).c_str());
  return code;
}

int fail(const Error& error, int code = 2) {
  std::fprintf(stderr, "nofctl: %s\n", nof::to_string(error).c_str());
  return code;
}

RecoveryPolicy recovery_from(const Options& options) {
  RecoveryPolicy policy = RecoveryPolicy::Refuse;
  const std::string value = options.get("--recovery", "refuse");
  if (!nof::parse_recovery_policy(value, policy)) {
    std::fprintf(stderr, "nofctl: unknown recovery policy '%s'\n", value.c_str());
    std::exit(1);
  }
  return policy;
}

void write_output(const Options& options, const std::string& text) {
  const std::string out = options.get("--out");
  if (out.empty()) {
    std::fwrite(text.data(), 1, text.size(), stdout);
    if (text.empty() || text.back() != '\n') {
      std::fputc('\n', stdout);
    }
    return;
  }
  std::FILE* file = nullptr;
#if defined(_WIN32)
  file = _fsopen(out.c_str(), "wb", _SH_DENYNO);
#else
  file = std::fopen(out.c_str(), "wb");
#endif
  if (file == nullptr) {
    std::fprintf(stderr, "nofctl: cannot open output file %s\n", out.c_str());
    std::exit(2);
  }
  std::fwrite(text.data(), 1, text.size(), file);
  std::fclose(file);
}

// A pinned logical clock makes a whole process run reproducible: the same
// evidence, the same policy, and the same time produce byte-identical state.
std::shared_ptr<nof::ManualClock> pinned_clock(const Options& options) {
  const std::string value = options.get("--clock-at");
  if (value.empty()) {
    return nullptr;
  }
  try {
    return std::make_shared<nof::ManualClock>(nof::Micros::raw(std::stoll(value)));
  } catch (...) {
    return nullptr;
  }
}

std::unique_ptr<Fabric> open_fabric(const Options& options, std::size_t hosts,
                                    std::function<void(nof::CrashBoundary)> crash_hook) {
  FabricConfig config;
  config.store_path = options.get("--store");
  config.recovery = recovery_from(options);
  config.crash_hook = std::move(crash_hook);
  config.clock = pinned_clock(options);
  if (config.clock) {
    config.boot_id = nof::BootId::from_validated("dddddddddddddddddddddddddddddddd");
  }
  (void)hosts;
  auto fabric = std::make_unique<Fabric>(std::move(config));
  return fabric;
}

Status run_synthetic_workload(Fabric& fabric, std::size_t hosts, std::size_t applies,
                              const Options& options) {
  nof::synthetic::ScenarioOptions scenario_options;
  scenario_options.hosts = hosts;
  scenario_options.sequence_base = options.number("--sequence-base", 1);
  scenario_options.policy_generation = nof::PolicyGeneration::from_validated(
      options.number("--policy-generation", 1));
  scenario_options.topology_generation = nof::TopologyGeneration::from_validated(
      options.number("--topology-generation", 1));
  scenario_options.capability_generation = nof::CapabilityGeneration::from_validated(
      options.number("--capability-generation", 1));
  if (options.has("--clock-at")) {
    try {
      const std::int64_t at = std::stoll(options.get("--clock-at"));
      scenario_options.observed_at = nof::Micros::raw(at);
      scenario_options.valid_until = nof::Micros::raw(at + 1000000);
    } catch (...) {
      return nof::Error(nof::ReasonCode::InvalidConfiguration, "clock value is not an integer");
    }
  }
  const nof::synthetic::Scenario scenario = nof::synthetic::make_scenario(scenario_options);
  Status status = fabric.start();
  if (!status) {
    return status.error();
  }
  for (const nof::FunctionDescriptor& function : scenario.functions) {
    status = fabric.register_function(function);
    if (!status) {
      return status.error();
    }
  }
  status = fabric.ingest_policy(scenario.policy);
  if (!status) {
    return status.error();
  }
  status = fabric.ingest_topology(scenario.topology);
  if (!status) {
    return status.error();
  }
  status = fabric.ingest_capabilities(scenario.capabilities);
  if (!status) {
    return status.error();
  }
  status = fabric.ingest_observations(scenario.observations);
  if (!status) {
    return status.error();
  }
  status = fabric.grant_authority(scenario.authority);
  if (!status) {
    return status.error();
  }
  // Request identities include the sequence base so that a rerun on an
  // existing store does not collide with a committed request.
  const std::string run_tag = std::to_string(scenario_options.sequence_base);
  for (std::size_t index = 0; index < applies; ++index) {
    nof::PlacementRequest request = nof::synthetic::make_request(
        scenario, scenario_options, "req-" + run_tag + "-" + std::to_string(index + 1));
    request.scope.selector = "dir=ingress,proto=tcp,dst=10.0.0." + std::to_string(index + 1) + ":443";
    nof::ApplyOptions apply_options;
    apply_options.request_id = request.request_id;
    auto record = fabric.apply(request, apply_options);
    if (!record) {
      return record.error();
    }
    nof::EffectReport effect;
    effect.request_id =
        nof::RequestId::from_validated("eff-" + run_tag + "-" + std::to_string(index + 1));
    effect.assignment = record.value().id;
    effect.attempt = record.value().attempt;
    effect.generation = record.value().generation;
    effect.fence = record.value().fence;
    effect.incarnation = record.value().incarnation;
    effect.capability_generation = record.value().binding.capability;
    effect.outcome = nof::EffectOutcome::Applied;
    effect.observed_at = scenario_options.observed_at;
    effect.provenance.source = nof::SourceId::from_validated("syn-enforcement");
    effect.provenance.sequence = index + 1;
    auto verified = fabric.report_effect(effect);
    if (!verified) {
      return verified.error();
    }
  }
  return nof::ok_status();
}

int command_inspect(const Options& options) {
  auto fabric = open_fabric(options, 2, nullptr);
  Status status = fabric->start();
  if (!status) {
    return fail(status);
  }
  std::string document;
  const std::string format = options.get("--format", "text");
  nof::ExportFormat export_format = nof::ExportFormat::CanonicalText;
  if (!nof::parse_export_format(format, export_format)) {
    return fail("unknown export format");
  }
  status = fabric->export_canonical(export_format, document);
  if (!status) {
    return fail(status);
  }
  std::string header = fabric->recovery_report().render();
  const nof::InvariantReport invariants = fabric->verify_invariants();
  header += invariants.render();
  write_output(options, header + document);
  const int code = invariants.clean ? 0 : 3;
  (void)fabric->shutdown();
  return code;
}

int command_export(const Options& options) {
  auto fabric = open_fabric(options, 2, nullptr);
  Status status = fabric->start();
  if (!status) {
    return fail(status);
  }
  nof::ExportFormat format = nof::ExportFormat::CanonicalJson;
  if (!nof::parse_export_format(options.get("--format", "json"), format)) {
    return fail("unknown export format");
  }
  std::string document;
  status = fabric->export_canonical(format, document);
  if (!status) {
    return fail(status);
  }
  write_output(options, document);
  (void)fabric->shutdown();
  return 0;
}

int command_digest(const Options& options) {
  auto fabric = open_fabric(options, 2, nullptr);
  Status status = fabric->start();
  if (!status) {
    return fail(status);
  }
  std::printf("%s\n", fabric->state_digest().hex().c_str());
  (void)fabric->shutdown();
  return 0;
}

int command_verify(const Options& options) {
  const std::string path = options.get("--store");
  if (path.empty()) {
    return fail("--store is required");
  }
  nof::RecoveryReport report;
  nof::StoreOpenOptions open_options;
  open_options.create_if_missing = false;
  open_options.recovery = nof::RecoveryPolicy::Refuse;
  auto store = nof::JournalStore::open(path, open_options, report);
  if (!store) {
    std::printf("%s", report.render().c_str());
    return fail(store.error(), 3);
  }
  std::printf("%s", report.render().c_str());
  std::uint64_t records = 0;
  Status status = store.value()->replay([&records](nof::RecordType, std::uint64_t,
                                                   std::span<const std::byte>) {
    records += 1;
    return nof::ok_status();
  });
  if (!status) {
    return fail(status, 3);
  }
  std::printf("records_scanned=%llu\n", static_cast<unsigned long long>(records));
  std::printf("store_id=%s\n", store.value()->store_id().value().c_str());
  (void)store.value()->close();
  return 0;
}

int command_scenario(const Options& options) {
  auto fabric = open_fabric(options, options.number("--hosts", 2), nullptr);
  Status status = run_synthetic_workload(*fabric, options.number("--hosts", 2),
                                         options.number("--applies", 2), options);
  if (!status) {
    return fail(status);
  }
  std::string document;
  status = fabric->export_canonical(nof::ExportFormat::CanonicalText, document);
  if (!status) {
    return fail(status);
  }
  const nof::InvariantReport invariants = fabric->verify_invariants();
  const std::string digest = fabric->state_digest().hex();
  (void)fabric->shutdown();
  std::printf("state_digest=%s\n", digest.c_str());
  std::printf("%s", invariants.render().c_str());
  write_output(options, document);
  return invariants.clean ? 0 : 3;
}

int command_crash(const Options& options) {
  nof::CrashBoundary boundary = nof::CrashBoundary::AfterCommitBeforeAck;
  if (!nof::parse_crash_boundary(options.get("--boundary", "after_commit_before_ack"), boundary)) {
    return fail("unknown crash boundary");
  }
  auto fabric = open_fabric(options, options.number("--hosts", 2),
                            [boundary](nof::CrashBoundary reached) {
                              if (reached != boundary) {
                                return;
                              }
                              std::printf("nofctl: crash boundary %s\n", nof::to_string(boundary));
                              std::fflush(stdout);
                              std::_Exit(70);
                            });
  Status status = run_synthetic_workload(*fabric, options.number("--hosts", 2),
                                         options.number("--applies", 2), options);
  if (!status) {
    return fail(status);
  }
  std::printf("state_digest=%s\n", fabric->state_digest().hex().c_str());
  status = fabric->shutdown();
  if (!status) {
    return fail(status);
  }
  std::printf("completed\n");
  return 0;
}

nof::service::Client* connect_client(const Options& options, std::unique_ptr<nof::service::Client>& holder) {
  const std::string endpoint = options.get("--endpoint");
  const std::size_t colon = endpoint.find(':');
  if (colon == std::string::npos) {
    return nullptr;
  }
  const std::string host = endpoint.substr(0, colon);
  std::uint16_t port = 0;
  try {
    const unsigned long parsed = std::stoul(endpoint.substr(colon + 1));
    if (parsed == 0 || parsed > 65535) {
      return nullptr;
    }
    port = static_cast<std::uint16_t>(parsed);
  } catch (...) {
    return nullptr;
  }
  Bounds bounds;
  auto client = nof::service::Client::connect(host, port, bounds);
  if (!client) {
    return nullptr;
  }
  holder = client.take();
  return holder.get();
}

int run_endpoint_command(const Options& options, const std::string& command) {
  std::unique_ptr<nof::service::Client> holder;
  nof::service::Client* client = connect_client(options, holder);
  if (client == nullptr) {
    return fail("cannot connect to the endpoint");
  }
  Bounds bounds;
  nof::service::Frame request;
  request.request_id = 1;
  nof::BinWriter writer(bounds.max_request_bytes);
  if (command == "stats") {
    request.opcode = nof::service::Opcode::Stats;
  } else if (command == "invariants") {
    request.opcode = nof::service::Opcode::VerifyInvariants;
  } else if (command == "recovery") {
    request.opcode = nof::service::Opcode::RecoveryReport;
  } else if (command == "assignment") {
    request.opcode = nof::service::Opcode::GetAssignment;
    const std::string id = options.get("--id");
    Status status = writer.token(id);
    if (!status) {
      return fail(status, 1);
    }
    request.payload.assign(writer.data().begin(), writer.data().end());
  } else if (command == "explain") {
    request.opcode = nof::service::Opcode::ExplainAssignment;
    const std::string id = options.get("--id");
    Status status = writer.token(id);
    if (!status) {
      return fail(status, 1);
    }
    request.payload.assign(writer.data().begin(), writer.data().end());
  } else {
    return fail("unknown endpoint command", 1);
  }
  auto response = client->call(request);
  if (!response) {
    return fail(response.error());
  }
  if (command == "assignment") {
    nof::BinReader reader(response.value().payload, bounds.max_text_bytes);
    auto record = nof::wire::decode_assignment(reader, bounds);
    if (!record) {
      return fail(record.error());
    }
    std::printf("%s", nof::render_assignment(record.value()).c_str());
    return 0;
  }
  nof::BinReader reader(response.value().payload, bounds.max_text_bytes);
  auto text = reader.text();
  if (!text) {
    return fail(text.error());
  }
  std::printf("%s", text.value().c_str());
  if (!text.value().empty() && text.value().back() != '\n') {
    std::printf("\n");
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  std::string command;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument.rfind("--", 0) == 0) {
      if (index + 1 < argc && std::strncmp(argv[index + 1], "--", 2) != 0) {
        options.flags[argument] = argv[index + 1];
        ++index;
      } else {
        options.flags[argument] = "1";
      }
      continue;
    }
    if (command.empty()) {
      command = argument;
    } else {
      options.positional.push_back(argument);
    }
  }
  if (command.empty() || command == "help" || options.has("--help")) {
    usage();
    return command.empty() ? 1 : 0;
  }
  if (command == "version") {
    std::printf("nofctl %s\n", std::string(nof::version_string()).c_str());
    return 0;
  }
  if (command == "inspect") {
    return command_inspect(options);
  }
  if (command == "export") {
    return command_export(options);
  }
  if (command == "digest") {
    return command_digest(options);
  }
  if (command == "verify") {
    return command_verify(options);
  }
  if (command == "scenario") {
    return command_scenario(options);
  }
  if (command == "crash") {
    return command_crash(options);
  }
  if (command == "stats" || command == "invariants" || command == "recovery" ||
      command == "assignment" || command == "explain") {
    return run_endpoint_command(options, command);
  }
  std::fprintf(stderr, "nofctl: unknown command '%s'\n", command.c_str());
  usage();
  return 1;
}
