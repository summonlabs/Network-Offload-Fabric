#include "support.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

#if defined(_WIN32)
#include <io.h>
#include <share.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace nof::support {

std::string store_path(const std::string& name) {
  std::string path = "nof-test-";
  path += name;
  path += ".nofjournal";
  return path;
}

void remove_store(const std::string& path) {
  (void)std::remove(path.c_str());
  (void)std::remove((path + ".snapshot").c_str());
  (void)std::remove((path + ".tmp").c_str());
  (void)std::remove((path + ".snapshot.tmp").c_str());
}

std::string read_file_text(const std::string& path) {
  std::ifstream stream(path, std::ios::binary);
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

void write_file_bytes(const std::string& path, const std::string& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::trunc);
  stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

void append_file_bytes(const std::string& path, const std::string& bytes) {
  std::ofstream stream(path, std::ios::binary | std::ios::app);
  stream.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

void truncate_file(const std::string& path, std::size_t size) {
#if defined(_WIN32)
  std::FILE* file = _fsopen(path.c_str(), "r+b", _SH_DENYNO);
  if (file == nullptr) {
    return;
  }
  (void)_chsize_s(_fileno(file), static_cast<__int64>(size));
  std::fclose(file);
#else
  (void)truncate(path.c_str(), static_cast<off_t>(size));
#endif
}

std::size_t file_bytes(const std::string& path) {
  std::ifstream stream(path, std::ios::binary | std::ios::ate);
  if (!stream) {
    return 0;
  }
  return static_cast<std::size_t>(stream.tellg());
}

Fixture::Fixture(const std::string& name, bool durable, nof::RecoveryPolicy recovery)
    : Fixture(name, nof::synthetic::ScenarioOptions{}, durable, recovery) {}

Fixture::Fixture(const std::string& name, const nof::synthetic::ScenarioOptions& scenario_options,
                 bool durable, nof::RecoveryPolicy recovery) {
  path = store_path(name);
  remove_store(path);
  options = scenario_options;
  if (options.hosts == 0) {
    options.hosts = 2;
  }
  if (options.observed_at.value() == 0) {
    options.observed_at = nof::Micros::raw(1000000);
  }
  if (options.valid_until.value() == 0) {
    options.valid_until = nof::Micros::raw(2000000);
  }
  scenario = nof::synthetic::make_scenario(options);
  clock = std::make_shared<nof::ManualClock>(nof::Micros::raw(1500000));
  nof::FabricConfig config;
  config.store_path = path;
  config.recovery = recovery;
  config.durable_commit = durable;
  config.clock = clock;
  config.boot_id = nof::BootId::from_validated("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  fabric = std::make_unique<nof::Fabric>(std::move(config));
  (void)reopen(recovery);
  ingest_all();
}

Fixture::~Fixture() {
  if (fabric) {
    (void)fabric->shutdown();
  }
  remove_store(path);
}

nof::Status Fixture::reopen(nof::RecoveryPolicy recovery,
                            std::function<void(nof::CrashBoundary)> hook) {
  nof::FabricConfig config;
  config.store_path = path;
  config.recovery = recovery;
  config.clock = clock;
  config.boot_id = nof::BootId::from_validated("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  config.crash_hook = std::move(hook);
  fabric = std::make_unique<nof::Fabric>(std::move(config));
  return fabric->start();
}

void Fixture::ingest_all() {
  for (const nof::FunctionDescriptor& function : scenario.functions) {
    const nof::Status status = fabric->register_function(function);
    if (!status.ok()) {
      return;
    }
  }
  (void)fabric->ingest_policy(scenario.policy);
  (void)fabric->ingest_topology(scenario.topology);
  (void)fabric->ingest_capabilities(scenario.capabilities);
  (void)fabric->ingest_observations(scenario.observations);
  (void)fabric->grant_authority(scenario.authority);
}

nof::PlacementRequest Fixture::request(const std::string& id, bool replacement) const {
  return nof::synthetic::make_request(scenario, options, id, replacement);
}

nof::Result<nof::AssignmentRecord> Fixture::apply(const std::string& id, bool replacement) {
  nof::PlacementRequest placement = request(id, replacement);
  nof::ApplyOptions apply_options;
  apply_options.request_id = placement.request_id;
  apply_options.allow_replacement = replacement;
  return fabric->apply(placement, apply_options);
}

nof::Status Fixture::effect(const nof::AssignmentRecord& record, nof::EffectOutcome outcome,
                            const std::string& request_id) {
  nof::EffectReport report;
  report.request_id = nof::RequestId::from_validated(request_id);
  report.assignment = record.id;
  report.attempt = record.attempt;
  report.generation = record.generation;
  report.fence = record.fence;
  report.incarnation = record.incarnation;
  report.capability_generation = record.binding.capability;
  report.outcome = outcome;
  report.observed_at = clock->now();
  report.provenance.source = nof::SourceId::from_validated("syn-enforcement");
  report.provenance.sequence = 1;
  const auto result = fabric->report_effect(report);
  if (!result.ok()) {
    return result.error();
  }
  return nof::ok_status();
}

void ingest_evidence(nof::Fabric& fabric, const nof::synthetic::Scenario& scenario) {
  for (const nof::FunctionDescriptor& function : scenario.functions) {
    (void)fabric.register_function(function);
  }
  (void)fabric.ingest_policy(scenario.policy);
  (void)fabric.ingest_topology(scenario.topology);
  (void)fabric.ingest_capabilities(scenario.capabilities);
  (void)fabric.ingest_observations(scenario.observations);
  (void)fabric.grant_authority(scenario.authority);
}

nof::synthetic::Scenario fresh_scenario(nof::synthetic::ScenarioOptions options,
                                        std::uint64_t sequence_base,
                                        nof::TopologyGeneration generation) {
  options.sequence_base = sequence_base;
  options.topology_generation = generation;
  // New evidence is a new generation of policy, capability, and topology: the
  // restart floor refuses replayed sequences, and a changed payload at the same
  // generation is a conflict by design.
  options.policy_generation =
      nof::PolicyGeneration::from_validated(options.policy_generation.value() + 1);
  options.capability_generation =
      nof::CapabilityGeneration::from_validated(options.capability_generation.value() + 1);
  return nof::synthetic::make_scenario(options);
}

std::string shell_quote(const std::string& value) { return "\"" + value + "\""; }

std::string nofd_path() {
#ifdef NOF_NOFD_PATH
  return NOF_NOFD_PATH;
#else
  return "nofd";
#endif
}

std::string nofctl_path() {
#ifdef NOF_NOFCTL_PATH
  return NOF_NOFCTL_PATH;
#else
  return "nofctl";
#endif
}

ChildProcess::ChildProcess(const std::string& command) {
#if defined(_WIN32)
  // cmd.exe strips the outer quotes of a quoted program path unless the whole
  // command is quoted, which matters because checkout paths contain spaces.
  pipe_ = _popen(("\"" + command + "\"").c_str(), "r");
#else
  pipe_ = popen(command.c_str(), "r");
#endif
}

ChildProcess::~ChildProcess() {
  if (pipe_ != nullptr && !waited_) {
    (void)wait();
  }
}

std::string ChildProcess::read_line() {
  std::string line;
  if (pipe_ == nullptr) {
    return line;
  }
  int next = 0;
  while ((next = std::fgetc(pipe_)) != EOF) {
    if (next == '\n') {
      return line;
    }
    line.push_back(static_cast<char>(next));
  }
  return line;
}

std::string ChildProcess::read_until(const std::string& marker) {
  std::string collected;
  if (pipe_ == nullptr) {
    return collected;
  }
  for (;;) {
    std::string line;
    bool read_anything = false;
    int next = 0;
    while ((next = std::fgetc(pipe_)) != EOF) {
      read_anything = true;
      if (next == '\n') {
        break;
      }
      line.push_back(static_cast<char>(next));
    }
    if (!read_anything) {
      return collected;
    }
    collected += line;
    collected += "\n";
    if (line.find(marker) != std::string::npos) {
      return collected;
    }
  }
}

int ChildProcess::wait() {
  if (pipe_ == nullptr) {
    return -1;
  }
  waited_ = true;
#if defined(_WIN32)
  const int code = _pclose(pipe_);
#else
  const int code = pclose(pipe_);
#endif
  pipe_ = nullptr;
  return code;
}

int exit_code_of(int system_status) {
#if defined(_WIN32)
  return system_status;
#else
  if (WIFEXITED(system_status)) {
    return WEXITSTATUS(system_status);
  }
  return -system_status;
#endif
}

ProcessResult run_process(const std::string& command) {
  ProcessResult result;
  const std::string line = command + " > nof-test-process.out 2>&1";
  result.exit_code = exit_code_of(std::system(line.c_str()));
  result.output = read_file_text("nof-test-process.out");
  return result;
}

}  // namespace nof::support
