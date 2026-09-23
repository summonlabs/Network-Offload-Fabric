#pragma once

#include <functional>
#include <memory>
#include <string>

#include "nof/fabric.hpp"
#include "nof/synthetic.hpp"

// Shared helpers for the suites: bounded temporary store paths, a deterministic
// manual clock, and a fixture that stands up a fully evidenced fabric.
namespace nof::support {

std::string store_path(const std::string& name);
void remove_store(const std::string& path);

std::string read_file_text(const std::string& path);
void write_file_bytes(const std::string& path, const std::string& bytes);
void append_file_bytes(const std::string& path, const std::string& bytes);
void truncate_file(const std::string& path, std::size_t size);
std::size_t file_bytes(const std::string& path);

struct Fixture {
  nof::synthetic::ScenarioOptions options{};
  nof::synthetic::Scenario scenario{};
  std::shared_ptr<nof::ManualClock> clock{};
  std::unique_ptr<nof::Fabric> fabric{};
  std::string path{};

  explicit Fixture(const std::string& name, bool durable = true,
                   nof::RecoveryPolicy recovery = nof::RecoveryPolicy::Refuse);
  // Variant with explicit synthetic scenario options, used by the cases that
  // need a different policy or topology shape from the first ingest onwards.
  Fixture(const std::string& name, const nof::synthetic::ScenarioOptions& options,
          bool durable = true,
          nof::RecoveryPolicy recovery = nof::RecoveryPolicy::Refuse);
  ~Fixture();

  nof::Fabric& ref() { return *fabric; }

  // Restarts the fabric against the same store, the way a fresh process would.
  nof::Status reopen(nof::RecoveryPolicy recovery = nof::RecoveryPolicy::Refuse,
                     std::function<void(nof::CrashBoundary)> hook = nullptr);

  void ingest_all();
  nof::PlacementRequest request(const std::string& id, bool replacement = false) const;
  nof::Result<nof::AssignmentRecord> apply(const std::string& id, bool replacement = false);
  nof::Status effect(const nof::AssignmentRecord& record, nof::EffectOutcome outcome,
                     const std::string& request_id);
};

struct ProcessResult {
  int exit_code = -1;
  std::string output{};
};

// Ingests a complete synthetic evidence set into an arbitrary fabric. Used
// after a restart, where replayed provenance sequences must not be reused.
void ingest_evidence(nof::Fabric& fabric, const nof::synthetic::Scenario& scenario);

// Builds a scenario with a fresh sequence base and topology generation.
nof::synthetic::Scenario fresh_scenario(nof::synthetic::ScenarioOptions options,
                                        std::uint64_t sequence_base,
                                        nof::TopologyGeneration generation);

// Runs a real child process through the platform shell and captures its output.
ProcessResult run_process(const std::string& command);

// A long-lived child process whose standard output is read through a pipe. Used
// to prove multiprocess behaviour with real OS processes and real sockets
// instead of threads pretending to be processes.
class ChildProcess {
 public:
  explicit ChildProcess(const std::string& command);
  ~ChildProcess();

  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  bool valid() const { return pipe_ != nullptr; }
  // Blocking line read. Returns an empty string at end of file.
  std::string read_line();
  // Reads lines until the marker is seen, returning everything read so far.
  std::string read_until(const std::string& marker);
  // Waits for process exit and returns its exit code.
  int wait();

 private:
  std::FILE* pipe_ = nullptr;
  bool waited_ = false;
};

std::string nofd_path();
std::string nofctl_path();
std::string shell_quote(const std::string& value);
int exit_code_of(int system_status);

}  // namespace nof::support
