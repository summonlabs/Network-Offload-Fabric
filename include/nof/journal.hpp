#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "nof/bounds.hpp"
#include "nof/error.hpp"
#include "nof/fabric.hpp"
#include "nof/ids.hpp"

// Versioned, integrity-checked, crash-safe persistence.
//
// Layout on disk:
//   <path>            append-only journal of committed records
//   <path>.snapshot   atomically replaced state snapshot used to bound growth
//
// Every record carries a type, a monotonic sequence, a payload, and a CRC-32C
// over the whole record. A partial trailing record is a torn tail; damage
// anywhere else is corruption. Neither is ever silently accepted: the open
// reports an explicit classification and only proceeds under the configured
// recovery policy.
namespace nof {

enum class RecordType : std::uint16_t {
  EpochStarted = 1,
  FunctionRegistered = 2,
  TopologyIngested = 3,
  CapabilityIngested = 4,
  PolicyIngested = 5,
  ObservationsIngested = 6,
  AuthorityGranted = 7,
  AuthorityWithdrawn = 8,
  AssignmentCreated = 9,
  AssignmentTransitioned = 10,
  EffectRecorded = 11,
  ReassignmentRecorded = 12,
  RequestRecorded = 13,
  ScopeReleased = 14,
  SnapshotBase = 15,
  StoreSealed = 16,
};

const char* to_string(RecordType value) noexcept;
bool parse_record_type(std::uint16_t value, RecordType& out) noexcept;

struct StoreOpenOptions {
  bool create_if_missing = true;
  RecoveryPolicy recovery = RecoveryPolicy::Refuse;
  bool durable_commit = true;
  std::size_t max_journal_bytes = 64u * 1024u * 1024u;
  std::size_t max_snapshot_bytes = 64u * 1024u * 1024u;
  std::size_t max_record_bytes = 4u * 1024u * 1024u;
  // When set, opening a store whose header carries a different identity is
  // refused instead of adopting the on-disk identity.
  StoreId expected_store_id{};
  std::uint32_t format_version = 1;
};

struct StoreHeaderInfo {
  StoreId store_id{};
  std::uint32_t format_version = 0;
  std::uint16_t canonical_version = 0;
  std::int64_t created_at_micros = 0;
  bool present = false;
};

using RecordVisitor =
    std::function<Status(RecordType type, std::uint64_t sequence, std::span<const std::byte> payload)>;

class JournalStore {
 public:
  ~JournalStore();
  JournalStore(const JournalStore&) = delete;
  JournalStore& operator=(const JournalStore&) = delete;

  // Opens (or creates) the journal, validates the header, scans every record,
  // and classifies the outcome into `report`.
  static Result<std::unique_ptr<JournalStore>> open(const std::string& path,
                                                    const StoreOpenOptions& options,
                                                    RecoveryReport& report);

  // Reads just the header without mutating the store. Used by tooling.
  static Result<StoreHeaderInfo> read_header(const std::string& path);

  // Appends a record and commits it durably (when durable mode is on). The
  // record is only visible to readers after this call returns success.
  Status append(RecordType type, std::span<const std::byte> payload);

  // Visits records in sequence order, skipping anything already covered by the
  // snapshot base.
  Status replay(const RecordVisitor& visitor) const;

  // Returns the snapshot payload installed by the last successful compaction.
  Result<std::vector<std::byte>> snapshot_payload() const;

  // Installs a snapshot atomically and then truncates the journal. Crash-safe
  // in both orders: the snapshot records the sequence it covers, and replay
  // skips records at or below that sequence.
  Status compact(std::span<const std::byte> snapshot, std::uint64_t covered_sequence,
                 std::uint64_t new_generation);

  // Installs a hook invoked between the atomic snapshot replacement and the
  // journal replacement during compaction. The runtime uses it to prove that a
  // crash in that window is recovered consistently.
  void set_crash_hook(std::function<void()> hook);

  Status flush();
  Status seal(std::uint64_t epoch);
  Status close();
  bool closed() const noexcept;

  const StoreId& store_id() const noexcept;
  StoreGeneration generation() const noexcept;
  std::uint64_t last_sequence() const noexcept;
  std::uint64_t record_count() const noexcept;
  std::uint64_t journal_bytes() const noexcept;
  std::uint64_t snapshot_bytes() const noexcept;
  std::uint64_t compactions() const noexcept;
  std::uint64_t bytes_appended() const noexcept;
  std::vector<std::string> artifacts() const;

 private:
  JournalStore();

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace nof
