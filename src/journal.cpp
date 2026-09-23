#include "nof/journal.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

#include "detail/file_io.hpp"
#include "nof/canonical.hpp"
#include "nof/checked.hpp"
#include "nof/digest.hpp"
#include "nof/version.hpp"

namespace nof {

namespace {

// Journal file layout
//   [0,64)   header: magic, format version, canonical version, header size,
//            flags, store id (32 hex), created-at, header CRC, reserved
//   [64,..)  records: length(4), type(2), flags(2), sequence(8), payload, CRC(4)
constexpr std::uint32_t kJournalMagic = 0x4A464F4Eu;  // bytes 'N','O','F','J'
constexpr std::uint32_t kSnapshotMagic = 0x53464F4Eu;  // bytes 'N','O','F','S'
constexpr std::uint32_t kJournalHeaderSize = 64;
constexpr std::uint32_t kRecordHeaderSize = 20;
constexpr std::uint32_t kRecordTrailerSize = 4;
constexpr std::uint32_t kSnapshotHeaderSize = 36;
constexpr std::uint16_t kRecordFlagNone = 0;

std::uint16_t load_u16(const std::byte* data) {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[0]) |
                                    (static_cast<std::uint16_t>(data[1]) << 8));
}

std::uint32_t load_u32(const std::byte* data) {
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(data[i]) << (i * 8);
  }
  return value;
}

std::uint64_t load_u64(const std::byte* data) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(data[i]) << (i * 8);
  }
  return value;
}

void store_u16(std::byte* out, std::uint16_t value) {
  out[0] = static_cast<std::byte>(value & 0xFFu);
  out[1] = static_cast<std::byte>((value >> 8) & 0xFFu);
}

void store_u32(std::byte* out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out[i] = static_cast<std::byte>((value >> (i * 8)) & 0xFFu);
  }
}

void store_u64(std::byte* out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out[i] = static_cast<std::byte>((value >> (i * 8)) & 0xFFu);
  }
}

std::int64_t now_micros() {
  const auto since_epoch = std::chrono::system_clock::now().time_since_epoch();
  return std::chrono::duration_cast<std::chrono::microseconds>(since_epoch).count();
}

bool is_known_record_type(std::uint16_t raw) {
  RecordType type = RecordType::EpochStarted;
  return parse_record_type(raw, type);
}

struct ScanOutcome {
  std::uint64_t last_good_offset = kJournalHeaderSize;
  std::uint64_t last_sequence = 0;
  std::uint64_t records = 0;
  std::uint64_t discarded_bytes = 0;
  bool torn = false;
  bool damaged = false;
  ReasonCode reason = ReasonCode::Ok;
  std::string detail;
};

ScanOutcome scan_records(std::span<const std::byte> data, std::size_t max_record_bytes) {
  ScanOutcome outcome;
  std::size_t offset = kJournalHeaderSize;
  while (offset < data.size()) {
    const std::size_t remaining = data.size() - offset;
    if (remaining < kRecordHeaderSize + kRecordTrailerSize) {
      // A partial trailing record header: an interrupted commit.
      outcome.torn = true;
      outcome.reason = ReasonCode::JournalTornTail;
      outcome.detail = "partial trailing record header";
      outcome.discarded_bytes = remaining;
      return outcome;
    }
    const std::uint32_t payload_length = load_u32(data.data() + offset);
    const std::uint16_t type_raw = load_u16(data.data() + offset + 4);
    if (payload_length > max_record_bytes) {
      outcome.damaged = true;
      outcome.reason = ReasonCode::OversizedInput;
      outcome.detail = "record length exceeds the configured bound";
      outcome.discarded_bytes = remaining;
      return outcome;
    }
    std::size_t total = 0;
    if (!checked_add(static_cast<std::size_t>(kRecordHeaderSize), static_cast<std::size_t>(payload_length), total) ||
        !checked_add(total, static_cast<std::size_t>(kRecordTrailerSize), total)) {
      outcome.damaged = true;
      outcome.reason = ReasonCode::ArithmeticOverflow;
      outcome.detail = "record length overflow";
      outcome.discarded_bytes = remaining;
      return outcome;
    }
    if (remaining < total) {
      outcome.torn = true;
      outcome.reason = ReasonCode::JournalTornTail;
      outcome.detail = "partial trailing record payload";
      outcome.discarded_bytes = remaining;
      return outcome;
    }
    if (!is_known_record_type(type_raw)) {
      outcome.damaged = true;
      outcome.reason = ReasonCode::StoreCorrupt;
      outcome.detail = "record carries an unknown type";
      outcome.discarded_bytes = remaining;
      return outcome;
    }
    const std::uint32_t stored_crc = load_u32(data.data() + offset + total - kRecordTrailerSize);
    const std::uint32_t computed =
        crc32c(data.subspan(offset, total - kRecordTrailerSize));
    if (stored_crc != computed) {
      outcome.damaged = true;
      outcome.reason = ReasonCode::StoreCorrupt;
      outcome.detail = "record integrity check failed";
      outcome.discarded_bytes = remaining;
      return outcome;
    }
    const std::uint64_t sequence = load_u64(data.data() + offset + 8);
    if (sequence <= outcome.last_sequence && outcome.records > 0) {
      outcome.damaged = true;
      outcome.reason = ReasonCode::SequenceRegression;
      outcome.detail = "record sequence regressed";
      outcome.discarded_bytes = remaining;
      return outcome;
    }
    outcome.last_sequence = sequence;
    outcome.records += 1;
    offset += total;
    outcome.last_good_offset = offset;
  }
  return outcome;
}

std::vector<std::byte> build_header(const StoreId& store_id, std::int64_t created_at,
                                    std::uint32_t format_version) {
  std::vector<std::byte> header(kJournalHeaderSize, std::byte{0});
  store_u32(header.data(), kJournalMagic);
  store_u16(header.data() + 4, static_cast<std::uint16_t>(format_version & 0xFFFFu));
  store_u16(header.data() + 6, kCanonicalEncodingVersion);
  store_u32(header.data() + 8, kJournalHeaderSize);
  store_u32(header.data() + 12, 0);
  const std::string& id = store_id.value();
  if (id.size() != 32) {
    return {};
  }
  std::memcpy(header.data() + 16, id.data(), 32);
  store_u64(header.data() + 48, static_cast<std::uint64_t>(created_at));
  const std::uint32_t crc = crc32c(std::span<const std::byte>(header.data(), 56));
  store_u32(header.data() + 56, crc);
  store_u32(header.data() + 60, 0);
  return header;
}

StoreId generate_store_id() {
  static std::atomic<std::uint64_t> counter{0};
  const std::uint64_t a = static_cast<std::uint64_t>(now_micros());
  const std::uint64_t b = counter.fetch_add(1) ^ 0x9E3779B97F4A7C15ull;
  const Digest digest = sha256(std::string("nof-store") + hex64(a) + hex64(b));
  return StoreId::from_validated(digest.hex().substr(0, 32));
}

}  // namespace

const char* to_string(RecordType value) noexcept {
  switch (value) {
    case RecordType::EpochStarted:
      return "epoch_started";
    case RecordType::FunctionRegistered:
      return "function_registered";
    case RecordType::TopologyIngested:
      return "topology_ingested";
    case RecordType::CapabilityIngested:
      return "capability_ingested";
    case RecordType::PolicyIngested:
      return "policy_ingested";
    case RecordType::ObservationsIngested:
      return "observations_ingested";
    case RecordType::AuthorityGranted:
      return "authority_granted";
    case RecordType::AuthorityWithdrawn:
      return "authority_withdrawn";
    case RecordType::AssignmentCreated:
      return "assignment_created";
    case RecordType::AssignmentTransitioned:
      return "assignment_transitioned";
    case RecordType::EffectRecorded:
      return "effect_recorded";
    case RecordType::ReassignmentRecorded:
      return "reassignment_recorded";
    case RecordType::RequestRecorded:
      return "request_recorded";
    case RecordType::ScopeReleased:
      return "scope_released";
    case RecordType::SnapshotBase:
      return "snapshot_base";
    case RecordType::StoreSealed:
      return "store_sealed";
  }
  return "unknown_record_type";
}

bool parse_record_type(std::uint16_t value, RecordType& out) noexcept {
  switch (value) {
    case 1:
      out = RecordType::EpochStarted;
      return true;
    case 2:
      out = RecordType::FunctionRegistered;
      return true;
    case 3:
      out = RecordType::TopologyIngested;
      return true;
    case 4:
      out = RecordType::CapabilityIngested;
      return true;
    case 5:
      out = RecordType::PolicyIngested;
      return true;
    case 6:
      out = RecordType::ObservationsIngested;
      return true;
    case 7:
      out = RecordType::AuthorityGranted;
      return true;
    case 8:
      out = RecordType::AuthorityWithdrawn;
      return true;
    case 9:
      out = RecordType::AssignmentCreated;
      return true;
    case 10:
      out = RecordType::AssignmentTransitioned;
      return true;
    case 11:
      out = RecordType::EffectRecorded;
      return true;
    case 12:
      out = RecordType::ReassignmentRecorded;
      return true;
    case 13:
      out = RecordType::RequestRecorded;
      return true;
    case 14:
      out = RecordType::ScopeReleased;
      return true;
    case 15:
      out = RecordType::SnapshotBase;
      return true;
    case 16:
      out = RecordType::StoreSealed;
      return true;
    default:
      return false;
  }
}

const char* to_string(CrashBoundary value) noexcept {
  switch (value) {
    case CrashBoundary::BeforeCommit:
      return "before_commit";
    case CrashBoundary::AfterCommitBeforeAck:
      return "after_commit_before_ack";
    case CrashBoundary::AfterAckBeforeEffect:
      return "after_ack_before_effect";
    case CrashBoundary::DuringShutdown:
      return "during_shutdown";
    case CrashBoundary::DuringCompaction:
      return "during_compaction";
    case CrashBoundary::BeforeRecovery:
      return "before_recovery";
  }
  return "unknown_crash_boundary";
}

bool parse_crash_boundary(std::string_view token, CrashBoundary& out) noexcept {
  if (token == "before_commit") {
    out = CrashBoundary::BeforeCommit;
  } else if (token == "after_commit_before_ack") {
    out = CrashBoundary::AfterCommitBeforeAck;
  } else if (token == "after_ack_before_effect") {
    out = CrashBoundary::AfterAckBeforeEffect;
  } else if (token == "during_shutdown") {
    out = CrashBoundary::DuringShutdown;
  } else if (token == "during_compaction") {
    out = CrashBoundary::DuringCompaction;
  } else if (token == "before_recovery") {
    out = CrashBoundary::BeforeRecovery;
  } else {
    return false;
  }
  return true;
}

struct JournalStore::Impl {
  std::string path{};
  std::string snapshot_path{};
  std::string journal_tmp_path{};
  std::string snapshot_tmp_path{};
  StoreOpenOptions options{};
  StoreId store_id{};
  std::int64_t created_at_micros = 0;
  detail::FileHandle journal{};
  std::vector<std::byte> snapshot{};
  std::uint64_t snapshot_covered = 0;
  std::uint64_t snapshot_generation = 0;
  bool has_snapshot = false;
  std::uint64_t last_sequence = 0;
  std::uint64_t records = 0;
  std::uint64_t bytes = 0;
  std::uint64_t bytes_appended = 0;
  std::uint64_t compactions = 0;
  bool closed = false;
  std::function<void()> crash_hook{};
};

JournalStore::JournalStore() : impl_(std::make_unique<Impl>()) {}

JournalStore::~JournalStore() {
  if (impl_ && !impl_->closed) {
    close();
  }
}

Result<std::unique_ptr<JournalStore>> JournalStore::open(const std::string& path,
                                                        const StoreOpenOptions& options,
                                                        RecoveryReport& report) {
  if (path.empty()) {
    return Error(ReasonCode::InvalidConfiguration, "store path is empty");
  }
  if (options.max_record_bytes < 256u || options.max_journal_bytes < options.max_record_bytes ||
      options.max_snapshot_bytes < options.max_record_bytes) {
    return Error(ReasonCode::InvalidConfiguration, "store bounds are not usable");
  }
  Status status = detail::ensure_parent_directory(path);
  if (!status) {
    report.classification = RecoveryClassification::RefusedCorrupt;
    report.reason = status.error().code;
    return status.error();
  }

  auto store = std::unique_ptr<JournalStore>(new JournalStore());
  Impl& impl = *store->impl_;
  impl.path = path;
  impl.snapshot_path = path + ".snapshot";
  impl.journal_tmp_path = path + ".tmp";
  impl.snapshot_tmp_path = impl.snapshot_path + ".tmp";
  impl.options = options;

  // A leftover temporary artifact is an interrupted compaction, never
  // authoritative state. It is removed rather than interpreted.
  if (detail::file_exists(impl.journal_tmp_path)) {
    (void)detail::remove_file(impl.journal_tmp_path);
  }
  if (detail::file_exists(impl.snapshot_tmp_path)) {
    (void)detail::remove_file(impl.snapshot_tmp_path);
  }

  const bool existed = detail::file_exists(path);
  if (!existed && !options.create_if_missing) {
    report.classification = RecoveryClassification::RefusedCorrupt;
    report.reason = ReasonCode::StoreUnavailable;
    return Error(ReasonCode::StoreUnavailable, "store does not exist and creation is disabled");
  }

  auto handle = detail::open_file(path, true, true);
  if (!handle) {
    report.classification = RecoveryClassification::RefusedCorrupt;
    report.reason = handle.error().code;
    return handle.error();
  }
  impl.journal = handle.take();
  impl.created_at_micros = now_micros();

  auto size = detail::file_size(path);
  if (!size) {
    report.classification = RecoveryClassification::RefusedCorrupt;
    report.reason = size.error().code;
    return size.error();
  }

  if (size.value() == 0) {
    const StoreId id = options.expected_store_id.is_set() ? options.expected_store_id
                                                          : generate_store_id();
    const std::vector<std::byte> header =
        build_header(id, impl.created_at_micros, options.format_version);
    if (header.empty()) {
      return Error(ReasonCode::InvalidConfiguration, "store identity is not canonical");
    }
    status = detail::write_all(impl.journal.file, header);
    if (!status) {
      return status.error();
    }
    status = detail::flush_and_sync(impl.journal.file, options.durable_commit);
    if (!status) {
      return status.error();
    }
    impl.store_id = id;
    impl.bytes = kJournalHeaderSize;
    report.classification = existed ? RecoveryClassification::EmptyStore
                                    : RecoveryClassification::FreshStore;
    report.reason = ReasonCode::Ok;
    return store;
  }

  const std::uint64_t read_limit =
      options.max_journal_bytes * 2ull + options.max_record_bytes * 4ull;
  auto data = detail::read_file(path, read_limit);
  if (!data) {
    report.classification = RecoveryClassification::RefusedCorrupt;
    report.reason = data.error().code;
    return data.error();
  }
  if (data.value().size() < kJournalHeaderSize) {
    report.classification = RecoveryClassification::RefusedCorrupt;
    report.reason = ReasonCode::StoreCorrupt;
    return Error(ReasonCode::StoreCorrupt, "store header is truncated");
  }
  const std::span<const std::byte> bytes(data.value().data(), data.value().size());
  if (load_u32(bytes.data()) != kJournalMagic) {
    report.classification = RecoveryClassification::RefusedCorrupt;
    report.reason = ReasonCode::StoreCorrupt;
    return Error(ReasonCode::StoreCorrupt, "store magic does not match");
  }
  const std::uint32_t format_version = load_u16(bytes.data() + 4);
  if (format_version != options.format_version) {
    report.classification = RecoveryClassification::IncompatibleVersion;
    report.reason = ReasonCode::IncompatibleVersion;
    return Error(ReasonCode::IncompatibleVersion, "store format version is incompatible");
  }
  const std::uint16_t canonical_version = load_u16(bytes.data() + 6);
  if (canonical_version != kCanonicalEncodingVersion) {
    report.classification = RecoveryClassification::IncompatibleSemantics;
    report.reason = ReasonCode::IncompatibleSemantics;
    return Error(ReasonCode::IncompatibleSemantics, "store semantics version is incompatible");
  }
  if (load_u32(bytes.data() + 8) != kJournalHeaderSize) {
    report.classification = RecoveryClassification::RefusedCorrupt;
    report.reason = ReasonCode::StoreCorrupt;
    return Error(ReasonCode::StoreCorrupt, "store header size is not recognized");
  }
  if (load_u32(bytes.data() + 56) != crc32c(bytes.subspan(0, 56))) {
    report.classification = RecoveryClassification::RefusedCorrupt;
    report.reason = ReasonCode::StoreCorrupt;
    return Error(ReasonCode::StoreCorrupt, "store header integrity check failed");
  }
  const std::string id_text(reinterpret_cast<const char*>(bytes.data() + 16), 32);
  auto store_id = StoreId::parse(id_text);
  if (!store_id) {
    report.classification = RecoveryClassification::RefusedCorrupt;
    report.reason = store_id.error().code;
    return store_id.error();
  }
  if (options.expected_store_id.is_set() && !(options.expected_store_id == store_id.value())) {
    report.classification = RecoveryClassification::RefusedCorrupt;
    report.reason = ReasonCode::UnknownIdentity;
    return Error(ReasonCode::UnknownIdentity, "store identity does not match the expected identity");
  }
  impl.store_id = store_id.value();
  impl.created_at_micros = static_cast<std::int64_t>(load_u64(bytes.data() + 48));

  // Snapshot base (if any) must be validated before the journal tail is
  // interpreted, because it determines which records are already covered.
  if (detail::file_exists(impl.snapshot_path)) {
    auto snapshot_data = detail::read_file(impl.snapshot_path, options.max_snapshot_bytes);
    if (!snapshot_data) {
      report.classification = RecoveryClassification::RefusedCorrupt;
      report.reason = snapshot_data.error().code;
      return snapshot_data.error();
    }
    const std::span<const std::byte> snap(snapshot_data.value().data(),
                                          snapshot_data.value().size());
    if (snap.size() < kSnapshotHeaderSize || load_u32(snap.data()) != kSnapshotMagic) {
      report.classification = RecoveryClassification::RefusedCorrupt;
      report.reason = ReasonCode::StoreCorrupt;
      return Error(ReasonCode::StoreCorrupt, "snapshot magic or header is invalid");
    }
    if (load_u16(snap.data() + 4) != options.format_version ||
        load_u16(snap.data() + 6) != kCanonicalEncodingVersion) {
      report.classification = RecoveryClassification::IncompatibleVersion;
      report.reason = ReasonCode::IncompatibleVersion;
      return Error(ReasonCode::IncompatibleVersion, "snapshot version is incompatible");
    }
    const std::uint32_t payload_length = load_u32(snap.data() + 8);
    if (payload_length > options.max_snapshot_bytes) {
      report.classification = RecoveryClassification::RefusedCorrupt;
      report.reason = ReasonCode::OversizedInput;
      return Error(ReasonCode::OversizedInput, "snapshot payload exceeds the configured bound");
    }
    if (load_u32(snap.data() + 32) != crc32c(snap.subspan(0, 32))) {
      report.classification = RecoveryClassification::RefusedCorrupt;
      report.reason = ReasonCode::StoreCorrupt;
      return Error(ReasonCode::StoreCorrupt, "snapshot header integrity check failed");
    }
    if (snap.size() != kSnapshotHeaderSize + payload_length) {
      report.classification = RecoveryClassification::RefusedCorrupt;
      report.reason = ReasonCode::StoreCorrupt;
      return Error(ReasonCode::StoreCorrupt, "snapshot size does not match its header");
    }
    const std::span<const std::byte> payload = snap.subspan(kSnapshotHeaderSize);
    if (load_u32(snap.data() + 12) != crc32c(payload)) {
      report.classification = RecoveryClassification::RefusedCorrupt;
      report.reason = ReasonCode::StoreCorrupt;
      return Error(ReasonCode::StoreCorrupt, "snapshot payload integrity check failed");
    }
    impl.snapshot.assign(payload.begin(), payload.end());
    impl.snapshot_covered = load_u64(snap.data() + 16);
    impl.snapshot_generation = load_u64(snap.data() + 24);
    impl.has_snapshot = true;
  }

  ScanOutcome outcome = scan_records(bytes, options.max_record_bytes);
  impl.last_sequence = outcome.last_sequence;
  impl.records = outcome.records;
  impl.bytes = bytes.size();
  report.records_replayed = outcome.records;
  report.records_discarded = outcome.discarded_bytes > 0 ? 1u : 0u;
  report.bytes_discarded = outcome.discarded_bytes;
  report.store_generation = StoreGeneration::from_validated(
      impl.snapshot_generation == 0 ? 1u : impl.snapshot_generation);

  if (outcome.torn || outcome.damaged) {
    const bool tail_truncation_allowed =
        (outcome.torn && options.recovery == RecoveryPolicy::TruncateTornTail) ||
        options.recovery == RecoveryPolicy::TruncateDamagedTail;
    if (!tail_truncation_allowed) {
      report.classification = RecoveryClassification::RefusedCorrupt;
      report.reason = outcome.reason;
      return Error(outcome.reason, "store tail is not usable under the configured recovery policy: " +
                                       outcome.detail);
    }
    // `last_good_offset` is already an absolute file position.
    status = detail::truncate_to(impl.journal.file, outcome.last_good_offset);
    if (!status) {
      report.classification = RecoveryClassification::RefusedCorrupt;
      report.reason = status.error().code;
      return status.error();
    }
    status = detail::flush_and_sync(impl.journal.file, options.durable_commit);
    if (!status) {
      report.classification = RecoveryClassification::RefusedCorrupt;
      report.reason = status.error().code;
      return status.error();
    }
    impl.bytes = outcome.last_good_offset;
    report.classification = outcome.torn ? RecoveryClassification::TornTailTruncated
                                         : RecoveryClassification::DamagedTailTruncated;
    report.reason = outcome.reason;
    return store;
  }

  report.classification = RecoveryClassification::CleanReopen;
  report.reason = ReasonCode::Ok;
  return store;
}

Result<StoreHeaderInfo> JournalStore::read_header(const std::string& path) {
  auto data = detail::read_file(path, 4096);
  if (!data) {
    return data.error();
  }
  const std::span<const std::byte> bytes(data.value().data(), data.value().size());
  StoreHeaderInfo info;
  if (bytes.size() < kJournalHeaderSize) {
    return Error(ReasonCode::StoreTruncated, "store header is truncated");
  }
  if (load_u32(bytes.data()) != kJournalMagic) {
    return Error(ReasonCode::StoreCorrupt, "store magic does not match");
  }
  if (load_u32(bytes.data() + 56) != crc32c(bytes.subspan(0, 56))) {
    return Error(ReasonCode::StoreCorrupt, "store header integrity check failed");
  }
  const std::string id_text(reinterpret_cast<const char*>(bytes.data() + 16), 32);
  auto store_id = StoreId::parse(id_text);
  if (!store_id) {
    return store_id.error();
  }
  info.store_id = store_id.value();
  info.format_version = load_u16(bytes.data() + 4);
  info.canonical_version = load_u16(bytes.data() + 6);
  info.created_at_micros = static_cast<std::int64_t>(load_u64(bytes.data() + 48));
  info.present = true;
  return info;
}

Status JournalStore::append(RecordType type, std::span<const std::byte> payload) {
  Impl& impl = *impl_;
  if (impl.closed) {
    return Error(ReasonCode::StoreClosed, "store is closed");
  }
  if (payload.size() > impl.options.max_record_bytes) {
    return Error(ReasonCode::OversizedInput, "record payload exceeds the configured bound");
  }
  std::size_t record_size = 0;
  if (!checked_add(static_cast<std::size_t>(kRecordHeaderSize), payload.size(), record_size) ||
      !checked_add(record_size, static_cast<std::size_t>(kRecordTrailerSize), record_size)) {
    return Error(ReasonCode::ArithmeticOverflow, "record size overflow");
  }
  std::uint64_t hard_cap = 0;
  if (!checked_mul(static_cast<std::uint64_t>(impl.options.max_journal_bytes), std::uint64_t{2},
                   hard_cap)) {
    return Error(ReasonCode::ArithmeticOverflow, "journal cap overflow");
  }
  std::uint64_t projected = 0;
  if (!checked_add(impl.bytes, static_cast<std::uint64_t>(record_size), projected)) {
    return Error(ReasonCode::ArithmeticOverflow, "journal size overflow");
  }
  if (projected > hard_cap) {
    return Error(ReasonCode::CompactionRequired,
                 "journal reached its hard size cap and must be compacted");
  }

  std::uint64_t sequence = 0;
  if (!checked_add(impl.last_sequence, std::uint64_t{1}, sequence)) {
    return Error(ReasonCode::ArithmeticOverflow, "journal sequence exhausted");
  }

  std::vector<std::byte> record(record_size, std::byte{0});
  store_u32(record.data(), static_cast<std::uint32_t>(payload.size()));
  store_u16(record.data() + 4, static_cast<std::uint16_t>(type));
  store_u16(record.data() + 6, kRecordFlagNone);
  store_u64(record.data() + 8, sequence);
  if (!payload.empty()) {
    std::memcpy(record.data() + kRecordHeaderSize, payload.data(), payload.size());
  }
  const std::uint32_t crc =
      crc32c(std::span<const std::byte>(record.data(), record_size - kRecordTrailerSize));
  store_u32(record.data() + record_size - kRecordTrailerSize, crc);

  Status status = detail::write_all(impl.journal.file, record);
  if (!status) {
    return status.error();
  }
  status = detail::flush_and_sync(impl.journal.file, impl.options.durable_commit);
  if (!status) {
    return status.error();
  }
  impl.last_sequence = sequence;
  impl.records += 1;
  impl.bytes += record_size;
  impl.bytes_appended += record_size;
  return ok_status();
}

Status JournalStore::replay(const RecordVisitor& visitor) const {
  const Impl& impl = *impl_;
  if (impl.closed) {
    return Error(ReasonCode::StoreClosed, "store is closed");
  }
  auto data = detail::read_file(impl.path,
                                impl.options.max_journal_bytes * 2ull +
                                    impl.options.max_record_bytes * 4ull);
  if (!data) {
    return data.error();
  }
  const std::span<const std::byte> bytes(data.value().data(), data.value().size());
  if (bytes.size() < kJournalHeaderSize) {
    return Error(ReasonCode::StoreTruncated, "store header is truncated");
  }
  std::size_t offset = kJournalHeaderSize;
  while (offset < bytes.size()) {
    const std::size_t remaining = bytes.size() - offset;
    if (remaining < kRecordHeaderSize + kRecordTrailerSize) {
      return ok_status();
    }
    const std::uint32_t payload_length = load_u32(bytes.data() + offset);
    const std::uint16_t type_raw = load_u16(bytes.data() + offset + 4);
    const std::size_t total = kRecordHeaderSize + payload_length + kRecordTrailerSize;
    if (remaining < total) {
      return ok_status();
    }
    const std::uint64_t sequence = load_u64(bytes.data() + offset + 8);
    RecordType type = RecordType::SnapshotBase;
    if (!parse_record_type(type_raw, type)) {
      return Error(ReasonCode::StoreCorrupt, "record carries an unknown type");
    }
    const std::uint32_t stored_crc = load_u32(bytes.data() + offset + total - kRecordTrailerSize);
    if (stored_crc != crc32c(bytes.subspan(offset, total - kRecordTrailerSize))) {
      return Error(ReasonCode::StoreCorrupt, "record integrity check failed during replay");
    }
    if (type != RecordType::SnapshotBase && sequence > impl.snapshot_covered) {
      const std::span<const std::byte> payload =
          bytes.subspan(offset + kRecordHeaderSize, payload_length);
      const Status status = visitor(type, sequence, payload);
      if (!status) {
        return status.error();
      }
    }
    offset += total;
  }
  return ok_status();
}

Result<std::vector<std::byte>> JournalStore::snapshot_payload() const {
  const Impl& impl = *impl_;
  if (!impl.has_snapshot) {
    return Error(ReasonCode::NotFound, "store has no snapshot");
  }
  return impl.snapshot;
}

Status JournalStore::compact(std::span<const std::byte> snapshot, std::uint64_t covered_sequence,
                             std::uint64_t new_generation) {
  Impl& impl = *impl_;
  if (impl.closed) {
    return Error(ReasonCode::StoreClosed, "store is closed");
  }
  if (snapshot.size() > impl.options.max_snapshot_bytes) {
    return Error(ReasonCode::OversizedInput, "snapshot exceeds the configured bound");
  }
  if (covered_sequence < impl.snapshot_covered) {
    return Error(ReasonCode::SequenceRegression, "snapshot would move backwards");
  }

  // 1. Install the snapshot atomically.
  {
    std::vector<std::byte> header(kSnapshotHeaderSize, std::byte{0});
    store_u32(header.data(), kSnapshotMagic);
    store_u16(header.data() + 4, static_cast<std::uint16_t>(impl.options.format_version & 0xFFFFu));
    store_u16(header.data() + 6, kCanonicalEncodingVersion);
    store_u32(header.data() + 8, static_cast<std::uint32_t>(snapshot.size()));
    store_u32(header.data() + 12, crc32c(snapshot));
    store_u64(header.data() + 16, covered_sequence);
    store_u64(header.data() + 24, new_generation);
    store_u32(header.data() + 32, crc32c(std::span<const std::byte>(header.data(), 32)));
    auto tmp = detail::open_file(impl.snapshot_tmp_path, true, false, true);
    if (!tmp) {
      return tmp.error();
    }
    Status status = detail::write_all(tmp.value().file, header);
    if (!status) {
      return status.error();
    }
    status = detail::write_all(tmp.value().file, snapshot);
    if (!status) {
      return status.error();
    }
    status = detail::flush_and_sync(tmp.value().file, impl.options.durable_commit);
    if (!status) {
      return status.error();
    }
    tmp.value().close();
    status = detail::atomic_replace(impl.snapshot_tmp_path, impl.snapshot_path);
    if (!status) {
      return status.error();
    }
  }

  if (impl.crash_hook) {
    impl.crash_hook();
  }

  // 2. Replace the journal with a fresh file that records the snapshot base.
  const std::vector<std::byte> header =
      build_header(impl.store_id, impl.created_at_micros, impl.options.format_version);
  if (header.empty()) {
    return Error(ReasonCode::InvalidConfiguration, "store identity is not canonical");
  }
  impl.journal.close();
  {
    auto tmp = detail::open_file(impl.journal_tmp_path, true, false, true);
    if (!tmp) {
      return tmp.error();
    }
    Status status = detail::write_all(tmp.value().file, header);
    if (!status) {
      return status.error();
    }
    status = detail::flush_and_sync(tmp.value().file, impl.options.durable_commit);
    if (!status) {
      return status.error();
    }
    tmp.value().close();
    status = detail::atomic_replace(impl.journal_tmp_path, impl.path);
    if (!status) {
      return status.error();
    }
  }
  auto reopened = detail::open_file(impl.path, true, true);
  if (!reopened) {
    return reopened.error();
  }
  impl.journal = reopened.take();
  impl.bytes = kJournalHeaderSize;
  impl.records = 0;
  impl.last_sequence = covered_sequence;
  impl.snapshot.assign(snapshot.begin(), snapshot.end());
  impl.snapshot_covered = covered_sequence;
  impl.snapshot_generation = new_generation;
  impl.has_snapshot = true;
  impl.compactions += 1;

  // 3. Record the snapshot base so the journal is self-describing.
  std::vector<std::byte> base(24, std::byte{0});
  store_u64(base.data(), covered_sequence);
  store_u64(base.data() + 8, new_generation);
  store_u64(base.data() + 16, 0);
  return append(RecordType::SnapshotBase, base);
}

void JournalStore::set_crash_hook(std::function<void()> hook) {
  impl_->crash_hook = std::move(hook);
}

Status JournalStore::flush() {
  Impl& impl = *impl_;
  if (impl.closed) {
    return Error(ReasonCode::StoreClosed, "store is closed");
  }
  return detail::flush_and_sync(impl.journal.file, impl.options.durable_commit);
}

Status JournalStore::seal(std::uint64_t epoch) {
  std::vector<std::byte> payload(8, std::byte{0});
  store_u64(payload.data(), epoch);
  return append(RecordType::StoreSealed, payload);
}

Status JournalStore::close() {
  Impl& impl = *impl_;
  if (impl.closed) {
    return ok_status();
  }
  Status status = ok_status();
  if (impl.journal.valid()) {
    status = detail::flush_and_sync(impl.journal.file, impl.options.durable_commit);
    impl.journal.close();
  }
  impl.closed = true;
  return status;
}

bool JournalStore::closed() const noexcept { return impl_->closed; }

const StoreId& JournalStore::store_id() const noexcept { return impl_->store_id; }

StoreGeneration JournalStore::generation() const noexcept {
  return StoreGeneration::from_validated(impl_->snapshot_generation == 0 ? 1u
                                                                        : impl_->snapshot_generation);
}

std::uint64_t JournalStore::last_sequence() const noexcept { return impl_->last_sequence; }

std::uint64_t JournalStore::record_count() const noexcept { return impl_->records; }

std::uint64_t JournalStore::journal_bytes() const noexcept { return impl_->bytes; }

std::uint64_t JournalStore::snapshot_bytes() const noexcept { return impl_->snapshot.size(); }

std::uint64_t JournalStore::compactions() const noexcept { return impl_->compactions; }

std::uint64_t JournalStore::bytes_appended() const noexcept { return impl_->bytes_appended; }

std::vector<std::string> JournalStore::artifacts() const {
  std::vector<std::string> out;
  for (const std::string& candidate :
       {impl_->path, impl_->snapshot_path, impl_->journal_tmp_path, impl_->snapshot_tmp_path}) {
    if (detail::file_exists(candidate)) {
      out.push_back(candidate);
    }
  }
  return out;
}

}  // namespace nof
