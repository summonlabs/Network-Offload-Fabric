#include "nof/fabric.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <functional>
#include <mutex>
#include <random>
#include <set>

#include "detail/fabric_state.hpp"
#include "detail/file_io.hpp"
#include "nof/canonical.hpp"
#include "nof/checked.hpp"
#include "nof/digest.hpp"
#include "nof/journal.hpp"
#include "nof/version.hpp"
#include "nof/wire.hpp"

namespace nof {

namespace detail {

const char* to_string(EvidenceDomain value) noexcept {
  switch (value) {
    case EvidenceDomain::Topology:
      return "topology";
    case EvidenceDomain::Capability:
      return "capability";
    case EvidenceDomain::Policy:
      return "policy";
    case EvidenceDomain::Observation:
      return "observation";
    case EvidenceDomain::Authority:
      return "authority";
  }
  return "unknown_evidence_domain";
}

SourceState& FabricState::source_state(const SourceId& source, EvidenceDomain domain) {
  SourceKey key;
  key.source = source;
  key.domain = domain;
  return sources[key];
}

const SourceState* FabricState::find_source(const SourceId& source,
                                            EvidenceDomain domain) const {
  SourceKey key;
  key.source = source;
  key.domain = domain;
  const auto it = sources.find(key);
  if (it == sources.end()) {
    return nullptr;
  }
  return &it->second;
}

DemandVector committed_demand_for(const FabricState& state, const DeviceId& device) {
  const auto it = state.committed.find(device);
  if (it == state.committed.end()) {
    return DemandVector{};
  }
  return it->second;
}

}  // namespace detail

namespace {

using detail::CapabilityKey;
using detail::EvidenceDomain;
using detail::ExclusivityKeyLess;
using detail::FabricState;
using detail::IdempotencyEntry;
using detail::SourceKey;
using detail::SourceState;

// ---------------------------------------------------------------------------
// Deterministic identifier and token issuance
// ---------------------------------------------------------------------------

std::uint64_t parse_ordinal(const std::string& token, std::string_view prefix) {
  if (token.size() != prefix.size() + 16 || token.compare(0, prefix.size(), prefix) != 0) {
    return 0;
  }
  std::uint64_t value = 0;
  for (std::size_t i = prefix.size(); i < token.size(); ++i) {
    const char c = token[i];
    std::uint64_t digit = 0;
    if (c >= '0' && c <= '9') {
      digit = static_cast<std::uint64_t>(c - '0');
    } else if (c >= 'a' && c <= 'f') {
      digit = static_cast<std::uint64_t>(c - 'a' + 10);
    } else {
      return 0;
    }
    value = (value << 4) | digit;
  }
  return value;
}

Result<AssignmentId> issue_assignment_id(FabricState& state) {
  std::uint64_t ordinal = 0;
  if (!checked_add(state.next_assignment_ordinal, std::uint64_t{1}, ordinal)) {
    return Error(ReasonCode::ArithmeticOverflow, "assignment ordinal exhausted");
  }
  state.next_assignment_ordinal = ordinal;
  return AssignmentId::parse("as-" + hex64(ordinal));
}

Result<LeaseId> issue_lease(FabricState& state) {
  std::uint64_t value = 0;
  if (!checked_add(state.next_lease, std::uint64_t{1}, value)) {
    return Error(ReasonCode::ArithmeticOverflow, "lease counter exhausted");
  }
  state.next_lease = value;
  return LeaseId::from_validated(value);
}

Result<AttemptId> issue_attempt(FabricState& state) {
  std::uint64_t value = 0;
  if (!checked_add(state.next_attempt, std::uint64_t{1}, value)) {
    return Error(ReasonCode::ArithmeticOverflow, "attempt counter exhausted");
  }
  state.next_attempt = value;
  return AttemptId::from_validated(value);
}

Result<FencingToken> issue_fence(FabricState& state) {
  std::uint64_t sequence = 0;
  if (!checked_add(state.next_fence_sequence, std::uint64_t{1}, sequence)) {
    return Error(ReasonCode::ArithmeticOverflow, "fencing token counter exhausted");
  }
  state.next_fence_sequence = sequence;
  FencingToken token;
  token.epoch = state.epoch.counter;
  token.sequence = sequence;
  return token;
}

BootId generate_boot_id() {
  std::random_device device;
  const std::uint64_t a = (static_cast<std::uint64_t>(device()) << 32) ^
                          static_cast<std::uint64_t>(device());
  const std::uint64_t b = static_cast<std::uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  const Digest digest = sha256(std::string("nof-boot") + hex64(a) + hex64(b));
  return BootId::from_validated(digest.hex().substr(0, 32));
}

// ---------------------------------------------------------------------------
// Record payload encoding
// ---------------------------------------------------------------------------

struct RecordedAssignment {
  AssignmentRecord record{};
  RequestId request_id{};
  Digest request_fingerprint{};
};

Status encode_recorded_assignment(const RecordedAssignment& value, BinWriter& writer,
                                 const Bounds& bounds) {
  Status status = wire::encode_assignment(value.record, writer, bounds);
  if (!status) {
    return status;
  }
  status = writer.token(value.request_id.view());
  if (!status) {
    return status;
  }
  return writer.digest(value.request_fingerprint);
}

Result<RecordedAssignment> decode_recorded_assignment(BinReader& reader, const Bounds& bounds) {
  auto record = wire::decode_assignment(reader, bounds);
  if (!record) {
    return record.error();
  }
  auto request_id = reader.token();
  if (!request_id) {
    return request_id.error();
  }
  auto fingerprint = reader.digest();
  if (!fingerprint) {
    return fingerprint.error();
  }
  RecordedAssignment out;
  out.record = record.take();
  out.request_id = RequestId::from_validated(request_id.take());
  out.request_fingerprint = fingerprint.value();
  return out;
}

struct RecordedEffect {
  EffectReport report{};
  AssignmentRecord record{};
  RequestId request_id{};
  Digest request_fingerprint{};
};

Status encode_recorded_effect(const RecordedEffect& value, BinWriter& writer,
                             const Bounds& bounds) {
  Status status = wire::encode_effect_report(value.report, writer);
  if (!status) {
    return status;
  }
  status = wire::encode_assignment(value.record, writer, bounds);
  if (!status) {
    return status;
  }
  status = writer.token(value.request_id.view());
  if (!status) {
    return status;
  }
  return writer.digest(value.request_fingerprint);
}

Result<RecordedEffect> decode_recorded_effect(BinReader& reader, const Bounds& bounds) {
  auto report = wire::decode_effect_report(reader, bounds);
  if (!report) {
    return report.error();
  }
  auto record = wire::decode_assignment(reader, bounds);
  if (!record) {
    return record.error();
  }
  auto request_id = reader.token();
  if (!request_id) {
    return request_id.error();
  }
  auto fingerprint = reader.digest();
  if (!fingerprint) {
    return fingerprint.error();
  }
  RecordedEffect out;
  out.report = report.take();
  out.record = record.take();
  out.request_id = RequestId::from_validated(request_id.take());
  out.request_fingerprint = fingerprint.value();
  return out;
}

struct RecordedWithdrawal {
  AuthorityId authority{};
  ReasonCode reason = ReasonCode::AuthorityWithdrawn;
  Micros at{};
  RequestId request_id{};
  Digest request_fingerprint{};
};

Status encode_recorded_withdrawal(const RecordedWithdrawal& value, BinWriter& writer) {
  Status status = writer.token(value.authority.view());
  if (!status) {
    return status;
  }
  status = writer.u16(static_cast<std::uint16_t>(value.reason));
  if (!status) {
    return status;
  }
  status = writer.i64(value.at.value());
  if (!status) {
    return status;
  }
  status = writer.token(value.request_id.view());
  if (!status) {
    return status;
  }
  return writer.digest(value.request_fingerprint);
}

Result<RecordedWithdrawal> decode_recorded_withdrawal(BinReader& reader) {
  RecordedWithdrawal out;
  auto authority = reader.token();
  if (!authority) {
    return authority.error();
  }
  out.authority = AuthorityId::from_validated(authority.take());
  auto reason = reader.u16();
  if (!reason) {
    return reason.error();
  }
  if (std::string_view(to_string(static_cast<ReasonCode>(reason.value()))) == "UNKNOWN_REASON") {
    return Error(ReasonCode::UnsupportedValue, "unknown reason code in withdrawal record");
  }
  out.reason = static_cast<ReasonCode>(reason.value());
  auto at = reader.i64();
  if (!at) {
    return at.error();
  }
  out.at = Micros::raw(at.value());
  auto request_id = reader.token();
  if (!request_id) {
    return request_id.error();
  }
  out.request_id = RequestId::from_validated(request_id.take());
  auto fingerprint = reader.digest();
  if (!fingerprint) {
    return fingerprint.error();
  }
  out.request_fingerprint = fingerprint.value();
  return out;
}

struct RecordedRequest {
  RequestId request_id{};
  Digest request_fingerprint{};
  ReasonCode outcome = ReasonCode::Ok;
  std::vector<std::byte> response{};
  Micros at{};
};

Status encode_recorded_request(const RecordedRequest& value, BinWriter& writer) {
  Status status = writer.token(value.request_id.view());
  if (!status) {
    return status;
  }
  status = writer.digest(value.request_fingerprint);
  if (!status) {
    return status;
  }
  status = writer.u16(static_cast<std::uint16_t>(value.outcome));
  if (!status) {
    return status;
  }
  status = writer.i64(value.at.value());
  if (!status) {
    return status;
  }
  return writer.bytes(value.response);
}

Result<RecordedRequest> decode_recorded_request(BinReader& reader, const Bounds& bounds) {
  RecordedRequest out;
  auto request_id = reader.token();
  if (!request_id) {
    return request_id.error();
  }
  out.request_id = RequestId::from_validated(request_id.take());
  auto fingerprint = reader.digest();
  if (!fingerprint) {
    return fingerprint.error();
  }
  out.request_fingerprint = fingerprint.value();
  auto outcome = reader.u16();
  if (!outcome) {
    return outcome.error();
  }
  if (std::string_view(to_string(static_cast<ReasonCode>(outcome.value()))) == "UNKNOWN_REASON") {
    return Error(ReasonCode::UnsupportedValue, "unknown reason code in request record");
  }
  out.outcome = static_cast<ReasonCode>(outcome.value());
  auto at = reader.i64();
  if (!at) {
    return at.error();
  }
  out.at = Micros::raw(at.value());
  auto payload = reader.take_bytes(bounds.max_record_bytes);
  if (!payload) {
    return payload.error();
  }
  out.response.assign(payload.value().begin(), payload.value().end());
  return out;
}

// --- error envelope used for idempotent refusal replay ----------------------

Status encode_error_envelope(const Error& error, BinWriter& writer, const Bounds& bounds) {
  Status status = writer.u16(static_cast<std::uint16_t>(error.code));
  if (!status) {
    return status;
  }
  std::string detail = error.detail;
  if (detail.size() > bounds.max_reason_detail_bytes) {
    detail.resize(bounds.max_reason_detail_bytes);
  }
  return writer.text(detail);
}

Result<Error> decode_error_envelope(BinReader& reader) {
  auto code = reader.u16();
  if (!code) {
    return code.error();
  }
  if (std::string_view(to_string(static_cast<ReasonCode>(code.value()))) == "UNKNOWN_REASON") {
    return Error(ReasonCode::UnsupportedValue, "unknown reason code in error envelope");
  }
  auto detail = reader.text();
  if (!detail) {
    return detail.error();
  }
  Error out;
  out.code = static_cast<ReasonCode>(code.value());
  out.detail = detail.take();
  return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// FabricState canonical encoding
// ---------------------------------------------------------------------------

namespace detail {

Status encode_state(const FabricState& state, BinWriter& writer, const Bounds& bounds) {
  Status status = writer.u16(kCanonicalEncodingVersion);
  if (!status) {
    return status;
  }
  status = wire::encode_epoch(state.epoch, writer);
  if (!status) {
    return status;
  }
  const std::uint64_t counters[6] = {state.epoch_counter,        state.previous_epoch_counter,
                                     state.next_assignment_ordinal, state.next_lease,
                                     state.next_attempt,         state.next_fence_sequence};
  for (const std::uint64_t counter : counters) {
    status = writer.u64(counter);
    if (!status) {
      return status;
    }
  }
  status = writer.u32(static_cast<std::uint32_t>(state.functions.size()));
  if (!status) {
    return status;
  }
  for (const auto& entry : state.functions) {
    status = wire::encode_function(entry.second, writer);
    if (!status) {
      return status;
    }
  }
  status = writer.presence(state.has_topology);
  if (!status) {
    return status;
  }
  if (state.has_topology) {
    status = wire::encode_topology(state.topology, writer, bounds);
    if (!status) {
      return status;
    }
  }
  status = writer.digest(state.topology_digest);
  if (!status) {
    return status;
  }
  status = writer.u32(static_cast<std::uint32_t>(state.capabilities.size()));
  if (!status) {
    return status;
  }
  for (const auto& entry : state.capabilities) {
    status = wire::encode_capability_record(entry.second, writer, bounds);
    if (!status) {
      return status;
    }
  }
  status = writer.presence(state.has_policy);
  if (!status) {
    return status;
  }
  if (state.has_policy) {
    status = wire::encode_policy(state.policy, writer, bounds);
    if (!status) {
      return status;
    }
  }
  status = writer.digest(state.policy_digest);
  if (!status) {
    return status;
  }
  status = writer.u32(static_cast<std::uint32_t>(state.observations.size()));
  if (!status) {
    return status;
  }
  for (const auto& entry : state.observations) {
    status = wire::encode_observation(entry.second, writer);
    if (!status) {
      return status;
    }
  }
  status = writer.u32(static_cast<std::uint32_t>(state.authority.size()));
  if (!status) {
    return status;
  }
  for (const auto& entry : state.authority) {
    status = wire::encode_authority(entry.second, writer, bounds);
    if (!status) {
      return status;
    }
  }
  status = writer.u32(static_cast<std::uint32_t>(state.assignments.size()));
  if (!status) {
    return status;
  }
  for (const auto& entry : state.assignments) {
    status = wire::encode_assignment(entry.second, writer, bounds);
    if (!status) {
      return status;
    }
  }
  status = writer.u32(static_cast<std::uint32_t>(state.scope_specs.size()));
  if (!status) {
    return status;
  }
  for (const auto& entry : state.scope_specs) {
    status = writer.token(entry.first.view());
    if (!status) {
      return status;
    }
    status = wire::encode_scope_spec(entry.second, writer);
    if (!status) {
      return status;
    }
  }
  status = writer.u32(static_cast<std::uint32_t>(state.sources.size()));
  if (!status) {
    return status;
  }
  for (const auto& entry : state.sources) {
    status = writer.token(entry.first.source.view());
    if (!status) {
      return status;
    }
    status = writer.u8(static_cast<std::uint8_t>(entry.first.domain));
    if (!status) {
      return status;
    }
    status = writer.u64(entry.second.last_sequence);
    if (!status) {
      return status;
    }
    status = writer.u64(entry.second.restart_floor);
    if (!status) {
      return status;
    }
    status = writer.digest(entry.second.last_digest);
    if (!status) {
      return status;
    }
    status = writer.boolean(entry.second.seen);
    if (!status) {
      return status;
    }
  }
  status = writer.u32(static_cast<std::uint32_t>(state.reassignments.size()));
  if (!status) {
    return status;
  }
  for (const auto& entry : state.reassignments) {
    status = writer.token(entry.first.scope.view());
    if (!status) {
      return status;
    }
    status = writer.u16(static_cast<std::uint16_t>(entry.first.cls));
    if (!status) {
      return status;
    }
    status = writer.u32(static_cast<std::uint32_t>(entry.second.size()));
    if (!status) {
      return status;
    }
    for (const Micros stamp : entry.second) {
      status = writer.i64(stamp.value());
      if (!status) {
        return status;
      }
    }
  }
  status = writer.u32(static_cast<std::uint32_t>(state.idempotency.size()));
  if (!status) {
    return status;
  }
  for (const auto& entry : state.idempotency) {
    status = writer.token(entry.first.view());
    if (!status) {
      return status;
    }
    status = writer.digest(entry.second.request_fingerprint);
    if (!status) {
      return status;
    }
    status = writer.u16(static_cast<std::uint16_t>(entry.second.outcome));
    if (!status) {
      return status;
    }
    status = writer.i64(entry.second.at.value());
    if (!status) {
      return status;
    }
    status = writer.bytes(entry.second.response);
    if (!status) {
      return status;
    }
  }
  return ok_status();
}

namespace {

Result<bool> read_presence(BinReader& reader) {
  auto value = reader.presence();
  if (!value) {
    return value.error();
  }
  return value.value();
}

Result<std::uint32_t> read_count(BinReader& reader, std::size_t max_count) {
  auto value = reader.u32();
  if (!value) {
    return value.error();
  }
  if (value.value() > max_count) {
    return Error(ReasonCode::LimitExceeded, "state collection exceeds the configured bound");
  }
  return value.value();
}

}  // namespace

Result<FabricState> decode_state(BinReader& reader, const Bounds& bounds) {
  FabricState state;
  auto version = reader.u16();
  if (!version) {
    return version.error();
  }
  if (version.value() != kCanonicalEncodingVersion) {
    return Error(ReasonCode::IncompatibleSemantics, "state encoding version is not supported");
  }
  auto epoch = wire::decode_epoch(reader);
  if (!epoch) {
    return epoch.error();
  }
  state.epoch = epoch.take();
  const auto read_u64 = [&](std::uint64_t& out) -> Status {
    auto value = reader.u64();
    if (!value) {
      return value.error();
    }
    out = value.value();
    return ok_status();
  };
  Status status = read_u64(state.epoch_counter);
  if (!status) {
    return status.error();
  }
  status = read_u64(state.previous_epoch_counter);
  if (!status) {
    return status.error();
  }
  status = read_u64(state.next_assignment_ordinal);
  if (!status) {
    return status.error();
  }
  status = read_u64(state.next_lease);
  if (!status) {
    return status.error();
  }
  status = read_u64(state.next_attempt);
  if (!status) {
    return status.error();
  }
  status = read_u64(state.next_fence_sequence);
  if (!status) {
    return status.error();
  }

  auto function_count = read_count(reader, bounds.max_functions);
  if (!function_count) {
    return function_count.error();
  }
  for (std::uint32_t i = 0; i < function_count.value(); ++i) {
    auto function = wire::decode_function(reader, bounds);
    if (!function) {
      return function.error();
    }
    state.functions.emplace(function.value().id, function.take());
  }

  auto has_topology = read_presence(reader);
  if (!has_topology) {
    return has_topology.error();
  }
  state.has_topology = has_topology.value();
  if (state.has_topology) {
    auto topology = wire::decode_topology(reader, bounds);
    if (!topology) {
      return topology.error();
    }
    state.topology = topology.take();
  }
  auto topology_digest = reader.digest();
  if (!topology_digest) {
    return topology_digest.error();
  }
  state.topology_digest = topology_digest.value();

  auto capability_count = read_count(reader, bounds.max_capability_records);
  if (!capability_count) {
    return capability_count.error();
  }
  for (std::uint32_t i = 0; i < capability_count.value(); ++i) {
    auto record = wire::decode_capability_record(reader, bounds);
    if (!record) {
      return record.error();
    }
    CapabilityKey key;
    key.device = record.value().device;
    key.cls = record.value().cls;
    state.capabilities.emplace(key, record.take());
  }

  auto has_policy = read_presence(reader);
  if (!has_policy) {
    return has_policy.error();
  }
  state.has_policy = has_policy.value();
  if (state.has_policy) {
    auto policy = wire::decode_policy(reader, bounds);
    if (!policy) {
      return policy.error();
    }
    state.policy = policy.take();
  }
  auto policy_digest = reader.digest();
  if (!policy_digest) {
    return policy_digest.error();
  }
  state.policy_digest = policy_digest.value();

  auto observation_count = read_count(reader, bounds.max_observations);
  if (!observation_count) {
    return observation_count.error();
  }
  for (std::uint32_t i = 0; i < observation_count.value(); ++i) {
    auto observation = wire::decode_observation(reader);
    if (!observation) {
      return observation.error();
    }
    state.observations.emplace(observation.value().device, observation.take());
  }

  auto authority_count = read_count(reader, bounds.max_authority_grants);
  if (!authority_count) {
    return authority_count.error();
  }
  for (std::uint32_t i = 0; i < authority_count.value(); ++i) {
    auto grant = wire::decode_authority(reader, bounds);
    if (!grant) {
      return grant.error();
    }
    state.authority.emplace(grant.value().id, grant.take());
  }

  auto assignment_count = read_count(reader, bounds.max_assignments);
  if (!assignment_count) {
    return assignment_count.error();
  }
  for (std::uint32_t i = 0; i < assignment_count.value(); ++i) {
    auto record = wire::decode_assignment(reader, bounds);
    if (!record) {
      return record.error();
    }
    state.assignments.emplace(record.value().id, record.take());
  }

  auto scope_count = read_count(reader, bounds.max_scopes);
  if (!scope_count) {
    return scope_count.error();
  }
  for (std::uint32_t i = 0; i < scope_count.value(); ++i) {
    auto scope_id = reader.token();
    if (!scope_id) {
      return scope_id.error();
    }
    auto spec = wire::decode_scope_spec(reader);
    if (!spec) {
      return spec.error();
    }
    state.scope_specs.emplace(ScopeId::from_validated(scope_id.take()), spec.take());
  }

  auto source_count = read_count(reader, bounds.max_sources);
  if (!source_count) {
    return source_count.error();
  }
  for (std::uint32_t i = 0; i < source_count.value(); ++i) {
    auto source = reader.token();
    if (!source) {
      return source.error();
    }
    auto domain = reader.u8();
    if (!domain) {
      return domain.error();
    }
    if (domain.value() < 1 || domain.value() > 5) {
      return Error(ReasonCode::UnsupportedValue, "state carries an unknown evidence domain");
    }
    SourceKey key;
    key.source = SourceId::from_validated(source.take());
    key.domain = static_cast<EvidenceDomain>(domain.value());
    SourceState value;
    auto sequence = reader.u64();
    if (!sequence) {
      return sequence.error();
    }
    value.last_sequence = sequence.value();
    auto floor_value = reader.u64();
    if (!floor_value) {
      return floor_value.error();
    }
    value.restart_floor = floor_value.value();
    auto digest = reader.digest();
    if (!digest) {
      return digest.error();
    }
    value.last_digest = digest.value();
    auto seen = read_presence(reader);
    if (!seen) {
      return seen.error();
    }
    value.seen = seen.value();
    state.sources.emplace(key, value);
  }

  auto reassignment_count = read_count(reader, bounds.max_scopes);
  if (!reassignment_count) {
    return reassignment_count.error();
  }
  for (std::uint32_t i = 0; i < reassignment_count.value(); ++i) {
    auto scope = reader.token();
    if (!scope) {
      return scope.error();
    }
    auto cls = reader.u16();
    if (!cls) {
      return cls.error();
    }
    if (std::string_view(to_string(static_cast<FunctionClass>(cls.value()))) ==
        "unknown_function_class") {
      return Error(ReasonCode::UnsupportedValue, "state carries an unknown function class");
    }
    ExclusivityKey key;
    key.scope = ScopeId::from_validated(scope.take());
    key.cls = static_cast<FunctionClass>(cls.value());
    auto stamp_count = read_count(reader, bounds.max_reassignments_per_scope * 64u);
    if (!stamp_count) {
      return stamp_count.error();
    }
    std::deque<Micros> stamps;
    for (std::uint32_t s = 0; s < stamp_count.value(); ++s) {
      auto stamp = reader.i64();
      if (!stamp) {
        return stamp.error();
      }
      stamps.push_back(Micros::raw(stamp.value()));
    }
    state.reassignments.emplace(key, std::move(stamps));
  }

  auto idempotency_count = read_count(reader, bounds.max_idempotency_entries);
  if (!idempotency_count) {
    return idempotency_count.error();
  }
  for (std::uint32_t i = 0; i < idempotency_count.value(); ++i) {
    auto request_id = reader.token();
    if (!request_id) {
      return request_id.error();
    }
    const RequestId id = RequestId::from_validated(request_id.take());
    IdempotencyEntry entry;
    auto fingerprint = reader.digest();
    if (!fingerprint) {
      return fingerprint.error();
    }
    entry.request_fingerprint = fingerprint.value();
    auto outcome = reader.u16();
    if (!outcome) {
      return outcome.error();
    }
    if (std::string_view(to_string(static_cast<ReasonCode>(outcome.value()))) ==
        "UNKNOWN_REASON") {
      return Error(ReasonCode::UnsupportedValue, "state carries an unknown reason code");
    }
    entry.outcome = static_cast<ReasonCode>(outcome.value());
    auto at = reader.i64();
    if (!at) {
      return at.error();
    }
    entry.at = Micros::raw(at.value());
    auto length = reader.u32();
    if (!length) {
      return length.error();
    }
    if (length.value() > bounds.max_record_bytes) {
      return Error(ReasonCode::OversizedInput, "state response payload exceeds the bound");
    }
    auto payload = reader.take_raw(length.value());
    if (!payload) {
      return payload.error();
    }
    entry.response.assign(payload.value().begin(), payload.value().end());
    state.idempotency.emplace(id, std::move(entry));
    state.idempotency_order.push_back(id);
  }
  if (!reader.at_end()) {
    return Error(ReasonCode::MalformedInput, "state encoding carries trailing bytes");
  }
  return state;
}

Digest compute_state_digest(const FabricState& state, const Bounds& bounds) {
  BinWriter writer(bounds.max_canonical_bytes);
  const Status status = encode_state(state, writer, bounds);
  if (!status) {
    return Digest::zero();
  }
  return writer.fingerprint();
}

void rebuild_indexes(FabricState& state) {
  state.exclusive_by_class.clear();
  state.exclusive_by_scope.clear();
  state.committed.clear();
  state.scope_specs.clear();
  for (auto& entry : state.assignments) {
    AssignmentRecord& record = entry.second;
    if (!is_live(record.state)) {
      continue;
    }
    if (!record.scope_id.empty()) {
      state.scope_specs[record.scope_id] = record.scope;
    }
    const std::uint64_t ordinal = parse_ordinal(record.id.value(), "as-");
    if (ordinal > state.next_assignment_ordinal) {
      state.next_assignment_ordinal = ordinal;
    }
    if (record.lease.value() > state.next_lease) {
      state.next_lease = record.lease.value();
    }
    if (record.attempt.value() > state.next_attempt) {
      state.next_attempt = record.attempt.value();
    }
    if (record.fence.sequence > state.next_fence_sequence &&
        record.fence.epoch == state.epoch.counter) {
      state.next_fence_sequence = record.fence.sequence;
    }
    if (record.exclusivity == Exclusivity::Exclusive && holds_authority(record.state)) {
      ExclusivityKey key;
      key.scope = record.scope_id;
      key.cls = record.cls;
      if (record.exclusive_key == ExclusiveKeyMode::PerClass) {
        state.exclusive_by_class[key] = record.id;
      } else {
        state.exclusive_by_scope[record.scope_id] = record.id;
      }
    }
    if (holds_authority(record.state)) {
      DemandVector& used = state.committed[record.device];
      std::uint64_t pps = 0;
      std::uint64_t bps = 0;
      std::uint64_t flows = 0;
      std::uint64_t queues = 0;
      std::uint64_t memory = 0;
      (void)checked_add(used.packets_per_second.value(), record.demand.packets_per_second.value(), pps);
      (void)checked_add(used.bytes_per_second.value(), record.demand.bytes_per_second.value(), bps);
      (void)checked_add(used.flows.value(), record.demand.flows.value(), flows);
      (void)checked_add(used.queues.value(), record.demand.queues.value(), queues);
      (void)checked_add(used.memory.value(), record.demand.memory.value(), memory);
      used.packets_per_second = PacketRate::raw(pps);
      used.bytes_per_second = ByteRate::raw(bps);
      used.flows = FlowCount::raw(flows);
      used.queues = QueueCount::raw(queues);
      used.memory = ByteSize::raw(memory);
    }
  }
  for (auto& entry : state.authority) {
    entry.second.used = 0;
  }
  for (const auto& entry : state.assignments) {
    if (holds_authority(entry.second.state) && !entry.second.authority.empty()) {
      const auto grant = state.authority.find(entry.second.authority);
      if (grant != state.authority.end()) {
        grant->second.used += 1;
      }
    }
  }
}

}  // namespace detail

// ---------------------------------------------------------------------------
// Candidate evaluation
// ---------------------------------------------------------------------------

namespace {

using detail::EvidenceDomain;

bool evidence_current(const FabricState& state, const SourceId& source, EvidenceDomain domain,
                      std::uint64_t sequence) {
  const SourceState* source_state = state.find_source(source, domain);
  return source_state != nullptr && source_state->is_current(sequence);
}

bool freshness_usable(const Freshness& freshness, Micros now) {
  return !freshness.is_expired(now);
}

std::uint32_t kind_rank(DeviceKind kind) {
  switch (kind) {
    case DeviceKind::Dpu:
      return 0;
    case DeviceKind::SmartNic:
      return 1;
    case DeviceKind::Nic:
      return 2;
    case DeviceKind::HostStack:
      return 3;
  }
  return 4;
}

bool contains_id(const std::vector<DeviceId>& items, const DeviceId& id) {
  return std::find(items.begin(), items.end(), id) != items.end();
}

bool contains_id(const std::vector<HostId>& items, const HostId& id) {
  return std::find(items.begin(), items.end(), id) != items.end();
}

bool contains_label(const std::vector<std::string>& labels, const std::string& label) {
  return std::find(labels.begin(), labels.end(), label) != labels.end();
}

bool kinds_allow(const std::vector<DeviceKind>& kinds, DeviceKind kind) {
  return std::find(kinds.begin(), kinds.end(), kind) != kinds.end();
}

std::uint64_t utilization_ppm(const DemandVector& used, const CapacityVector& capacity) {
  const std::uint64_t used_total = used.packets_per_second.value() + used.flows.value() +
                                   used.queues.value() + used.memory.value();
  const std::uint64_t capacity_total = capacity.packets_per_second.value() + capacity.flows.value() +
                                       capacity.queues.value() + capacity.memory.value();
  if (capacity_total == 0) {
    return used_total == 0 ? 0u : 1000000u;
  }
  if (used_total == 0) {
    return 0u;
  }
  std::uint64_t scaled = 0;
  if (!checked_mul(used_total, std::uint64_t{1000000}, scaled)) {
    return 1000000u;
  }
  const std::uint64_t ratio = scaled / capacity_total;
  return ratio > 1000000u ? 1000000u : ratio;
}

struct EvaluationContext {
  const FabricState* state = nullptr;
  const Bounds* bounds = nullptr;
  Micros now{};
  const FunctionDescriptor* function = nullptr;
  const PolicyRule* rule = nullptr;
  const PolicySnapshot* policy = nullptr;
  const TopologySnapshot* topology = nullptr;
  const PlacementRequest* request = nullptr;
  ScopeId request_scope{};
  AssignmentId replacing{};
};

// Re-runs the authority evaluation ignoring the remaining use budget, which was
// already consumed when the assignment was placed.
AuthorityDecision authority_recheck(const AuthorityGrant& grant, AuthorityAction action,
                                    FunctionClass cls, DeviceKind kind, const HostId& host,
                                    const ScopeId& scope, const SemanticsMask& semantics,
                                    PolicyGeneration policy_generation, Micros now) {
  AuthorityGrant copy = grant;
  copy.used = 0;
  copy.max_uses = 0;
  return authority_admits(copy, action, cls, kind, host, scope, semantics, policy_generation, now);
}

bool scope_has_exclusive_conflict(const FabricState& state, const ScopeId& scope,
                                  FunctionClass cls, ExclusiveKeyMode key_mode,
                                  const AssignmentId& replacing, AssignmentId& holder) {
  if (scope.empty()) {
    return false;
  }
  const auto scope_holder = state.exclusive_by_scope.find(scope);
  if (scope_holder != state.exclusive_by_scope.end() && !(scope_holder->second == replacing)) {
    holder = scope_holder->second;
    return true;
  }
  if (key_mode == ExclusiveKeyMode::PerClass) {
    ExclusivityKey key;
    key.scope = scope;
    key.cls = cls;
    const auto class_holder = state.exclusive_by_class.find(key);
    if (class_holder != state.exclusive_by_class.end() && !(class_holder->second == replacing)) {
      holder = class_holder->second;
      return true;
    }
    return false;
  }
  // A whole-scope claim conflicts with every per-class claim on that scope.
  ExclusivityKey lower;
  lower.scope = scope;
  lower.cls = static_cast<FunctionClass>(0);
  for (auto it = state.exclusive_by_class.lower_bound(lower);
       it != state.exclusive_by_class.end() && it->first.scope == scope; ++it) {
    if (!(it->second == replacing)) {
      holder = it->second;
      return true;
    }
  }
  return false;
}

DeviceObservation lookup_observation(const FabricState& state, const DeviceId& device) {
  const auto it = state.observations.find(device);
  if (it == state.observations.end()) {
    return DeviceObservation{};
  }
  return it->second;
}

const CapabilityRecord* lookup_capability(const FabricState& state, const DeviceId& device,
                                          FunctionClass cls) {
  CapabilityKey key;
  key.device = device;
  key.cls = cls;
  const auto it = state.capabilities.find(key);
  if (it == state.capabilities.end()) {
    return nullptr;
  }
  return &it->second;
}

// Evaluates one candidate target. Every refusal carries the exact reason that
// made the target ineligible; nothing is inferred from a device kind, a name,
// or a neighbouring capability.
CandidateEvaluation evaluate_device(const EvaluationContext& context, const DeviceRecord& device) {
  CandidateEvaluation evaluation;
  evaluation.device = device.id;
  evaluation.host = device.host;
  evaluation.kind = device.kind;
  evaluation.incarnation = device.incarnation;
  evaluation.eligible = false;

  const PlacementRequest& request = *context.request;
  const PolicyRule& rule = *context.rule;

  const auto refuse = [&](MatchVerdict verdict, ReasonCode reason) {
    evaluation.verdict = verdict;
    evaluation.reason = reason;
    return evaluation;
  };

  if (device.decommissioned) {
    return refuse(MatchVerdict::Unsupported, ReasonCode::TargetDisappeared);
  }
  if (device.kind == DeviceKind::HostStack) {
    // Host fallback is explicit in both directions: the request must opt in and
    // the policy must permit it. The specific reason is reported so the refusal
    // is not confused with an ordinary device-kind restriction.
    if (!request.allow_host_fallback || !rule.allow_host_fallback) {
      return refuse(MatchVerdict::Unsupported, ReasonCode::HostFallbackNotPermitted);
    }
    evaluation.mode = ExecutionMode::HostFallback;
  } else if (!kinds_allow(rule.allowed_kinds, device.kind)) {
    return refuse(MatchVerdict::Unsupported, ReasonCode::DeviceKindNotPermitted);
  }

  // Affinity and anti-affinity are hard constraints, evaluated before any
  // capability work so that the refusal reason is the operationally relevant
  // one. A non-empty preferred list means "only these targets".
  if (!request.preferred_devices.empty() && !contains_id(request.preferred_devices, device.id)) {
    return refuse(MatchVerdict::Unknown, ReasonCode::AffinityUnsatisfied);
  }
  if (!request.preferred_hosts.empty() && !contains_id(request.preferred_hosts, device.host)) {
    return refuse(MatchVerdict::Unknown, ReasonCode::AffinityUnsatisfied);
  }
  if (contains_id(request.anti_affinity_devices, device.id) ||
      contains_id(request.anti_affinity_hosts, device.host)) {
    return refuse(MatchVerdict::Unknown, ReasonCode::AntiAffinityViolation);
  }
  for (const std::string& label : request.required_labels) {
    if (!contains_label(device.labels, label)) {
      return refuse(MatchVerdict::Unknown, ReasonCode::AffinityUnsatisfied);
    }
  }

  // Capability evidence. Host fallback is the one path where the offload
  // semantics are known to be unavailable: the policy and the request both had
  // to opt in, so the degradation is explicit and is recorded on the
  // evaluation. No capability generation is claimed for such a placement.
  const bool host_fallback = device.kind == DeviceKind::HostStack;
  const CapabilityRecord* capability = lookup_capability(*context.state, device.id, request.cls);
  if (capability == nullptr) {
    if (rule.require_capability && !host_fallback) {
      return refuse(MatchVerdict::Missing, ReasonCode::EvidenceMissing);
    }
  } else {
    const CapabilityMatch match =
        match_capability(*context.function, *capability, device.incarnation, context.now);
    if (match.verdict == MatchVerdict::Revoked ||
        match.verdict == MatchVerdict::IncarnationMismatch) {
      return refuse(match.verdict, match.reason);
    }
    if (host_fallback) {
      if (match.verdict != MatchVerdict::Eligible) {
        evaluation.contributing.push_back(match.reason);
      }
    } else if (match.verdict == MatchVerdict::Unsupported ||
               match.verdict == MatchVerdict::VersionIncompatible) {
      // A denial, an incompatible version, or an incarnation mismatch is a
      // refusal even when capability evidence is optional.
      return refuse(match.verdict, match.reason);
    } else if (rule.require_capability) {
      if (!evidence_current(*context.state, capability->provenance.source,
                            EvidenceDomain::Capability, capability->provenance.sequence)) {
        return refuse(MatchVerdict::Superseded, ReasonCode::EvidenceSuperseded);
      }
      if (request.min_capability.is_set() && capability->generation < request.min_capability) {
        return refuse(MatchVerdict::Stale, ReasonCode::GenerationMismatch);
      }
      if (!match.eligible()) {
        return refuse(match.verdict, match.reason);
      }
      evaluation.capability_generation = capability->generation;
    } else if (match.eligible()) {
      evaluation.capability_generation = capability->generation;
    }
  }

  // Capacity and the per-device assignment ceiling.
  const DemandVector committed = detail::committed_demand_for(*context.state, device.id);
  DemandVector projected{};
  if (!capacity_admits(device.capacity, committed, request.demand, projected)) {
    return refuse(MatchVerdict::Eligible, ReasonCode::CapacityExhausted);
  }
  std::size_t device_assignments = 0;
  for (const auto& entry : context.state->assignments) {
    if (entry.second.device == device.id && holds_authority(entry.second.state)) {
      device_assignments += 1;
    }
  }
  if (device_assignments >= rule.max_assignments_per_device) {
    return refuse(MatchVerdict::Eligible, ReasonCode::CapacityExhausted);
  }

  // Liveness evidence.
  if (rule.require_fresh_observation) {
    const DeviceObservation observation = lookup_observation(*context.state, device.id);
    if (!observation.device.is_set()) {
      return refuse(MatchVerdict::Unknown, ReasonCode::LivenessUnknown);
    }
    if (!(observation.incarnation == device.incarnation)) {
      return refuse(MatchVerdict::IncarnationMismatch, ReasonCode::IncarnationMismatch);
    }
    if (!evidence_current(*context.state, observation.provenance.source,
                          EvidenceDomain::Observation, observation.provenance.sequence)) {
      return refuse(MatchVerdict::Superseded, ReasonCode::EvidenceSuperseded);
    }
    if (!freshness_usable(observation.freshness, context.now)) {
      return refuse(MatchVerdict::Stale, ReasonCode::LivenessStale);
    }
    switch (observation.liveness) {
      case Liveness::Alive:
        break;
      case Liveness::Degraded:
        return refuse(MatchVerdict::Eligible, ReasonCode::LivenessDegraded);
      case Liveness::Dead:
        return refuse(MatchVerdict::Eligible, ReasonCode::LivenessDead);
      case Liveness::Unknown:
        return refuse(MatchVerdict::Unknown, ReasonCode::LivenessUnknown);
    }
  }

  // Dependencies must already hold authority on this device or this scope.
  for (const FunctionId& dependency : request.dependencies) {
    if (dependency == request.function) {
      return refuse(MatchVerdict::Eligible, ReasonCode::DependencyCycle);
    }
    if (context.state->functions.find(dependency) == context.state->functions.end()) {
      return refuse(MatchVerdict::Eligible, ReasonCode::DependencyUnresolved);
    }
    bool satisfied = false;
    for (const auto& entry : context.state->assignments) {
      const AssignmentRecord& candidate = entry.second;
      if (!(candidate.function == dependency) || !holds_authority(candidate.state)) {
        continue;
      }
      if (candidate.device == device.id ||
          (!context.request_scope.empty() && candidate.scope_id == context.request_scope)) {
        satisfied = true;
        break;
      }
    }
    if (!satisfied) {
      return refuse(MatchVerdict::Eligible, ReasonCode::DependencyUnresolved);
    }
  }

  // Exclusive authority over the governed scope.
  if (request.exclusivity == Exclusivity::Exclusive) {
    AssignmentId holder{};
    if (scope_has_exclusive_conflict(*context.state, context.request_scope, request.cls,
                                     rule.exclusive_key, context.replacing, holder)) {
      return refuse(MatchVerdict::Conflicting, ReasonCode::ExclusiveConflict);
    }
  }

  // Authority.
  const SemanticsMask effective = context.function->required.unite(rule.required);
  if (rule.require_authority) {
    bool admitted = false;
    for (const auto& entry : context.state->authority) {
      const AuthorityGrant& grant = entry.second;
      if (!evidence_current(*context.state, grant.provenance.source, EvidenceDomain::Authority,
                            grant.provenance.sequence)) {
        continue;
      }
      const AuthorityDecision decision =
          authority_admits(grant, AuthorityAction::Place, request.cls, device.kind, device.host,
                           context.request_scope, effective, context.policy->generation,
                           context.now);
      if (decision.admitted) {
        admitted = true;
        break;
      }
    }
    if (!admitted) {
      return refuse(MatchVerdict::Eligible, ReasonCode::AuthorityMissing);
    }
  }

  evaluation.eligible = true;
  evaluation.verdict = MatchVerdict::Eligible;
  evaluation.reason = ReasonCode::Ok;
  return evaluation;
}

void finalize_ranking(CandidateEvaluation& evaluation, const CapacityVector& capacity,
                      const DemandVector& committed, const ScopeSpec& scope,
                      const std::vector<HostId>& preferred_hosts) {
  evaluation.offload_rank = evaluation.mode == ExecutionMode::HostFallback ? 1u : 0u;
  evaluation.kind_rank = kind_rank(evaluation.kind);
  if (evaluation.locality_rank == 0) {
    if (scope.domain.is_set() && scope.domain == evaluation.host) {
      evaluation.locality_rank = 0;
    } else if (contains_id(preferred_hosts, evaluation.host)) {
      evaluation.locality_rank = 1;
    } else {
      evaluation.locality_rank = 2;
    }
  }
  evaluation.utilization_ppm = utilization_ppm(committed, capacity);
  const std::uint64_t part_a = static_cast<std::uint64_t>(evaluation.offload_rank) * 1000000000000ull;
  const std::uint64_t part_b = static_cast<std::uint64_t>(evaluation.kind_rank) * 10000000000ull;
  const std::uint64_t part_c = static_cast<std::uint64_t>(evaluation.locality_rank) * 100000000ull;
  evaluation.rank = part_a + part_b + part_c + evaluation.utilization_ppm;
}

bool candidate_precedes(const CandidateEvaluation& left, const CandidateEvaluation& right) {
  if (left.offload_rank != right.offload_rank) {
    return left.offload_rank < right.offload_rank;
  }
  if (left.kind_rank != right.kind_rank) {
    return left.kind_rank < right.kind_rank;
  }
  if (left.locality_rank != right.locality_rank) {
    return left.locality_rank < right.locality_rank;
  }
  if (left.utilization_ppm != right.utilization_ppm) {
    return left.utilization_ppm < right.utilization_ppm;
  }
  return left.device < right.device;
}

// Deterministic primary refusal reason: the reason of the best-ranked target
// that was refused, using exactly the ranking that would have selected it. The
// full per-candidate verdicts remain in the explanation, so a refusal is never
// reduced to a single unexplained code.
ReasonCode primary_refusal_reason(const std::vector<CandidateEvaluation>& candidates) {
  const CandidateEvaluation* best = nullptr;
  for (const CandidateEvaluation& candidate : candidates) {
    if (candidate.eligible) {
      continue;
    }
    if (best == nullptr || candidate_precedes(candidate, *best)) {
      best = &candidate;
    }
  }
  if (best == nullptr) {
    return ReasonCode::NoEligibleTarget;
  }
  return best->reason;
}

}  // namespace

// ---------------------------------------------------------------------------
// Runtime implementation
// ---------------------------------------------------------------------------

struct Fabric::Impl {
  FabricConfig config{};
  Bounds bounds{};
  std::shared_ptr<Clock> clock{};
  mutable std::mutex mutex{};
  FabricState state{};
  std::unique_ptr<JournalStore> store{};
  RecoveryReport recovery{};
  Stats stats{};
  bool running = false;
  bool recovery_accepted = true;
  bool replaying = false;
  bool shutting_down = false;
  std::size_t assignment_history_drops = 0;

  Micros now() const { return clock->now(); }

  void inject(CrashBoundary boundary) {
    if (replaying) {
      return;
    }
    if (config.crash_hook) {
      config.crash_hook(boundary);
    }
  }

  Digest fingerprint_of(const PlacementRequest& request) const {
    auto digest = wire::digest_with(
        request, bounds.max_canonical_bytes,
        [this](const PlacementRequest& value, BinWriter& writer) {
          return wire::encode_placement_request(value, writer, bounds);
        });
    if (!digest) {
      return Digest::zero();
    }
    return digest.value();
  }

  Status compact_locked() {
    if (!store) {
      return ok_status();
    }
    BinWriter writer(bounds.max_snapshot_bytes > 0 ? bounds.max_snapshot_bytes
                                                  : bounds.max_canonical_bytes);
    Status status = detail::encode_state(state, writer, bounds);
    if (!status) {
      return status.error();
    }
    const Digest digest = writer.fingerprint();
    BinWriter envelope(writer.size() + 64 + bounds.max_canonical_bytes);
    status = envelope.bytes(writer.data());
    if (!status) {
      return status.error();
    }
    status = envelope.digest(digest);
    if (!status) {
      return status.error();
    }
    if (envelope.size() > bounds.max_snapshot_bytes) {
      return Error(ReasonCode::OversizedInput, "snapshot exceeds the configured bound");
    }
    const std::uint64_t next_generation = store->generation().value() + 1;
    status = store->compact(envelope.data(), store->last_sequence(), next_generation);
    if (!status) {
      stats.commit_failures += 1;
      return status.error();
    }
    stats.compactions += 1;
    return ok_status();
  }

  Status commit(RecordType type, std::span<const std::byte> payload) {
    if (replaying) {
      return ok_status();
    }
    if (!store) {
      return ok_status();
    }
    if (store->journal_bytes() > bounds.max_journal_bytes) {
      Status status = compact_locked();
      if (!status) {
        return status;
      }
    }
    Status status = store->append(type, payload);
    if (!status) {
      stats.commit_failures += 1;
      return status.error();
    }
    stats.journal_records_appended += 1;
    stats.journal_bytes_appended += payload.size();
    stats.commits += 1;
    return ok_status();
  }

  Status accept_evidence(const SourceId& source, EvidenceDomain domain, std::uint64_t sequence,
                         const Digest& digest, bool& duplicate) {
    duplicate = false;
    if (!source.is_set() || sequence == 0) {
      return Error(ReasonCode::ProvenanceMismatch, "evidence provenance is incomplete");
    }
    const SourceState* existing = state.find_source(source, domain);
    if (existing != nullptr && existing->seen) {
      if (sequence < existing->last_sequence) {
        stats.sequence_regressions += 1;
        return Error(ReasonCode::SequenceRegression,
                     "evidence sequence regressed for this source and domain");
      }
      if (sequence == existing->last_sequence) {
        if (existing->last_digest == digest) {
          duplicate = true;
          return ok_status();
        }
        stats.evidence_conflicting += 1;
        return Error(ReasonCode::EvidenceConflicting,
                     "a different payload was delivered for an accepted sequence");
      }
    }
    return ok_status();
  }

  void mark_source(const SourceId& source, EvidenceDomain domain, std::uint64_t sequence,
                   const Digest& digest) {
    SourceState& entry = state.source_state(source, domain);
    entry.last_sequence = sequence;
    entry.last_digest = digest;
    entry.seen = true;
  }

  void note_history_drop(const AssignmentRecord& record) {
    if (record.history.size() > bounds.max_history_per_assignment) {
      assignment_history_drops += 1;
      stats.entries_evicted += 1;
      stats.results_truncated += 1;
    }
  }

  void trim_history(AssignmentRecord& record) {
    if (record.history.size() > bounds.max_history_per_assignment) {
      const std::size_t excess = record.history.size() - bounds.max_history_per_assignment;
      record.history.erase(record.history.begin(),
                           record.history.begin() + static_cast<std::ptrdiff_t>(excess));
      assignment_history_drops += 1;
      stats.entries_evicted += 1;
    }
    if (record.effects.size() > bounds.max_effects_per_assignment) {
      const std::size_t excess = record.effects.size() - bounds.max_effects_per_assignment;
      record.effects.erase(record.effects.begin(),
                           record.effects.begin() + static_cast<std::ptrdiff_t>(excess));
      assignment_history_drops += 1;
      stats.entries_evicted += 1;
    }
  }

  void record_idempotency(const RequestId& request_id, const Digest& fingerprint,
                          ReasonCode outcome, std::span<const std::byte> response, Micros at) {
    if (request_id.empty()) {
      return;
    }
    IdempotencyEntry entry;
    entry.request_fingerprint = fingerprint;
    entry.outcome = outcome;
    entry.response.assign(response.begin(), response.end());
    entry.at = at;
    const auto existing = state.idempotency.find(request_id);
    if (existing == state.idempotency.end()) {
      state.idempotency_order.push_back(request_id);
    }
    state.idempotency[request_id] = std::move(entry);
    while (state.idempotency.size() > bounds.max_idempotency_entries) {
      const RequestId oldest = state.idempotency_order.front();
      state.idempotency_order.pop_front();
      state.idempotency.erase(oldest);
      stats.entries_evicted += 1;
    }
  }

  const IdempotencyEntry* find_idempotency(const RequestId& request_id) const {
    if (request_id.empty()) {
      return nullptr;
    }
    const auto it = state.idempotency.find(request_id);
    if (it == state.idempotency.end()) {
      return nullptr;
    }
    return &it->second;
  }

  // Encodes a refusal so that a duplicate delivery returns the identical
  // refusal instead of a different one.
  Status record_refusal(const RequestId& request_id, const Digest& fingerprint, const Error& error,
                        Micros at) {
    if (request_id.empty()) {
      return ok_status();
    }
    BinWriter writer(bounds.max_reason_detail_bytes + 64);
    Status status = encode_error_envelope(error, writer, bounds);
    if (!status) {
      return status.error();
    }
    RecordedRequest payload;
    payload.request_id = request_id;
    payload.request_fingerprint = fingerprint;
    payload.outcome = error.code;
    payload.response.assign(writer.data().begin(), writer.data().end());
    payload.at = at;
    BinWriter envelope(bounds.max_record_bytes);
    status = encode_recorded_request(payload, envelope);
    if (!status) {
      return status.error();
    }
    status = commit(RecordType::RequestRecorded, envelope.data());
    if (!status) {
      return status.error();
    }
    record_idempotency(request_id, fingerprint, error.code, payload.response, at);
    return ok_status();
  }

  void acquire_claims(const AssignmentRecord& record) {
    if (!record.scope_id.empty()) {
      state.scope_specs[record.scope_id] = record.scope;
    }
    if (record.exclusivity == Exclusivity::Exclusive && holds_authority(record.state)) {
      ExclusivityKey key;
      key.scope = record.scope_id;
      key.cls = record.cls;
      if (record.exclusive_key == ExclusiveKeyMode::PerClass) {
        state.exclusive_by_class[key] = record.id;
      } else {
        state.exclusive_by_scope[record.scope_id] = record.id;
      }
    }
    if (holds_authority(record.state)) {
      DemandVector& used = state.committed[record.device];
      std::uint64_t pps = 0;
      std::uint64_t bps = 0;
      std::uint64_t flows = 0;
      std::uint64_t queues = 0;
      std::uint64_t memory = 0;
      (void)checked_add(used.packets_per_second.value(), record.demand.packets_per_second.value(), pps);
      (void)checked_add(used.bytes_per_second.value(), record.demand.bytes_per_second.value(), bps);
      (void)checked_add(used.flows.value(), record.demand.flows.value(), flows);
      (void)checked_add(used.queues.value(), record.demand.queues.value(), queues);
      (void)checked_add(used.memory.value(), record.demand.memory.value(), memory);
      used.packets_per_second = PacketRate::raw(pps);
      used.bytes_per_second = ByteRate::raw(bps);
      used.flows = FlowCount::raw(flows);
      used.queues = QueueCount::raw(queues);
      used.memory = ByteSize::raw(memory);
    }
  }

  void release_claims(const AssignmentRecord& record) {
    ExclusivityKey key;
    key.scope = record.scope_id;
    key.cls = record.cls;
    const auto class_holder = state.exclusive_by_class.find(key);
    if (class_holder != state.exclusive_by_class.end() && class_holder->second == record.id) {
      state.exclusive_by_class.erase(class_holder);
    }
    const auto scope_holder = state.exclusive_by_scope.find(record.scope_id);
    if (scope_holder != state.exclusive_by_scope.end() && scope_holder->second == record.id) {
      state.exclusive_by_scope.erase(scope_holder);
    }
    DemandVector& used = state.committed[record.device];
    std::uint64_t pps = 0;
    std::uint64_t bps = 0;
    std::uint64_t flows = 0;
    std::uint64_t queues = 0;
    std::uint64_t memory = 0;
    if (!checked_sub(used.packets_per_second.value(), record.demand.packets_per_second.value(), pps)) {
      pps = 0;
    }
    if (!checked_sub(used.bytes_per_second.value(), record.demand.bytes_per_second.value(), bps)) {
      bps = 0;
    }
    if (!checked_sub(used.flows.value(), record.demand.flows.value(), flows)) {
      flows = 0;
    }
    if (!checked_sub(used.queues.value(), record.demand.queues.value(), queues)) {
      queues = 0;
    }
    if (!checked_sub(used.memory.value(), record.demand.memory.value(), memory)) {
      memory = 0;
    }
    used.packets_per_second = PacketRate::raw(pps);
    used.bytes_per_second = ByteRate::raw(bps);
    used.flows = FlowCount::raw(flows);
    used.queues = QueueCount::raw(queues);
    used.memory = ByteSize::raw(memory);
  }

  // Authority usage is derived, never typed in by hand: the use counter is the
  // number of live assignments that reference the grant.
  void refresh_authority_usage() {
    for (auto& entry : state.authority) {
      entry.second.used = 0;
    }
    for (const auto& entry : state.assignments) {
      if (!holds_authority(entry.second.state) || entry.second.authority.empty()) {
        continue;
      }
      const auto grant = state.authority.find(entry.second.authority);
      if (grant != state.authority.end()) {
        grant->second.used += 1;
      }
    }
  }

  void insert_assignment(const AssignmentRecord& record) {
    const auto existing = state.assignments.find(record.id);
    if (existing != state.assignments.end()) {
      release_claims(existing->second);
    }
    state.assignments[record.id] = record;
    acquire_claims(record);
    refresh_authority_usage();
  }

  // Persists a transition and then applies it in memory. The durable record is
  // always written before the in-memory state moves.
  Status store_assignment(const AssignmentRecord& record, const RequestId& request_id,
                          const Digest& fingerprint, RecordType type) {
    BinWriter writer(bounds.max_record_bytes);
    RecordedAssignment payload;
    payload.record = record;
    payload.request_id = request_id;
    payload.request_fingerprint = fingerprint;
    Status status = encode_recorded_assignment(payload, writer, bounds);
    if (!status) {
      return status.error();
    }
    status = commit(type, writer.data());
    if (!status) {
      return status.error();
    }
    insert_assignment(record);
    if (!request_id.empty()) {
      BinWriter response(bounds.max_record_bytes);
      Status encoded = wire::encode_assignment(record, response, bounds);
      if (!encoded) {
        return encoded.error();
      }
      record_idempotency(request_id, fingerprint, ReasonCode::Ok, response.data(), now());
    }
    return ok_status();
  }

  // Effect records carry the effect report plus the resulting assignment, so a
  // replay reconstructs exactly what the enforcement plane reported.
  Status store_effect(const AssignmentRecord& record, const EffectReport& report,
                      const RequestId& request_id, const Digest& fingerprint);

  Status apply_record(RecordType type, std::span<const std::byte> payload);
  Status revalidate_locked(const CancelToken* cancel, RevalidationReport& report);
  Status revalidate_now() {
    RevalidationReport report;
    return revalidate_locked(nullptr, report);
  }
  Result<PlanResult> plan_locked(const PlacementRequest& request, const CancelToken* cancel);
  ReasonCode assignment_validity(const AssignmentRecord& record, Micros at) const;
  // Target-level validity: whether the placement itself is still sound against
  // current evidence (target present, capability current, liveness current).
  // Re-authorization re-binds generations, so this deliberately ignores the
  // policy generation, the previous authority, and the old fencing epoch.
  ReasonCode assignment_target_validity(const AssignmentRecord& record, Micros at,
                                       bool require_binding_generations) const;
  std::size_t reassignment_count(const ScopeId& scope, FunctionClass cls, Micros at) const;
  Status note_reassignment(const ScopeId& scope, FunctionClass cls, Micros at);
  void apply_recovery_invariants();
  Result<AssignmentRecord> authorize_locked(const PlanResult& planned, const ApplyOptions& options);
  Result<AssignmentRecord> apply_locked(const PlacementRequest& request,
                                        const ApplyOptions& options);
  Freshness effective_freshness_locked(const AssignmentRecord& record, Micros at) const;
};

// ---------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------

Status Fabric::Impl::store_effect(const AssignmentRecord& record, const EffectReport& report,
                                    const RequestId& request_id, const Digest& fingerprint) {
  BinWriter writer(bounds.max_record_bytes);
  RecordedEffect payload;
  payload.report = report;
  payload.record = record;
  payload.request_id = request_id;
  payload.request_fingerprint = fingerprint;
  Status status = encode_recorded_effect(payload, writer, bounds);
  if (!status) {
    return status.error();
  }
  status = commit(RecordType::EffectRecorded, writer.data());
  if (!status) {
    return status.error();
  }
  insert_assignment(record);
  if (!request_id.empty()) {
    BinWriter response(bounds.max_record_bytes);
    Status encoded = wire::encode_assignment(record, response, bounds);
    if (!encoded) {
      return encoded.error();
    }
    record_idempotency(request_id, fingerprint, ReasonCode::Ok, response.data(), now());
  }
  return ok_status();
}

Status Fabric::Impl::apply_record(RecordType type, std::span<const std::byte> payload) {
  const auto make_reader = [&]() { return BinReader(payload, bounds.max_text_bytes); };
  switch (type) {
    case RecordType::EpochStarted: {
      BinReader reader = make_reader();
      auto epoch = wire::decode_epoch(reader);
      if (!epoch) {
        return epoch.error();
      }
      state.epoch = epoch.value();
      if (epoch.value().counter > state.epoch_counter) {
        state.epoch_counter = epoch.value().counter;
      }
      return ok_status();
    }
    case RecordType::FunctionRegistered: {
      BinReader reader = make_reader();
      auto function = wire::decode_function(reader, bounds);
      if (!function) {
        return function.error();
      }
      state.functions[function.value().id] = function.take();
      return ok_status();
    }
    case RecordType::TopologyIngested: {
      BinReader reader = make_reader();
      auto topology = wire::decode_topology(reader, bounds);
      if (!topology) {
        return topology.error();
      }
      mark_source(topology.value().provenance.source, EvidenceDomain::Topology,
                  topology.value().provenance.sequence, sha256(payload));
      state.topology = topology.take();
      state.has_topology = true;
      return ok_status();
    }
    case RecordType::CapabilityIngested: {
      BinReader reader = make_reader();
      auto report = wire::decode_capability_report(reader, bounds);
      if (!report) {
        return report.error();
      }
      mark_source(report.value().provenance.source, EvidenceDomain::Capability,
                  report.value().provenance.sequence, sha256(payload));
      for (const CapabilityRecord& record : report.value().records) {
        CapabilityKey key;
        key.device = record.device;
        key.cls = record.cls;
        state.capabilities[key] = record;
      }
      return ok_status();
    }
    case RecordType::PolicyIngested: {
      BinReader reader = make_reader();
      auto policy = wire::decode_policy(reader, bounds);
      if (!policy) {
        return policy.error();
      }
      mark_source(policy.value().provenance.source, EvidenceDomain::Policy,
                  policy.value().provenance.sequence, sha256(payload));
      state.policy = policy.take();
      state.has_policy = true;
      return ok_status();
    }
    case RecordType::ObservationsIngested: {
      BinReader reader = make_reader();
      auto report = wire::decode_observation_report(reader, bounds);
      if (!report) {
        return report.error();
      }
      mark_source(report.value().provenance.source, EvidenceDomain::Observation,
                  report.value().provenance.sequence, sha256(payload));
      for (const DeviceObservation& observation : report.value().devices) {
        state.observations[observation.device] = observation;
      }
      return ok_status();
    }
    case RecordType::AuthorityGranted: {
      BinReader reader = make_reader();
      auto grant = wire::decode_authority(reader, bounds);
      if (!grant) {
        return grant.error();
      }
      mark_source(grant.value().provenance.source, EvidenceDomain::Authority,
                  grant.value().provenance.sequence, sha256(payload));
      state.authority[grant.value().id] = grant.take();
      return ok_status();
    }
    case RecordType::AuthorityWithdrawn: {
      BinReader reader = make_reader();
      auto withdrawal = decode_recorded_withdrawal(reader);
      if (!withdrawal) {
        return withdrawal.error();
      }
      const auto it = state.authority.find(withdrawal.value().authority);
      if (it != state.authority.end()) {
        it->second.revoked = true;
      }
      if (!withdrawal.value().request_id.empty()) {
        BinWriter writer(64);
        Error error(withdrawal.value().reason, "authority withdrawal replayed");
        Status status = encode_error_envelope(error, writer, bounds);
        if (status) {
          record_idempotency(withdrawal.value().request_id,
                             withdrawal.value().request_fingerprint, error.code, writer.data(),
                             withdrawal.value().at);
        }
      }
      return ok_status();
    }
    case RecordType::AssignmentCreated:
    case RecordType::AssignmentTransitioned: {
      BinReader reader = make_reader();
      auto recorded = decode_recorded_assignment(reader, bounds);
      if (!recorded) {
        return recorded.error();
      }
      const AssignmentRecord& record = recorded.value().record;
      insert_assignment(record);
      note_history_drop(record);
      if (!recorded.value().request_id.empty()) {
        BinWriter response(bounds.max_record_bytes);
        Status status = wire::encode_assignment(record, response, bounds);
        if (!status) {
          return status.error();
        }
        record_idempotency(recorded.value().request_id, recorded.value().request_fingerprint,
                           ReasonCode::Ok, response.data(), record.updated_at);
      }
      return ok_status();
    }
    case RecordType::EffectRecorded: {
      BinReader reader = make_reader();
      auto recorded = decode_recorded_effect(reader, bounds);
      if (!recorded) {
        return recorded.error();
      }
      insert_assignment(recorded.value().record);
      note_history_drop(recorded.value().record);
      if (!recorded.value().request_id.empty()) {
        BinWriter response(bounds.max_record_bytes);
        Status status = wire::encode_assignment(recorded.value().record, response, bounds);
        if (!status) {
          return status.error();
        }
        record_idempotency(recorded.value().request_id, recorded.value().request_fingerprint,
                           ReasonCode::Ok, response.data(), recorded.value().report.observed_at);
      }
      return ok_status();
    }
    case RecordType::ReassignmentRecorded: {
      BinReader reader = make_reader();
      auto scope = reader.token();
      if (!scope) {
        return scope.error();
      }
      auto cls = reader.u16();
      if (!cls) {
        return cls.error();
      }
      auto at = reader.i64();
      if (!at) {
        return at.error();
      }
      if (std::string_view(to_string(static_cast<FunctionClass>(cls.value()))) ==
          "unknown_function_class") {
        return Error(ReasonCode::UnsupportedValue, "record carries an unknown function class");
      }
      ExclusivityKey key;
      key.scope = ScopeId::from_validated(scope.take());
      key.cls = static_cast<FunctionClass>(cls.value());
      state.reassignments[key].push_back(Micros::raw(at.value()));
      return ok_status();
    }
    case RecordType::RequestRecorded: {
      BinReader reader = make_reader();
      auto recorded = decode_recorded_request(reader, bounds);
      if (!recorded) {
        return recorded.error();
      }
      record_idempotency(recorded.value().request_id, recorded.value().request_fingerprint,
                         recorded.value().outcome, recorded.value().response, recorded.value().at);
      return ok_status();
    }
    case RecordType::ScopeReleased:
      return ok_status();
    case RecordType::SnapshotBase:
      return ok_status();
    case RecordType::StoreSealed:
      return ok_status();
  }
  return Error(ReasonCode::UnsupportedValue, "unknown record type during replay");
}

// ---------------------------------------------------------------------------
// Validity, reassignment budget, revalidation
// ---------------------------------------------------------------------------

ReasonCode Fabric::Impl::assignment_target_validity(const AssignmentRecord& record, Micros at,
                                                   bool require_binding_generations) const {
  if (!state.has_topology) {
    return ReasonCode::TopologyStale;
  }
  if (!evidence_current(state, state.topology.provenance.source, EvidenceDomain::Topology,
                        state.topology.provenance.sequence)) {
    return ReasonCode::EvidenceSuperseded;
  }
  if (!freshness_usable(state.topology.freshness, at)) {
    return ReasonCode::TopologyStale;
  }
  if (record.binding.topology.is_set() && state.topology.generation < record.binding.topology) {
    return ReasonCode::GenerationMismatch;
  }
  const DeviceRecord* device = state.topology.find_device(record.device);
  if (device == nullptr || device->decommissioned) {
    return ReasonCode::TargetDisappeared;
  }
  if (!(device->incarnation == record.incarnation)) {
    return ReasonCode::IncarnationMismatch;
  }
  if (!state.has_policy) {
    return ReasonCode::PolicyStale;
  }
  if (!evidence_current(state, state.policy.provenance.source, EvidenceDomain::Policy,
                        state.policy.provenance.sequence)) {
    return ReasonCode::EvidenceSuperseded;
  }
  if (!freshness_usable(state.policy.freshness, at)) {
    return ReasonCode::PolicyStale;
  }
  const PolicyRule* rule = state.policy.find_rule(record.cls);
  if (rule == nullptr) {
    return ReasonCode::RefusedByPolicy;
  }
  if (!kinds_allow(rule->allowed_kinds, record.kind)) {
    return ReasonCode::DeviceKindNotPermitted;
  }
  if (record.kind == DeviceKind::HostStack && !rule->allow_host_fallback) {
    return ReasonCode::HostFallbackNotPermitted;
  }
  if (record.binding.capability.is_set()) {
    const CapabilityRecord* capability = lookup_capability(state, record.device, record.cls);
    if (capability == nullptr) {
      return ReasonCode::CapabilityStale;
    }
    if (require_binding_generations && !(capability->generation == record.binding.capability)) {
      return ReasonCode::CapabilityStale;
    }
    if (!evidence_current(state, capability->provenance.source, EvidenceDomain::Capability,
                          capability->provenance.sequence)) {
      return ReasonCode::EvidenceSuperseded;
    }
    if (!freshness_usable(capability->freshness, at)) {
      return ReasonCode::CapabilityStale;
    }
    const auto function = state.functions.find(record.function);
    if (function != state.functions.end()) {
      const CapabilityMatch match =
          match_capability(function->second, *capability, record.incarnation, at);
      if (!match.eligible()) {
        return match.reason;
      }
    }
  }
  if (rule->require_fresh_observation) {
    const DeviceObservation observation = lookup_observation(state, record.device);
    if (!observation.device.is_set()) {
      return ReasonCode::LivenessUnknown;
    }
    if (!(observation.incarnation == record.incarnation)) {
      return ReasonCode::IncarnationMismatch;
    }
    if (!evidence_current(state, observation.provenance.source, EvidenceDomain::Observation,
                          observation.provenance.sequence)) {
      return ReasonCode::EvidenceSuperseded;
    }
    if (!freshness_usable(observation.freshness, at)) {
      return ReasonCode::LivenessStale;
    }
    if (observation.liveness == Liveness::Dead) {
      return ReasonCode::LivenessDead;
    }
    if (observation.liveness == Liveness::Degraded) {
      return ReasonCode::LivenessDegraded;
    }
    if (observation.liveness != Liveness::Alive) {
      return ReasonCode::LivenessUnknown;
    }
  }
  return ReasonCode::Ok;
}

ReasonCode Fabric::Impl::assignment_validity(const AssignmentRecord& record, Micros at) const {
  const ReasonCode target = assignment_target_validity(record, at, true);
  if (target != ReasonCode::Ok) {
    return target;
  }
  const PolicyRule* rule = state.policy.find_rule(record.cls);
  // A live assignment is bound to the exact policy generation and the exact
  // authority grant it was authorized under; a new generation requires an
  // explicit re-authorization.
  if (record.binding.policy.is_set() && !(state.policy.generation == record.binding.policy)) {
    return ReasonCode::PolicyStale;
  }
  if (record.fence.is_set() && record.fence.epoch != state.epoch.counter) {
    return ReasonCode::LeaseExpired;
  }
  if (record.authority.is_set()) {
    const auto grant = state.authority.find(record.authority);
    if (grant == state.authority.end()) {
      return ReasonCode::AuthorityMissing;
    }
    if (!evidence_current(state, grant->second.provenance.source, EvidenceDomain::Authority,
                          grant->second.provenance.sequence)) {
      return ReasonCode::EvidenceSuperseded;
    }
    SemanticsMask effective;
    const auto function_entry = state.functions.find(record.function);
    if (function_entry != state.functions.end() && rule != nullptr) {
      effective = function_entry->second.required.unite(rule->required);
    }
    const AuthorityDecision decision =
        authority_recheck(grant->second, AuthorityAction::Place, record.cls, record.kind, record.host,
                          record.scope_id, effective, state.policy.generation, at);
    if (!decision.admitted) {
      return decision.reason;
    }
  }
  return ReasonCode::Ok;
}

std::size_t Fabric::Impl::reassignment_count(const ScopeId& scope, FunctionClass cls,
                                             Micros at) const {
  ExclusivityKey key;
  key.scope = scope;
  key.cls = cls;
  const auto it = state.reassignments.find(key);
  if (it == state.reassignments.end()) {
    return 0;
  }
  std::size_t count = 0;
  for (const Micros stamp : it->second) {
    if (at.value() >= stamp.value()) {
      count += 1;
    }
  }
  return count;
}

Status Fabric::Impl::note_reassignment(const ScopeId& scope, FunctionClass cls, Micros at) {
  ExclusivityKey key;
  key.scope = scope;
  key.cls = cls;
  std::deque<Micros>& stamps = state.reassignments[key];
  stamps.push_back(at);
  while (stamps.size() > bounds.max_reassignments_per_scope * 8u) {
    stamps.pop_front();
    stats.entries_evicted += 1;
  }
  BinWriter writer(64);
  Status status = writer.token(scope.view());
  if (!status) {
    return status.error();
  }
  status = writer.u16(static_cast<std::uint16_t>(cls));
  if (!status) {
    return status.error();
  }
  status = writer.i64(at.value());
  if (!status) {
    return status.error();
  }
  stats.reassignments += 1;
  return commit(RecordType::ReassignmentRecorded, writer.data());
}

Status Fabric::Impl::revalidate_locked(const CancelToken* cancel, RevalidationReport& report) {
  std::vector<AssignmentId> ids;
  ids.reserve(state.assignments.size());
  for (const auto& entry : state.assignments) {
    if (is_live(entry.second.state)) {
      ids.push_back(entry.first);
    }
  }
  const Micros at = now();
  std::size_t checked = 0;
  std::size_t suspended = 0;
  std::size_t degraded = 0;
  stats.revalidations += 1;
  for (const AssignmentId& id : ids) {
    if (cancel != nullptr && cancel->cancelled()) {
      stats.cancellations += 1;
      return Error(ReasonCode::Cancelled, "revalidation cancelled");
    }
    const auto it = state.assignments.find(id);
    if (it == state.assignments.end()) {
      continue;
    }
    AssignmentRecord record = it->second;
    if (is_terminal(record.state)) {
      continue;
    }
    checked += 1;
    const ReasonCode reason = assignment_validity(record, at);
    if (reason == ReasonCode::Ok) {
      continue;
    }
    if (reason == ReasonCode::LivenessDegraded) {
      if (record.state == AssignmentState::Degraded) {
        continue;
      }
      record.state = AssignmentState::Degraded;
      record.state_reason = reason;
      record.updated_at = at;
      record.history.push_back(TransitionRecord{it->second.state, AssignmentState::Degraded, reason, at,
                                                record.fence});
      trim_history(record);
      Status status = store_assignment(record, RequestId{}, Digest::zero(),
                                       RecordType::AssignmentTransitioned);
      if (!status) {
        return status.error();
      }
      stats.assignments_degraded += 1;
      degraded += 1;
      continue;
    }
    record.state = AssignmentState::Suspended;
    record.state_reason = reason;
    record.updated_at = at;
    record.history.push_back(TransitionRecord{it->second.state, AssignmentState::Suspended, reason, at,
                                              record.fence});
    trim_history(record);
    Status status =
        store_assignment(record, RequestId{}, Digest::zero(), RecordType::AssignmentTransitioned);
    if (!status) {
      return status.error();
    }
    stats.assignments_suspended += 1;
    suspended += 1;
  }
  report.checked = checked;
  report.suspended = suspended;
  report.degraded = degraded;
  report.unchanged = checked > (suspended + degraded) ? checked - suspended - degraded : 0;
  return ok_status();
}

void Fabric::Impl::apply_recovery_invariants() {
  for (auto& entry : state.sources) {
    entry.second.restart_floor = entry.second.last_sequence;
  }
  recovery.observations_invalidated = state.observations.size();
  state.observations.clear();
  recovery.authority_invalidated = state.authority.size();
  state.next_fence_sequence = 0;
}

// ---------------------------------------------------------------------------
// Placement
// ---------------------------------------------------------------------------

namespace {

AuthorityId find_admitting_authority(const FabricState& state, AuthorityAction action,
                                     FunctionClass cls, DeviceKind kind, const HostId& host,
                                     const ScopeId& scope, const SemanticsMask& semantics,
                                     PolicyGeneration policy_generation, Micros now) {
  for (const auto& entry : state.authority) {
    const AuthorityGrant& grant = entry.second;
    if (!evidence_current(state, grant.provenance.source, EvidenceDomain::Authority,
                          grant.provenance.sequence)) {
      continue;
    }
    const AuthorityDecision decision =
        authority_admits(grant, action, cls, kind, host, scope, semantics, policy_generation, now);
    if (decision.admitted) {
      return grant.id;
    }
  }
  return AuthorityId{};
}

}  // namespace

Result<PlanResult> Fabric::Impl::plan_locked(const PlacementRequest& request,
                                             const CancelToken* cancel) {
  const Micros at = now();
  PlanResult result;
  Explanation& explanation = result.explanation;
  explanation.request_id = request.request_id;
  explanation.function = request.function;
  explanation.cls = request.cls;
  explanation.scope = request.scope;
  explanation.exclusivity = request.exclusivity;
  explanation.input_digest = fingerprint_of(request);

  const auto refuse = [&](ReasonCode reason, const char* detail) -> Result<PlanResult> {
    result.decision = Decision::Refuse;
    result.primary_reason = reason;
    explanation.decision = Decision::Refuse;
    explanation.primary_reason = reason;
    explanation.reasons.clear();
    explanation.reasons.push_back(reason);
    (void)detail;
    return result;
  };

  if (cancel != nullptr && cancel->cancelled()) {
    stats.cancellations += 1;
    return Error(ReasonCode::Cancelled, "plan cancelled");
  }
  Status scope_status = request.scope.validate();
  if (!scope_status) {
    return Error(scope_status.error().code, scope_status.error().detail);
  }
  ScopeId scope_id{};
  if (request.scope.kind != ScopeKind::Global) {
    auto derived = derive_scope_id(request.scope);
    if (!derived) {
      return Error(derived.error().code, derived.error().detail);
    }
    scope_id = derived.value();
  }
  explanation.scope_id = scope_id;
  if (request.function.empty()) {
    return Error(ReasonCode::InvalidIdentifier, "placement request carries no function");
  }
  if (!state.has_topology) {
    return refuse(ReasonCode::EvidenceMissing, "topology has not been ingested");
  }
  if (!state.has_policy) {
    return refuse(ReasonCode::PolicyStale, "policy has not been ingested");
  }
  if (!evidence_current(state, state.topology.provenance.source, EvidenceDomain::Topology,
                        state.topology.provenance.sequence)) {
    return refuse(ReasonCode::EvidenceSuperseded, "topology evidence predates the last start");
  }
  if (!freshness_usable(state.topology.freshness, at)) {
    return refuse(ReasonCode::TopologyStale, "topology evidence is expired");
  }
  if (!evidence_current(state, state.policy.provenance.source, EvidenceDomain::Policy,
                        state.policy.provenance.sequence)) {
    return refuse(ReasonCode::EvidenceSuperseded, "policy evidence predates the last start");
  }
  if (!freshness_usable(state.policy.freshness, at)) {
    return refuse(ReasonCode::PolicyStale, "policy evidence is expired");
  }
  if (request.min_topology.is_set() && state.topology.generation < request.min_topology) {
    return refuse(ReasonCode::GenerationMismatch, "topology generation is below the request floor");
  }
  if (request.min_policy.is_set() && state.policy.generation < request.min_policy) {
    return refuse(ReasonCode::PolicyStale, "policy generation is below the request floor");
  }
  const ScopeSpec& placement_scope = request.scope;

  FunctionDescriptor function;
  function.id = request.function;
  function.cls = request.cls;
  function.required = request.required;
  function.required_version = request.required_version;
  const auto registered = state.functions.find(request.function);
  if (registered != state.functions.end()) {
    if (registered->second.cls != request.cls) {
      return refuse(ReasonCode::SemanticsMismatch,
                    "request function class differs from the registered class");
    }
    if (request.required_version.major != 0 || request.required_version.minor != 0) {
      if (!(request.required_version == registered->second.required_version)) {
        return refuse(ReasonCode::SemanticsMismatch,
                      "request version differs from the registered version");
      }
    }
    function.required_version = registered->second.required_version;
    function.required = registered->second.required.unite(request.required);
  }
  if (function.required.count() > bounds.max_semantics_per_requirement) {
    return Error(ReasonCode::LimitExceeded, "requirement exceeds the semantics bound");
  }

  const PolicyRule* rule = state.policy.find_rule(request.cls);
  if (rule == nullptr) {
    return refuse(ReasonCode::RefusedByPolicy, "policy carries no rule for this function class");
  }

  // Replacement intent: the current exclusive holder is the assignment being
  // replaced, so it does not conflict with itself.
  AssignmentId replacing{};
  if (request.request_replacement || request.exclusivity == Exclusivity::Exclusive) {
    const auto scope_holder = state.exclusive_by_scope.find(scope_id);
    if (scope_holder != state.exclusive_by_scope.end()) {
      replacing = scope_holder->second;
    }
    ExclusivityKey key;
    key.scope = scope_id;
    key.cls = request.cls;
    const auto class_holder = state.exclusive_by_class.find(key);
    if (class_holder != state.exclusive_by_class.end()) {
      replacing = class_holder->second;
    }
  }
  if (!request.request_replacement && !replacing.empty()) {
    stats.exclusive_conflicts += 1;
    result.decision = Decision::Refuse;
    result.primary_reason = ReasonCode::ExclusiveConflict;
    explanation.decision = Decision::Refuse;
    explanation.primary_reason = ReasonCode::ExclusiveConflict;
    explanation.reasons.push_back(ReasonCode::ExclusiveConflict);
    explanation.assignment = replacing;
    return result;
  }

  EvaluationContext context;
  context.state = &state;
  context.bounds = &bounds;
  context.now = at;
  context.function = &function;
  context.rule = rule;
  context.policy = &state.policy;
  context.topology = &state.topology;
  context.request = &request;
  context.request_scope = scope_id;
  context.replacing = replacing;

  std::vector<CandidateEvaluation> candidates;
  const std::size_t device_count = state.topology.devices.size();
  const std::size_t limit =
      device_count < bounds.max_candidates_per_plan ? device_count : bounds.max_candidates_per_plan;
  bool truncated = false;
  if (device_count > limit) {
    truncated = true;
    stats.results_truncated += 1;
  }
  candidates.reserve(limit);
  for (std::size_t i = 0; i < limit; ++i) {
    const DeviceRecord& device = state.topology.devices[i];
    CandidateEvaluation evaluation = evaluate_device(context, device);
    const DemandVector used = detail::committed_demand_for(state, device.id);
    finalize_ranking(evaluation, device.capacity, used, placement_scope, request.preferred_hosts);
    auto digest = wire::digest_with(
        evaluation, 4096,
        [&](const CandidateEvaluation& value, BinWriter& writer) {
          return wire::encode_candidate(value, writer);
        });
    evaluation.evaluation_digest = digest ? digest.value() : Digest::zero();
    candidates.push_back(std::move(evaluation));
  }

  const CandidateEvaluation* selected = nullptr;
  for (const CandidateEvaluation& candidate : candidates) {
    if (!candidate.eligible) {
      continue;
    }
    if (selected == nullptr || candidate_precedes(candidate, *selected)) {
      selected = &candidate;
    }
  }

  result.candidates_total = candidates.size();
  result.candidates_truncated = truncated;
  const std::size_t reported =
      candidates.size() < bounds.max_candidates_reported ? candidates.size()
                                                         : bounds.max_candidates_reported;
  result.candidates.assign(candidates.begin(),
                           candidates.begin() + static_cast<std::ptrdiff_t>(reported));
  explanation.candidates = result.candidates;
  explanation.candidates_total = candidates.size();
  explanation.candidates_truncated = truncated || reported < candidates.size();
  explanation.binding.topology = state.topology.generation;
  explanation.binding.policy = state.policy.generation;
  explanation.binding.assignment = AssignmentGeneration::from_validated(1);

  if (selected == nullptr) {
    const ReasonCode reason =
        candidates.empty() ? ReasonCode::NoEligibleTarget : primary_refusal_reason(candidates);
    result.decision = Decision::Refuse;
    result.primary_reason = reason;
    explanation.decision = Decision::Refuse;
    explanation.primary_reason = reason;
    explanation.reasons.clear();
    explanation.reasons.push_back(reason);
    if (truncated) {
      explanation.reasons.push_back(ReasonCode::TruncatedResult);
    }
    return result;
  }

  const SemanticsMask effective = function.required.unite(rule->required);
  AssignmentPlan& plan = result.plan;
  plan.request_id = request.request_id;
  plan.function = request.function;
  plan.cls = request.cls;
  plan.scope = request.scope;
  plan.scope_id = scope_id;
  plan.exclusivity = request.exclusivity;
  plan.exclusive_key = rule->exclusive_key;
  plan.mode = selected->mode;
  plan.device = selected->device;
  plan.host = selected->host;
  plan.kind = selected->kind;
  plan.incarnation = selected->incarnation;
  plan.demand = request.demand;
  plan.binding = explanation.binding;
  plan.binding.capability = selected->capability_generation;
  const CapabilityRecord* capability = lookup_capability(state, selected->device, request.cls);
  if (capability != nullptr) {
    plan.binding.schema = capability->schema;
  }
  plan.effective_requirement = effective;
  plan.authority = rule->require_authority
                       ? find_admitting_authority(state, AuthorityAction::Place, request.cls,
                                                  selected->kind, selected->host, scope_id, effective,
                                                  state.policy.generation, at)
                       : AuthorityId{};
  if (rule->require_authority && plan.authority.empty()) {
    result.decision = Decision::Refuse;
    result.primary_reason = ReasonCode::AuthorityMissing;
    explanation.decision = Decision::Refuse;
    explanation.primary_reason = ReasonCode::AuthorityMissing;
    explanation.reasons.clear();
    explanation.reasons.push_back(ReasonCode::AuthorityMissing);
    return result;
  }
  auto plan_digest = wire::digest_with(
      plan, bounds.max_canonical_bytes, [&](const AssignmentPlan& value, BinWriter& writer) {
        return wire::encode_plan(value, writer, bounds);
      });
  plan.plan_digest = plan_digest ? plan_digest.value() : Digest::zero();

  result.decision = replacing.empty() ? Decision::Accept : Decision::Replace;
  result.primary_reason = plan.mode == ExecutionMode::HostFallback ? ReasonCode::HostFallbackApplied
                                                                   : ReasonCode::Ok;
  explanation.decision = result.decision;
  explanation.primary_reason = result.primary_reason;
  explanation.reasons.clear();
  if (plan.mode == ExecutionMode::HostFallback) {
    explanation.reasons.push_back(ReasonCode::HostFallbackApplied);
  }
  if (truncated) {
    // Every bounded truncation is observable and accounted for.
    explanation.reasons.push_back(ReasonCode::TruncatedResult);
  }
  explanation.binding = plan.binding;
  explanation.authority = plan.authority;
  explanation.mode = plan.mode;
  explanation.selected_device = plan.device;
  explanation.replaced = replacing;
  auto decision_digest = wire::digest_with(
      plan, bounds.max_canonical_bytes, [&](const AssignmentPlan& value, BinWriter& writer) {
        Status status = wire::encode_plan(value, writer, bounds);
        if (!status) {
          return status;
        }
        return writer.u8(static_cast<std::uint8_t>(explanation.decision));
      });
  explanation.decision_digest = decision_digest ? decision_digest.value() : Digest::zero();
  return result;
}

// ---------------------------------------------------------------------------
// Fabric lifecycle
// ---------------------------------------------------------------------------

Fabric::Fabric(FabricConfig config) : impl_(std::make_unique<Impl>()) {
  impl_->config = std::move(config);
  impl_->bounds = impl_->config.bounds;
  impl_->clock = impl_->config.clock ? impl_->config.clock : std::make_shared<SystemClock>();
}

Fabric::~Fabric() {
  if (impl_) {
    (void)shutdown();
  }
}

Status Fabric::start() {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (impl.running) {
    return Error(ReasonCode::AlreadyExists, "runtime is already started");
  }
  impl.shutting_down = false;
  Status status = validate_bounds(impl.bounds);
  if (!status) {
    return status;
  }
  const BootId boot = impl.config.boot_id.is_set() ? impl.config.boot_id : generate_boot_id();

  if (impl.config.store_path.empty()) {
    impl.recovery = RecoveryReport{};
    impl.recovery.classification = RecoveryClassification::MemoryOnly;
    impl.recovery.reason = ReasonCode::Ok;
    impl.state.epoch_counter = 1;
    impl.state.epoch.counter = 1;
    impl.state.epoch.boot = boot;
    impl.recovery.epoch = impl.state.epoch;
    impl.running = true;
    impl.recovery_accepted = true;
    return ok_status();
  }

  StoreOpenOptions options;
  options.create_if_missing = true;
  options.recovery = impl.config.recovery;
  options.durable_commit = impl.config.durable_commit;
  options.max_journal_bytes = impl.bounds.max_journal_bytes;
  options.max_snapshot_bytes = impl.bounds.max_snapshot_bytes;
  options.max_record_bytes = impl.bounds.max_record_bytes;
  options.expected_store_id = impl.config.store_id;
  options.format_version = kStoreFormatVersion;

  RecoveryReport report;
  auto store = JournalStore::open(impl.config.store_path, options, report);
  if (!store) {
    impl.recovery = report;
    return Error(store.error().code, store.error().detail);
  }
  impl.store = store.take();
  impl.store->set_crash_hook([&impl]() { impl.inject(CrashBoundary::DuringCompaction); });
  impl.recovery = report;

  impl.inject(CrashBoundary::BeforeRecovery);

  auto snapshot = impl.store->snapshot_payload();
  if (snapshot) {
    BinReader envelope(snapshot.value(), impl.bounds.max_text_bytes);
    auto payload = envelope.take_bytes(impl.bounds.max_snapshot_bytes);
    if (!payload) {
      impl.recovery.classification = RecoveryClassification::RefusedCorrupt;
      impl.recovery.reason = payload.error().code;
      return Error(payload.error().code, payload.error().detail);
    }
    auto digest = envelope.digest();
    if (!digest) {
      impl.recovery.classification = RecoveryClassification::RefusedCorrupt;
      impl.recovery.reason = digest.error().code;
      return Error(digest.error().code, digest.error().detail);
    }
    if (!envelope.at_end()) {
      impl.recovery.classification = RecoveryClassification::RefusedCorrupt;
      impl.recovery.reason = ReasonCode::StoreCorrupt;
      return Error(ReasonCode::StoreCorrupt, "snapshot envelope carries trailing bytes");
    }
    if (!(sha256(payload.value()) == digest.value())) {
      impl.recovery.classification = RecoveryClassification::RefusedCorrupt;
      impl.recovery.reason = ReasonCode::IntegrityFailure;
      return Error(ReasonCode::IntegrityFailure, "snapshot payload integrity check failed");
    }
    BinReader reader(payload.value(), impl.bounds.max_text_bytes);
    auto decoded = detail::decode_state(reader, impl.bounds);
    if (!decoded) {
      impl.recovery.classification = RecoveryClassification::IncompatibleSemantics;
      impl.recovery.reason = decoded.error().code;
      return Error(decoded.error().code,
                   "snapshot state could not be reconstructed at offset " +
                       std::to_string(reader.position()) + " of " +
                       std::to_string(payload.value().size()) + ": " +
                       decoded.error().detail);
    }
    impl.state = decoded.take();
  }

  impl.replaying = true;
  status = impl.store->replay(
      [&impl](RecordType type, std::uint64_t sequence, std::span<const std::byte> payload) {
        const Status applied = impl.apply_record(type, payload);
        if (!applied) {
          // Replay failures name the exact record so a damaged store is
          // diagnosable without a debugger.
          return Status(Error(applied.error().code,
                              std::string("record ") + to_string(type) + " at sequence " +
                                  std::to_string(sequence) + ": " + applied.error().detail));
        }
        return applied;
      });
  impl.replaying = false;
  if (!status) {
    impl.recovery.classification = RecoveryClassification::RefusedCorrupt;
    impl.recovery.reason = status.error().code;
    return Error(status.error().code,
                 "journal replay failed: " + status.error().detail);
  }
  detail::rebuild_indexes(impl.state);
  impl.recovery.records_replayed = impl.store->record_count();
  impl.recovery.store_generation = impl.store->generation();

  // Conservative restart: advance the epoch, fence everything that predates
  // this process, and refuse to treat any prior authority as current.
  impl.recovery.previous_epoch = impl.state.epoch_counter;
  std::uint64_t next_epoch = 1;
  if (impl.state.epoch_counter > 0) {
    if (!checked_add(impl.state.epoch_counter, std::uint64_t{1}, next_epoch)) {
      return Error(ReasonCode::ArithmeticOverflow, "coordinator epoch exhausted");
    }
  }
  impl.state.previous_epoch_counter = impl.state.epoch_counter;
  impl.state.epoch_counter = next_epoch;
  impl.state.epoch.counter = next_epoch;
  impl.state.epoch.boot = boot;
  BinWriter epoch_writer(64);
  status = wire::encode_epoch(impl.state.epoch, epoch_writer);
  if (!status) {
    return status.error();
  }
  status = impl.commit(RecordType::EpochStarted, epoch_writer.data());
  if (!status) {
    return Error(status.error().code, "coordinator epoch could not be committed");
  }
  impl.recovery.epoch = impl.state.epoch;

  impl.apply_recovery_invariants();

  // Every lease from a previous process lifetime is void, and every assignment
  // that claimed authority is suspended until it is re-authorized.
  std::vector<AssignmentId> live_ids;
  for (const auto& entry : impl.state.assignments) {
    if (is_live(entry.second.state)) {
      live_ids.push_back(entry.first);
    }
  }
  const Micros at = impl.now();
  for (const AssignmentId& id : live_ids) {
    const auto it = impl.state.assignments.find(id);
    if (it == impl.state.assignments.end()) {
      continue;
    }
    AssignmentRecord record = it->second;
    if (record.state == AssignmentState::Suspended) {
      continue;
    }
    record.state = AssignmentState::Suspended;
    record.state_reason = ReasonCode::RestartAuthorityReset;
    record.updated_at = at;
    record.history.push_back(TransitionRecord{it->second.state, AssignmentState::Suspended,
                                              ReasonCode::RestartAuthorityReset, at, record.fence});
    impl.trim_history(record);
    status = impl.store_assignment(record, RequestId{}, Digest::zero(),
                                   RecordType::AssignmentTransitioned);
    if (!status) {
      return status.error();
    }
    impl.recovery.assignments_suspended += 1;
    impl.recovery.leases_voided += 1;
    impl.recovery.fences_invalidated += 1;
  }
  impl.recovery.authority_restored = false;
  impl.recovery.reason = ReasonCode::RestartAuthorityReset;
  impl.running = true;
  impl.recovery_accepted = impl.config.auto_accept_recovery;
  impl.stats.recovery_events += 1;
  return ok_status();
}

Status Fabric::shutdown() {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (impl.shutting_down || !impl.running) {
    impl.shutting_down = true;
    return ok_status();
  }
  impl.shutting_down = true;
  impl.inject(CrashBoundary::DuringShutdown);
  if (impl.store) {
    Status status = impl.store->seal(impl.state.epoch.counter);
    if (!status) {
      impl.stats.commit_failures += 1;
      (void)impl.store->close();
      impl.store.reset();
      impl.running = false;
      return status.error();
    }
    status = impl.store->flush();
    if (!status) {
      impl.stats.commit_failures += 1;
    }
    (void)impl.store->close();
    impl.store.reset();
  }
  impl.running = false;
  impl.stats.shutdowns += 1;
  return ok_status();
}

Status Fabric::accept_recovery() {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  impl.recovery_accepted = true;
  return ok_status();
}

bool Fabric::is_running() const noexcept { return impl_->running; }

bool Fabric::is_shutting_down() const noexcept { return impl_->shutting_down; }

CoordinatorEpoch Fabric::epoch() const {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  return impl.state.epoch;
}

const RecoveryReport& Fabric::recovery_report() const { return impl_->recovery; }

const Bounds& Fabric::bounds() const noexcept { return impl_->bounds; }

const FabricConfig& Fabric::config() const noexcept { return impl_->config; }

// ---------------------------------------------------------------------------
// Evidence ingestion
// ---------------------------------------------------------------------------

Status Fabric::register_function(const FunctionDescriptor& function) {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  if (!impl.recovery_accepted) {
    return Error(ReasonCode::RecoveryRequired, "recovery classification has not been accepted");
  }
  if (function.id.empty()) {
    impl.stats.functions_refused += 1;
    return Error(ReasonCode::InvalidIdentifier, "function identifier is empty");
  }
  if (function.required.count() > impl.bounds.max_semantics_per_requirement) {
    impl.stats.functions_refused += 1;
    return Error(ReasonCode::LimitExceeded, "function requirement exceeds the semantics bound");
  }
  if (impl.state.functions.size() >= impl.bounds.max_functions) {
    const auto existing = impl.state.functions.find(function.id);
    if (existing == impl.state.functions.end()) {
      impl.stats.functions_refused += 1;
      return Error(ReasonCode::LimitExceeded, "function registry is full");
    }
  }
  const auto existing = impl.state.functions.find(function.id);
  if (existing != impl.state.functions.end() && existing->second == function) {
    impl.stats.duplicate_deliveries_idempotent += 1;
    return ok_status();
  }
  BinWriter writer(impl.bounds.max_record_bytes);
  Status status = wire::encode_function(function, writer);
  if (!status) {
    impl.stats.functions_refused += 1;
    return status.error();
  }
  status = impl.commit(RecordType::FunctionRegistered, writer.data());
  if (!status) {
    impl.stats.functions_refused += 1;
    return status.error();
  }
  impl.state.functions[function.id] = function;
  impl.stats.functions_registered += 1;
  return ok_status();
}

Status Fabric::ingest_topology(const TopologySnapshot& snapshot) {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  if (!impl.recovery_accepted) {
    return Error(ReasonCode::RecoveryRequired, "recovery classification has not been accepted");
  }
  Status status = validate_topology(snapshot, impl.bounds);
  if (!status) {
    impl.stats.topology_refused += 1;
    return status.error();
  }
  auto digest = wire::digest_with(
      snapshot, impl.bounds.max_canonical_bytes,
      [&](const TopologySnapshot& value, BinWriter& writer) {
        return wire::encode_topology(value, writer, impl.bounds);
      });
  if (!digest) {
    impl.stats.topology_refused += 1;
    return digest.error();
  }
  bool duplicate = false;
  status = impl.accept_evidence(snapshot.provenance.source, EvidenceDomain::Topology,
                                snapshot.provenance.sequence, digest.value(), duplicate);
  if (!status) {
    impl.stats.topology_refused += 1;
    return status.error();
  }
  if (duplicate) {
    impl.stats.duplicate_deliveries_idempotent += 1;
    return ok_status();
  }
  if (impl.state.has_topology) {
    if (snapshot.generation < impl.state.topology.generation) {
      impl.stats.evidence_superseded += 1;
      impl.stats.topology_refused += 1;
      return Error(ReasonCode::EvidenceSuperseded,
                   "topology generation is older than the current generation");
    }
    if (snapshot.generation == impl.state.topology.generation &&
        !(impl.state.topology_digest == digest.value())) {
      impl.stats.evidence_conflicting += 1;
      impl.stats.topology_refused += 1;
      return Error(ReasonCode::EvidenceConflicting,
                   "topology content changed without a generation increment");
    }
  }
  BinWriter writer(impl.bounds.max_record_bytes);
  status = wire::encode_topology(snapshot, writer, impl.bounds);
  if (!status) {
    impl.stats.topology_refused += 1;
    return status.error();
  }
  status = impl.commit(RecordType::TopologyIngested, writer.data());
  if (!status) {
    impl.stats.topology_refused += 1;
    return status.error();
  }
  impl.state.topology = snapshot;
  impl.state.has_topology = true;
  impl.state.topology_digest = digest.value();
  impl.mark_source(snapshot.provenance.source, EvidenceDomain::Topology, snapshot.provenance.sequence,
                   digest.value());
  impl.stats.topology_accepted += 1;
  status = impl.revalidate_now();
  if (!status) {
    return status.error();
  }
  return ok_status();
}

Status Fabric::ingest_capabilities(const CapabilityReport& report) {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  if (!impl.recovery_accepted) {
    return Error(ReasonCode::RecoveryRequired, "recovery classification has not been accepted");
  }
  Status status = validate_capability_report(report, impl.bounds);
  if (!status) {
    impl.stats.capability_reports_refused += 1;
    return status.error();
  }
  auto digest = wire::digest_with(
      report, impl.bounds.max_canonical_bytes,
      [&](const CapabilityReport& value, BinWriter& writer) {
        return wire::encode_capability_report(value, writer, impl.bounds);
      });
  if (!digest) {
    impl.stats.capability_reports_refused += 1;
    return digest.error();
  }
  bool duplicate = false;
  status = impl.accept_evidence(report.provenance.source, EvidenceDomain::Capability,
                                report.provenance.sequence, digest.value(), duplicate);
  if (!status) {
    impl.stats.capability_reports_refused += 1;
    return status.error();
  }
  if (duplicate) {
    impl.stats.duplicate_deliveries_idempotent += 1;
    return ok_status();
  }
  for (const CapabilityRecord& record : report.records) {
    CapabilityKey key;
    key.device = record.device;
    key.cls = record.cls;
    const auto existing = impl.state.capabilities.find(key);
    if (existing == impl.state.capabilities.end()) {
      continue;
    }
    if (record.generation < existing->second.generation) {
      impl.stats.evidence_superseded += 1;
      impl.stats.capability_reports_refused += 1;
      return Error(ReasonCode::EvidenceSuperseded,
                   "capability generation is older than the current generation for a device");
    }
    if (record.generation == existing->second.generation &&
        capability_records_conflict(record, existing->second)) {
      impl.stats.capability_conflicts += 1;
      impl.stats.capability_reports_refused += 1;
      return Error(ReasonCode::EvidenceConflicting,
                   "capability content changed without a generation increment");
    }
  }
  BinWriter writer(impl.bounds.max_record_bytes);
  status = wire::encode_capability_report(report, writer, impl.bounds);
  if (!status) {
    impl.stats.capability_reports_refused += 1;
    return status.error();
  }
  status = impl.commit(RecordType::CapabilityIngested, writer.data());
  if (!status) {
    impl.stats.capability_reports_refused += 1;
    return status.error();
  }
  for (const CapabilityRecord& record : report.records) {
    CapabilityKey key;
    key.device = record.device;
    key.cls = record.cls;
    impl.state.capabilities[key] = record;
  }
  impl.mark_source(report.provenance.source, EvidenceDomain::Capability, report.provenance.sequence,
                   digest.value());
  impl.stats.capability_reports_accepted += 1;
  status = impl.revalidate_now();
  if (!status) {
    return status.error();
  }
  return ok_status();
}

Status Fabric::ingest_policy(const PolicySnapshot& snapshot) {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  if (!impl.recovery_accepted) {
    return Error(ReasonCode::RecoveryRequired, "recovery classification has not been accepted");
  }
  Status status = validate_policy_snapshot(snapshot, impl.bounds);
  if (!status) {
    impl.stats.policy_refused += 1;
    return status.error();
  }
  auto digest = wire::digest_with(
      snapshot, impl.bounds.max_canonical_bytes,
      [&](const PolicySnapshot& value, BinWriter& writer) {
        return wire::encode_policy(value, writer, impl.bounds);
      });
  if (!digest) {
    impl.stats.policy_refused += 1;
    return digest.error();
  }
  bool duplicate = false;
  status = impl.accept_evidence(snapshot.provenance.source, EvidenceDomain::Policy,
                                snapshot.provenance.sequence, digest.value(), duplicate);
  if (!status) {
    impl.stats.policy_refused += 1;
    return status.error();
  }
  if (duplicate) {
    impl.stats.duplicate_deliveries_idempotent += 1;
    return ok_status();
  }
  if (impl.state.has_policy) {
    if (snapshot.generation < impl.state.policy.generation) {
      impl.stats.evidence_superseded += 1;
      impl.stats.policy_refused += 1;
      return Error(ReasonCode::EvidenceSuperseded,
                   "policy generation is older than the current generation");
    }
    if (snapshot.generation == impl.state.policy.generation &&
        !(impl.state.policy_digest == digest.value())) {
      impl.stats.evidence_conflicting += 1;
      impl.stats.policy_refused += 1;
      return Error(ReasonCode::EvidenceConflicting,
                   "policy content changed without a generation increment");
    }
  }
  BinWriter writer(impl.bounds.max_record_bytes);
  status = wire::encode_policy(snapshot, writer, impl.bounds);
  if (!status) {
    impl.stats.policy_refused += 1;
    return status.error();
  }
  status = impl.commit(RecordType::PolicyIngested, writer.data());
  if (!status) {
    impl.stats.policy_refused += 1;
    return status.error();
  }
  impl.state.policy = snapshot;
  impl.state.has_policy = true;
  impl.state.policy_digest = digest.value();
  impl.mark_source(snapshot.provenance.source, EvidenceDomain::Policy, snapshot.provenance.sequence,
                   digest.value());
  impl.stats.policy_accepted += 1;
  status = impl.revalidate_now();
  if (!status) {
    return status.error();
  }
  return ok_status();
}

Status Fabric::ingest_observations(const ObservationReport& report) {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  if (!impl.recovery_accepted) {
    return Error(ReasonCode::RecoveryRequired, "recovery classification has not been accepted");
  }
  Status status = validate_observation_report(report, impl.bounds);
  if (!status) {
    impl.stats.observations_refused += 1;
    return status.error();
  }
  if (!impl.state.has_topology) {
    impl.stats.observations_refused += 1;
    return Error(ReasonCode::EvidenceMissing, "observations require a topology");
  }
  if (!(report.topology_generation == impl.state.topology.generation)) {
    impl.stats.observations_refused += 1;
    impl.stats.evidence_stale_refusals += 1;
    return Error(ReasonCode::TopologyStale,
                 "observation report targets a different topology generation");
  }
  for (const DeviceObservation& observation : report.devices) {
    const DeviceRecord* device = impl.state.topology.find_device(observation.device);
    if (device == nullptr) {
      impl.stats.observations_refused += 1;
      return Error(ReasonCode::UnknownIdentity,
                   "observation references an unknown device: " + observation.device.value());
    }
    if (!(device->incarnation == observation.incarnation)) {
      impl.stats.observations_refused += 1;
      return Error(ReasonCode::IncarnationMismatch,
                   "observation incarnation differs from the current topology incarnation");
    }
  }
  auto digest = wire::digest_with(
      report, impl.bounds.max_canonical_bytes,
      [&](const ObservationReport& value, BinWriter& writer) {
        return wire::encode_observation_report(value, writer, impl.bounds);
      });
  if (!digest) {
    impl.stats.observations_refused += 1;
    return digest.error();
  }
  bool duplicate = false;
  status = impl.accept_evidence(report.provenance.source, EvidenceDomain::Observation,
                                report.provenance.sequence, digest.value(), duplicate);
  if (!status) {
    impl.stats.observations_refused += 1;
    return status.error();
  }
  if (duplicate) {
    impl.stats.duplicate_deliveries_idempotent += 1;
    return ok_status();
  }
  BinWriter writer(impl.bounds.max_record_bytes);
  status = wire::encode_observation_report(report, writer, impl.bounds);
  if (!status) {
    impl.stats.observations_refused += 1;
    return status.error();
  }
  status = impl.commit(RecordType::ObservationsIngested, writer.data());
  if (!status) {
    impl.stats.observations_refused += 1;
    return status.error();
  }
  for (const DeviceObservation& observation : report.devices) {
    impl.state.observations[observation.device] = observation;
  }
  impl.mark_source(report.provenance.source, EvidenceDomain::Observation,
                   report.provenance.sequence, digest.value());
  impl.stats.observations_accepted += 1;
  status = impl.revalidate_now();
  if (!status) {
    return status.error();
  }
  return ok_status();
}

Status Fabric::grant_authority(const AuthorityGrant& grant) {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  if (!impl.recovery_accepted) {
    return Error(ReasonCode::RecoveryRequired, "recovery classification has not been accepted");
  }
  Status status = validate_authority_grant(grant, impl.bounds);
  if (!status) {
    impl.stats.authority_refused += 1;
    return status.error();
  }
  if (!impl.state.has_policy) {
    impl.stats.authority_refused += 1;
    return Error(ReasonCode::PolicyStale, "authority requires a current policy");
  }
  if (!(grant.policy_generation == impl.state.policy.generation)) {
    impl.stats.authority_refused += 1;
    return Error(ReasonCode::PolicyStale,
                 "authority is bound to a different policy generation");
  }
  auto digest = wire::digest_with(
      grant, impl.bounds.max_canonical_bytes,
      [&](const AuthorityGrant& value, BinWriter& writer) {
        return wire::encode_authority(value, writer, impl.bounds);
      });
  if (!digest) {
    impl.stats.authority_refused += 1;
    return digest.error();
  }
  bool duplicate = false;
  status = impl.accept_evidence(grant.provenance.source, EvidenceDomain::Authority,
                                grant.provenance.sequence, digest.value(), duplicate);
  if (!status) {
    impl.stats.authority_refused += 1;
    return status.error();
  }
  if (duplicate) {
    impl.stats.duplicate_deliveries_idempotent += 1;
    return ok_status();
  }
  const auto existing = impl.state.authority.find(grant.id);
  if (existing != impl.state.authority.end()) {
    if (existing->second == grant) {
      impl.stats.duplicate_deliveries_idempotent += 1;
      return ok_status();
    }
    impl.stats.authority_refused += 1;
    return Error(ReasonCode::AlreadyExists,
                 "an authority grant with this identifier already exists");
  }
  if (impl.state.authority.size() >= impl.bounds.max_authority_grants) {
    impl.stats.authority_refused += 1;
    return Error(ReasonCode::LimitExceeded, "authority grant store is full");
  }
  BinWriter writer(impl.bounds.max_record_bytes);
  status = wire::encode_authority(grant, writer, impl.bounds);
  if (!status) {
    impl.stats.authority_refused += 1;
    return status.error();
  }
  status = impl.commit(RecordType::AuthorityGranted, writer.data());
  if (!status) {
    impl.stats.authority_refused += 1;
    return status.error();
  }
  impl.state.authority[grant.id] = grant;
  impl.mark_source(grant.provenance.source, EvidenceDomain::Authority, grant.provenance.sequence,
                   digest.value());
  impl.stats.authority_granted += 1;
  return ok_status();
}

Status Fabric::withdraw_authority(const AuthorityId& id, ReasonCode reason) {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  if (id.empty()) {
    return Error(ReasonCode::InvalidIdentifier, "authority identifier is empty");
  }
  const auto it = impl.state.authority.find(id);
  if (it == impl.state.authority.end()) {
    return Error(ReasonCode::NotFound, "authority grant does not exist");
  }
  if (it->second.revoked) {
    impl.stats.duplicate_deliveries_idempotent += 1;
    return ok_status();
  }
  const Micros at = impl.now();
  RecordedWithdrawal payload;
  payload.authority = id;
  payload.reason = reason;
  payload.at = at;
  BinWriter writer(impl.bounds.max_record_bytes);
  Status status = encode_recorded_withdrawal(payload, writer);
  if (!status) {
    return status.error();
  }
  status = impl.commit(RecordType::AuthorityWithdrawn, writer.data());
  if (!status) {
    return status.error();
  }
  it->second.revoked = true;
  impl.stats.authority_withdrawn += 1;
  status = impl.revalidate_now();
  if (!status) {
    return status.error();
  }
  return ok_status();
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

namespace {

bool cancellation_requested(const CancelToken* token) {
  return token != nullptr && token->cancelled();
}

Status replay_cached_assignment(const IdempotencyEntry& entry, Result<AssignmentRecord>& out) {
  if (entry.outcome != ReasonCode::Ok) {
    BinReader reader(std::span<const std::byte>(entry.response.data(), entry.response.size()),
                     4096);
    auto error = decode_error_envelope(reader);
    if (!error) {
      out = error.error();
      return ok_status();
    }
    out = Error(error.value().code, error.value().detail);
    return ok_status();
  }
  const Bounds bounds{};
  BinReader reader(std::span<const std::byte>(entry.response.data(), entry.response.size()),
                   bounds.max_text_bytes);
  auto record = wire::decode_assignment(reader, bounds);
  if (!record) {
    out = record.error();
    return ok_status();
  }
  out = record.take();
  return ok_status();
}

}  // namespace

Result<AssignmentRecord> Fabric::Impl::authorize_locked(const PlanResult& planned,
                                                        const ApplyOptions& options) {
  const AssignmentPlan& plan = planned.plan;
  const Micros at = now();
  BinWriter plan_writer(bounds.max_canonical_bytes);
  {
    AssignmentPlan copy = plan;
    copy.plan_digest = Digest::zero();
    Status status = wire::encode_plan(copy, plan_writer, bounds);
    if (!status) {
      return status.error();
    }
  }
  if (!(plan_writer.fingerprint() == plan.plan_digest)) {
    return Error(ReasonCode::PlanSuperseded, "plan digest does not match the plan contents");
  }
  Status status = plan.scope.validate();
  if (!status) {
    return Error(status.error().code, status.error().detail);
  }
  ScopeId derived{};
  if (plan.scope.kind != ScopeKind::Global) {
    auto maybe = derive_scope_id(plan.scope);
    if (!maybe) {
      return Error(maybe.error().code, maybe.error().detail);
    }
    derived = maybe.value();
  }
  if (!(plan.scope_id == derived)) {
    return Error(ReasonCode::MalformedInput,
                 "plan scope identity does not re-derive from its scope specification");
  }
  if (!state.has_topology || !state.has_policy) {
    return Error(ReasonCode::EvidenceMissing, "placement requires current topology and policy");
  }
  if (!(state.topology.generation == plan.binding.topology)) {
    return Error(ReasonCode::PlanSuperseded,
                 "topology generation changed after the plan was produced");
  }
  if (!(state.policy.generation == plan.binding.policy)) {
    return Error(ReasonCode::PlanSuperseded,
                 "policy generation changed after the plan was produced");
  }
  const DeviceRecord* device = state.topology.find_device(plan.device);
  if (device == nullptr || device->decommissioned) {
    return Error(ReasonCode::TargetDisappeared, "plan target is not present in the topology");
  }
  if (!(device->incarnation == plan.incarnation)) {
    return Error(ReasonCode::IncarnationMismatch,
                 "plan target incarnation changed since the plan was produced");
  }
  const CapabilityRecord* capability = lookup_capability(state, plan.device, plan.cls);
  if (plan.binding.capability.is_set()) {
    if (capability == nullptr) {
      return Error(ReasonCode::CapabilityStale, "plan capability evidence is gone");
    }
    if (!(capability->generation == plan.binding.capability)) {
      return Error(ReasonCode::PlanSuperseded,
                   "capability generation changed after the plan was produced");
    }
  }
  const PolicyRule* rule = state.policy.find_rule(plan.cls);
  if (rule == nullptr) {
    return Error(ReasonCode::RefusedByPolicy, "policy carries no rule for this function class");
  }

  AssignmentId replacing{};
  if (plan.exclusivity == Exclusivity::Exclusive) {
    AssignmentId holder{};
    if (scope_has_exclusive_conflict(state, derived, plan.cls, plan.exclusive_key, AssignmentId{},
                                     holder)) {
      if (!options.allow_replacement) {
        stats.exclusive_conflicts += 1;
        return Error(ReasonCode::ExclusiveConflict,
                     "another assignment already holds exclusive authority over this scope");
      }
      replacing = holder;
    }
  }
  if (!replacing.empty()) {
    const std::size_t policy_budget = rule->max_reassignments_per_scope;
    const std::size_t used = reassignment_count(derived, plan.cls, at);
    if (used >= policy_budget) {
      stats.reassignment_budget_refusals += 1;
      return Error(ReasonCode::ReassignmentBudgetExhausted,
                   "the bounded reassignment budget for this scope is exhausted");
    }
  }

  FunctionDescriptor function;
  function.id = plan.function;
  function.cls = plan.cls;
  function.required = plan.effective_requirement;
  const auto registered = state.functions.find(plan.function);
  if (registered != state.functions.end()) {
    function.required_version = registered->second.required_version;
  }
  PlacementRequest synthetic;
  synthetic.request_id = plan.request_id;
  synthetic.function = plan.function;
  synthetic.cls = plan.cls;
  synthetic.scope = plan.scope;
  synthetic.required = plan.effective_requirement;
  synthetic.required_version = function.required_version;
  synthetic.exclusivity = plan.exclusivity;
  synthetic.demand = plan.demand;
  synthetic.allow_host_fallback = plan.mode == ExecutionMode::HostFallback;

  EvaluationContext context;
  context.state = &state;
  context.bounds = &bounds;
  context.now = at;
  context.function = &function;
  context.rule = rule;
  context.policy = &state.policy;
  context.topology = &state.topology;
  context.request = &synthetic;
  context.request_scope = derived;
  context.replacing = replacing;
  const CandidateEvaluation evaluation = evaluate_device(context, *device);
  if (!evaluation.eligible) {
    return Error(evaluation.reason, "plan target is no longer eligible");
  }

  const SemanticsMask effective = function.required.unite(rule->required);
  if (rule->require_authority) {
    if (plan.authority.is_set()) {
      const auto grant = state.authority.find(plan.authority);
      if (grant == state.authority.end()) {
        return Error(ReasonCode::AuthorityMissing, "plan authority grant no longer exists");
      }
      const AuthorityDecision decision =
          authority_admits(grant->second, AuthorityAction::Place, plan.cls, plan.kind, plan.host,
                           derived, effective, state.policy.generation, at);
      if (!decision.admitted) {
        return Error(decision.reason, "plan authority no longer authorizes this placement");
      }
    } else if (find_admitting_authority(state, AuthorityAction::Place, plan.cls, plan.kind,
                                        plan.host, derived, effective, state.policy.generation,
                                        at)
                   .empty()) {
      return Error(ReasonCode::AuthorityMissing, "no current authority authorizes this placement");
    }
  }

  if (options.cancel != nullptr && options.cancel->cancelled()) {
    stats.cancellations += 1;
    return Error(ReasonCode::Cancelled, "placement cancelled before commit");
  }
  inject(CrashBoundary::BeforeCommit);

  AssignmentRecord record;
  auto id = issue_assignment_id(state);
  if (!id) {
    return id.error();
  }
  record.id = id.value();
  record.generation = AssignmentGeneration::from_validated(1);
  record.function = plan.function;
  record.cls = plan.cls;
  record.scope = plan.scope;
  record.scope_id = derived;
  record.exclusivity = plan.exclusivity;
  record.exclusive_key = plan.exclusive_key;
  record.mode = plan.mode;
  record.device = plan.device;
  record.host = plan.host;
  record.kind = plan.kind;
  record.incarnation = plan.incarnation;
  record.demand = plan.demand;
  record.binding = plan.binding;
  record.binding.assignment = record.generation;
  if (capability != nullptr) {
    record.binding.schema = capability->schema;
  }
  record.authority = plan.authority;
  auto lease = issue_lease(state);
  if (!lease) {
    return lease.error();
  }
  record.lease = lease.value();
  auto attempt = issue_attempt(state);
  if (!attempt) {
    return attempt.error();
  }
  record.attempt = attempt.value();
  auto fence = issue_fence(state);
  if (!fence) {
    return fence.error();
  }
  record.fence = fence.value();
  record.request_fingerprint = options.request_id.empty()
                                   ? plan.plan_digest
                                   : fingerprint_of(synthetic);
  record.created_at = at;
  record.updated_at = at;
  record.state = AssignmentState::Dispatched;
  record.state_reason =
      plan.mode == ExecutionMode::HostFallback ? ReasonCode::HostFallbackApplied : ReasonCode::Ok;
  record.history.push_back(
      TransitionRecord{AssignmentState::Planned, AssignmentState::Authorized, ReasonCode::Ok, at,
                       record.fence});
  record.history.push_back(TransitionRecord{AssignmentState::Authorized, AssignmentState::Dispatched,
                                            record.state_reason, at, record.fence});
  record.freshness = effective_freshness_locked(record, at);
  trim_history(record);

  if (!replacing.empty()) {
    const auto previous = state.assignments.find(replacing);
    if (previous != state.assignments.end()) {
      AssignmentRecord superseded = previous->second;
      superseded.state = AssignmentState::Superseded;
      superseded.state_reason = ReasonCode::Superseded;
      superseded.updated_at = at;
      superseded.history.push_back(TransitionRecord{previous->second.state,
                                                    AssignmentState::Superseded,
                                                    ReasonCode::Superseded, at, superseded.fence});
      trim_history(superseded);
      Status supersede_status = store_assignment(superseded, RequestId{}, Digest::zero(),
                                                 RecordType::AssignmentTransitioned);
      if (!supersede_status) {
        return supersede_status.error();
      }
      Status budget_status = note_reassignment(derived, plan.cls, at);
      if (!budget_status) {
        return budget_status.error();
      }
      stats.replaces_accepted += 1;
    }
  }
  if (options.request_id.empty()) {
    Status store_status = store_assignment(record, RequestId{}, Digest::zero(),
                                           RecordType::AssignmentCreated);
    if (!store_status) {
      return store_status.error();
    }
  } else {
    Status store_status =
        store_assignment(record, options.request_id, fingerprint_of(synthetic),
                         RecordType::AssignmentCreated);
    if (!store_status) {
      return store_status.error();
    }
  }
  inject(CrashBoundary::AfterCommitBeforeAck);
  if (record.mode == ExecutionMode::HostFallback) {
    stats.host_fallbacks += 1;
  }
  stats.applies_accepted += 1;
  return record;
}

Freshness Fabric::Impl::effective_freshness_locked(const AssignmentRecord& record, Micros at) const {
  Freshness freshness;
  freshness.observed_at = at;
  std::int64_t limit = 0;
  const auto consider = [&limit](const Freshness& candidate) {
    if (!candidate.is_set()) {
      return;
    }
    if (limit == 0 || candidate.valid_until.value() < limit) {
      limit = candidate.valid_until.value();
    }
  };
  if (state.has_topology) {
    consider(state.topology.freshness);
  }
  if (state.has_policy) {
    consider(state.policy.freshness);
  }
  const CapabilityRecord* capability = lookup_capability(state, record.device, record.cls);
  if (capability != nullptr) {
    consider(capability->freshness);
  }
  const auto observation = state.observations.find(record.device);
  if (observation != state.observations.end()) {
    consider(observation->second.freshness);
  }
  freshness.valid_until = Micros::raw(limit == 0 ? at.value() : limit);
  return freshness;
}

Result<AssignmentRecord> Fabric::Impl::apply_locked(const PlacementRequest& request,
                                                    const ApplyOptions& options) {
  if (options.cancel != nullptr && options.cancel->cancelled()) {
    stats.cancellations += 1;
    stats.refusals_after_cancel += 1;
    return Error(ReasonCode::Cancelled, "placement cancelled before planning");
  }
  const Digest fingerprint = fingerprint_of(request);
  const IdempotencyEntry* cached = find_idempotency(request.request_id);
  if (cached != nullptr) {
    if (cached->request_fingerprint == fingerprint) {
      stats.duplicate_deliveries_idempotent += 1;
      Result<AssignmentRecord> out = Error(ReasonCode::InternalInvariant, "unset");
      Status replay = replay_cached_assignment(*cached, out);
      if (!replay) {
        return replay.error();
      }
      return out;
    }
    stats.duplicate_deliveries_fenced += 1;
    return Error(ReasonCode::DuplicateDelivery,
                 "request identifier was reused with a different payload");
  }
  const Micros at = now();
  auto planned = plan_locked(request, options.cancel);
  if (!planned) {
    stats.applies_refused += 1;
    return planned.error();
  }
  if (planned.value().decision == Decision::Refuse) {
    stats.plans_refused += 1;
    stats.applies_refused += 1;
    const Error error(planned.value().primary_reason, "placement refused");
    Status recorded = record_refusal(request.request_id, fingerprint, error, at);
    if (!recorded) {
      return recorded.error();
    }
    return error;
  }
  stats.plans_accepted += 1;
  ApplyOptions effective = options;
  effective.allow_replacement = options.allow_replacement ||
                                request.request_replacement ||
                                planned.value().decision == Decision::Replace;
  if (!request.request_id.empty()) {
    effective.request_id = request.request_id;
  }
  auto result = authorize_locked(planned.value(), effective);
  if (!result) {
    stats.applies_refused += 1;
    const Error error(result.error().code, result.error().detail);
    Status recorded = record_refusal(request.request_id, fingerprint, error, at);
    if (!recorded) {
      return recorded.error();
    }
    return error;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Intent surface
// ---------------------------------------------------------------------------

Result<PlanResult> Fabric::plan(const PlacementRequest& request) const { return plan(request, nullptr); }

Result<PlanResult> Fabric::plan(const PlacementRequest& request, const CancelToken* cancel) const {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  return impl.plan_locked(request, cancel);
}

Result<AssignmentRecord> Fabric::apply(const PlacementRequest& request,
                                       const ApplyOptions& options) {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  if (!impl.recovery_accepted) {
    return Error(ReasonCode::RecoveryRequired, "recovery classification has not been accepted");
  }
  return impl.apply_locked(request, options);
}

Result<AssignmentRecord> Fabric::apply_plan(const PlanResult& planned, const ApplyOptions& options) {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  if (!impl.recovery_accepted) {
    return Error(ReasonCode::RecoveryRequired, "recovery classification has not been accepted");
  }
  if (planned.decision == Decision::Refuse) {
    return Error(planned.primary_reason, "refused plans cannot be applied");
  }
  const IdempotencyEntry* cached = impl.find_idempotency(options.request_id);
  if (cached != nullptr) {
    const Digest fingerprint = planned.plan.plan_digest;
    if (cached->request_fingerprint == fingerprint) {
      impl.stats.duplicate_deliveries_idempotent += 1;
      Result<AssignmentRecord> out = Error(ReasonCode::InternalInvariant, "unset");
      Status replay = replay_cached_assignment(*cached, out);
      if (!replay) {
        return replay.error();
      }
      return out;
    }
    impl.stats.duplicate_deliveries_fenced += 1;
    return Error(ReasonCode::DuplicateDelivery,
                 "request identifier was reused with a different plan");
  }
  ApplyOptions effective = options;
  effective.allow_replacement = options.allow_replacement || planned.decision == Decision::Replace;
  auto result = impl.authorize_locked(planned, effective);
  if (!result) {
    impl.stats.applies_refused += 1;
    if (!options.request_id.empty()) {
      const Error error(result.error().code, result.error().detail);
      Status recorded = impl.record_refusal(options.request_id, planned.plan.plan_digest, error,
                                            impl.now());
      if (!recorded) {
        return recorded.error();
      }
    }
    return result.error();
  }
  return result;
}

Result<AssignmentRecord> Fabric::revoke(const RevokeRequest& request) {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  if (!impl.recovery_accepted) {
    return Error(ReasonCode::RecoveryRequired, "recovery classification has not been accepted");
  }
  const Micros at = impl.now();
  const Digest fingerprint = sha256(std::string("revoke:") + request.assignment.value() +
                                    ":" + to_string(request.reason));
  if (const IdempotencyEntry* cached = impl.find_idempotency(request.request_id)) {
    if (cached->request_fingerprint == fingerprint) {
      impl.stats.duplicate_deliveries_idempotent += 1;
      Result<AssignmentRecord> out = Error(ReasonCode::InternalInvariant, "unset");
      Status replay = replay_cached_assignment(*cached, out);
      if (!replay) {
        return replay.error();
      }
      return out;
    }
    impl.stats.duplicate_deliveries_fenced += 1;
    return Error(ReasonCode::DuplicateDelivery,
                 "request identifier was reused with a different payload");
  }
  const auto it = impl.state.assignments.find(request.assignment);
  if (it == impl.state.assignments.end()) {
    impl.stats.revokes_refused += 1;
    return Error(ReasonCode::NotFound, "assignment does not exist");
  }
  if (it->second.state == AssignmentState::Revoked) {
    impl.stats.duplicate_deliveries_idempotent += 1;
    return it->second;
  }
  if (cancellation_requested(request.cancel)) {
    impl.stats.cancellations += 1;
    impl.stats.refusals_after_cancel += 1;
    return Error(ReasonCode::Cancelled, "revocation cancelled before commit");
  }
  if (holds_authority(it->second.state) && !request.authority.empty()) {
    const auto grant = impl.state.authority.find(request.authority);
    if (grant == impl.state.authority.end()) {
      impl.stats.revokes_refused += 1;
      return Error(ReasonCode::AuthorityMissing, "revocation authority grant does not exist");
    }
    const SemanticsMask semantics{};
    const AuthorityDecision decision =
        authority_admits(grant->second, AuthorityAction::Revoke, it->second.cls, it->second.kind,
                         it->second.host, it->second.scope_id, semantics,
                         impl.state.has_policy ? impl.state.policy.generation
                                               : PolicyGeneration{},
                         at);
    if (!decision.admitted) {
      impl.stats.revokes_refused += 1;
      return Error(decision.reason, "revocation is not authorized by the named grant");
    }
  }
  impl.inject(CrashBoundary::BeforeCommit);
  AssignmentRecord record = it->second;
  record.state = AssignmentState::Revoked;
  record.state_reason = request.reason;
  record.updated_at = at;
  record.history.push_back(
      TransitionRecord{it->second.state, AssignmentState::Revoked, request.reason, at, record.fence});
  impl.trim_history(record);
  Status status = impl.store_assignment(record, request.request_id, fingerprint,
                                        RecordType::AssignmentTransitioned);
  if (!status) {
    impl.stats.revokes_refused += 1;
    return status.error();
  }
  impl.stats.revokes_accepted += 1;
  return record;
}

Result<AssignmentRecord> Fabric::replace(const ReplaceRequest& request) {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  if (!impl.recovery_accepted) {
    return Error(ReasonCode::RecoveryRequired, "recovery classification has not been accepted");
  }
  const auto it = impl.state.assignments.find(request.current);
  if (it == impl.state.assignments.end()) {
    impl.stats.replaces_refused += 1;
    return Error(ReasonCode::NotFound, "assignment to replace does not exist");
  }
  PlacementRequest placement = request.placement;
  placement.request_replacement = true;
  if (placement.function.empty()) {
    placement.function = it->second.function;
    placement.cls = it->second.cls;
    placement.scope = it->second.scope;
    placement.exclusivity = it->second.exclusivity;
    placement.demand = it->second.demand;
  }
  ApplyOptions options;
  options.request_id = request.request_id;
  options.cancel = request.cancel;
  options.allow_replacement = true;
  if (placement.request_id.empty()) {
    placement.request_id = request.request_id;
  }
  auto result = impl.apply_locked(placement, options);
  if (!result) {
    impl.stats.replaces_refused += 1;
    return result.error();
  }
  return result;
}

Result<AssignmentRecord> Fabric::reauthorize(const ReauthorizeRequest& request) {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  if (!impl.recovery_accepted) {
    return Error(ReasonCode::RecoveryRequired, "recovery classification has not been accepted");
  }
  const Micros at = impl.now();
  const Digest fingerprint = sha256(std::string("reauthorize:") + request.assignment.value());
  if (const IdempotencyEntry* cached = impl.find_idempotency(request.request_id)) {
    if (cached->request_fingerprint == fingerprint) {
      impl.stats.duplicate_deliveries_idempotent += 1;
      Result<AssignmentRecord> out = Error(ReasonCode::InternalInvariant, "unset");
      Status replay = replay_cached_assignment(*cached, out);
      if (!replay) {
        return replay.error();
      }
      return out;
    }
    impl.stats.duplicate_deliveries_fenced += 1;
    return Error(ReasonCode::DuplicateDelivery,
                 "request identifier was reused with a different payload");
  }
  const auto it = impl.state.assignments.find(request.assignment);
  if (it == impl.state.assignments.end()) {
    impl.stats.reauthorizations_refused += 1;
    return Error(ReasonCode::NotFound, "assignment does not exist");
  }
  if (holds_authority(it->second.state)) {
    impl.stats.duplicate_deliveries_idempotent += 1;
    return it->second;
  }
  if (it->second.state != AssignmentState::Suspended &&
      it->second.state != AssignmentState::Degraded) {
    impl.stats.reauthorizations_refused += 1;
    return Error(ReasonCode::IllegalStateTransition,
                 "only a suspended or degraded assignment can be re-authorized");
  }
  if (request.authority.empty()) {
    impl.stats.reauthorizations_refused += 1;
    return Error(ReasonCode::AuthorityMissing, "re-authorization requires a named grant");
  }
  const auto grant = impl.state.authority.find(request.authority);
  if (grant == impl.state.authority.end()) {
    impl.stats.reauthorizations_refused += 1;
    return Error(ReasonCode::AuthorityMissing, "re-authorization grant does not exist");
  }
  const SemanticsMask semantics = impl.state.functions.find(it->second.function) !=
                                          impl.state.functions.end()
                                      ? impl.state.functions[it->second.function].required
                                      : SemanticsMask{};
  const AuthorityDecision decision =
      authority_admits(grant->second, AuthorityAction::Reauthorize, it->second.cls, it->second.kind,
                       it->second.host, it->second.scope_id, semantics,
                       impl.state.has_policy ? impl.state.policy.generation : PolicyGeneration{},
                       at);
  if (!decision.admitted) {
    impl.stats.reauthorizations_refused += 1;
    return Error(decision.reason, "re-authorization grant does not admit this assignment");
  }
  // Re-authorization re-binds generations, so the capability generation is
  // re-established from current evidence rather than compared with the old
  // binding.
  const ReasonCode validity = impl.assignment_target_validity(it->second, at, false);
  if (validity != ReasonCode::Ok && validity != ReasonCode::LivenessDegraded) {
    impl.stats.reauthorizations_refused += 1;
    return Error(validity, "assignment is not valid against current evidence");
  }
  impl.inject(CrashBoundary::BeforeCommit);
  AssignmentRecord record = it->second;
  auto lease = issue_lease(impl.state);
  if (!lease) {
    return lease.error();
  }
  record.lease = lease.value();
  auto attempt = issue_attempt(impl.state);
  if (!attempt) {
    return attempt.error();
  }
  record.attempt = attempt.value();
  auto fence = issue_fence(impl.state);
  if (!fence) {
    return fence.error();
  }
  record.fence = fence.value();
  record.authority = request.authority;
  if (impl.state.has_policy) {
    record.binding.policy = impl.state.policy.generation;
  }
  if (impl.state.has_topology) {
    record.binding.topology = impl.state.topology.generation;
  }
  const CapabilityRecord* capability =
      lookup_capability(impl.state, record.device, record.cls);
  if (capability != nullptr) {
    record.binding.capability = capability->generation;
    record.binding.schema = capability->schema;
  }
  record.state = validity == ReasonCode::LivenessDegraded ? AssignmentState::Degraded
                                                          : AssignmentState::Dispatched;
  record.state_reason = ReasonCode::Ok;
  record.updated_at = at;
  record.history.push_back(TransitionRecord{it->second.state, record.state, ReasonCode::Ok, at,
                                            record.fence});
  impl.trim_history(record);
  Status status = impl.store_assignment(record, request.request_id, fingerprint,
                                        RecordType::AssignmentTransitioned);
  if (!status) {
    impl.stats.reauthorizations_refused += 1;
    return status.error();
  }
  impl.stats.reauthorizations_accepted += 1;
  return record;
}

Result<RevalidationReport> Fabric::revalidate(const CancelToken* cancel) {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  RevalidationReport report;
  Status status = impl.revalidate_locked(cancel, report);
  if (!status) {
    return status.error();
  }
  return report;
}

Result<AssignmentRecord> Fabric::report_effect(const EffectReport& report) {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  if (!impl.recovery_accepted) {
    return Error(ReasonCode::RecoveryRequired, "recovery classification has not been accepted");
  }
  const Micros at = impl.now();
  const Digest fingerprint = [&]() {
    auto digest = wire::digest_with(
        report, impl.bounds.max_canonical_bytes,
        [&](const EffectReport& value, BinWriter& writer) {
          return wire::encode_effect_report(value, writer);
        });
    return digest ? digest.value() : Digest::zero();
  }();
  if (const IdempotencyEntry* cached = impl.find_idempotency(report.request_id)) {
    if (cached->request_fingerprint == fingerprint) {
      impl.stats.duplicate_deliveries_idempotent += 1;
      impl.stats.effects_duplicate += 1;
      Result<AssignmentRecord> out = Error(ReasonCode::InternalInvariant, "unset");
      Status replay = replay_cached_assignment(*cached, out);
      if (!replay) {
        return replay.error();
      }
      return out;
    }
    impl.stats.duplicate_deliveries_fenced += 1;
    return Error(ReasonCode::DuplicateDelivery,
                 "request identifier was reused with a different payload");
  }
  const auto it = impl.state.assignments.find(report.assignment);
  if (it == impl.state.assignments.end()) {
    return Error(ReasonCode::NotFound, "assignment does not exist");
  }
  const AssignmentRecord& current = it->second;
  const auto reject = [&](ReasonCode code, const char* detail) -> Result<AssignmentRecord> {
    impl.stats.effects_fenced += 1;
    return Error(code, detail);
  };
  if (!report.fence.is_set() || !(report.fence == current.fence)) {
    return reject(ReasonCode::FencedAttempt, "effect report carries a fenced token");
  }
  if (report.fence.epoch != impl.state.epoch.counter) {
    return reject(ReasonCode::EpochStale, "effect report belongs to a previous coordinator epoch");
  }
  if (!(report.attempt == current.attempt)) {
    return reject(ReasonCode::AttemptMismatch, "effect report targets a different attempt");
  }
  if (!(report.generation == current.generation)) {
    return reject(ReasonCode::GenerationMismatch,
                  "effect report targets a different assignment generation");
  }
  if (!(report.incarnation == current.incarnation)) {
    return reject(ReasonCode::IncarnationMismatch,
                  "effect report targets a different device incarnation");
  }
  if (!(report.capability_generation == current.binding.capability)) {
    return reject(ReasonCode::GenerationMismatch,
                  "effect report targets a different capability generation");
  }
  for (const EffectRecord& existing : current.effects) {
    if (existing.attempt == report.attempt && existing.fence == report.fence &&
        existing.outcome == report.outcome) {
      impl.stats.effects_duplicate += 1;
      return current;
    }
  }
  if (is_terminal(current.state)) {
    return reject(ReasonCode::IllegalStateTransition,
                  "a terminal assignment cannot accept an effect report");
  }
  AssignmentRecord record = current;
  EffectRecord effect;
  effect.attempt = report.attempt;
  effect.fence = report.fence;
  effect.generation = report.generation;
  effect.incarnation = report.incarnation;
  effect.capability_generation = report.capability_generation;
  effect.outcome = report.outcome;
  effect.reason = report.detail_reason;
  effect.observed_at = report.observed_at;
  record.effects.push_back(effect);
  impl.trim_history(record);
  record.updated_at = at;
  switch (report.outcome) {
    case EffectOutcome::Applied: {
      if (current.state == AssignmentState::AppliedVerified) {
        impl.stats.effects_duplicate += 1;
        return current;
      }
      if (current.state != AssignmentState::Dispatched &&
          current.state != AssignmentState::Acknowledged &&
          current.state != AssignmentState::Degraded) {
        return reject(ReasonCode::IllegalStateTransition,
                      "only a dispatched or acknowledged assignment can be verified as applied");
      }
      impl.inject(CrashBoundary::AfterAckBeforeEffect);
      record.state = AssignmentState::AppliedVerified;
      record.state_reason = ReasonCode::AppliedVerified;
      record.history.push_back(TransitionRecord{current.state, AssignmentState::AppliedVerified,
                                                ReasonCode::AppliedVerified, at, record.fence});
      impl.stats.effects_applied += 1;
      break;
    }
    case EffectOutcome::Rejected: {
      record.state = AssignmentState::Rejected;
      record.state_reason = ReasonCode::EffectRejected;
      record.history.push_back(TransitionRecord{current.state, AssignmentState::Rejected,
                                                ReasonCode::EffectRejected, at, record.fence});
      impl.stats.effects_rejected += 1;
      break;
    }
    case EffectOutcome::Failed: {
      record.state = AssignmentState::Failed;
      record.state_reason = ReasonCode::EffectFailed;
      record.history.push_back(TransitionRecord{current.state, AssignmentState::Failed,
                                                ReasonCode::EffectFailed, at, record.fence});
      impl.stats.effects_failed += 1;
      break;
    }
    case EffectOutcome::Unknown: {
      record.state_reason = ReasonCode::EffectUnknown;
      record.history.push_back(TransitionRecord{current.state, current.state, ReasonCode::EffectUnknown,
                                                at, record.fence});
      impl.stats.effects_unknown += 1;
      break;
    }
  }
  Status status = impl.store_effect(record, report, report.request_id, fingerprint);
  if (!status) {
    return status.error();
  }
  return record;
}

// ---------------------------------------------------------------------------
// Query surface
// ---------------------------------------------------------------------------

Result<AssignmentRecord> Fabric::get_assignment(const AssignmentId& id) const {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  const auto it = impl.state.assignments.find(id);
  if (it == impl.state.assignments.end()) {
    return Error(ReasonCode::NotFound, "assignment does not exist");
  }
  return it->second;
}

Result<std::vector<AssignmentRecord>> Fabric::list_assignments(const AssignmentFilter& filter,
                                                               std::size_t offset,
                                                               std::size_t limit,
                                                               bool& truncated) const {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  truncated = false;
  std::vector<AssignmentRecord> matches;
  for (const auto& entry : impl.state.assignments) {
    const AssignmentRecord& record = entry.second;
    if (filter.function.is_set() && !(record.function == filter.function)) {
      continue;
    }
    if (filter.scope.is_set() && !(record.scope_id == filter.scope)) {
      continue;
    }
    if (filter.device.is_set() && !(record.device == filter.device)) {
      continue;
    }
    if (filter.filter_by_state && record.state != filter.state) {
      continue;
    }
    if (!filter.include_terminal && !filter.filter_by_state && is_terminal(record.state)) {
      continue;
    }
    matches.push_back(record);
  }
  if (offset >= matches.size()) {
    return std::vector<AssignmentRecord>{};
  }
  const std::size_t available = matches.size() - offset;
  const std::size_t take = available < limit ? available : limit;
  std::vector<AssignmentRecord> page(matches.begin() + static_cast<std::ptrdiff_t>(offset),
                                     matches.begin() + static_cast<std::ptrdiff_t>(offset + take));
  if (take < available) {
    truncated = true;
    impl.stats.results_truncated += 1;
  }
  return page;
}

Result<ScopeView> Fabric::get_scope(const ScopeId& scope) const {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  const auto spec = impl.state.scope_specs.find(scope);
  if (spec == impl.state.scope_specs.end()) {
    return Error(ReasonCode::NotFound, "scope is not known to this coordinator");
  }
  ScopeView view;
  view.spec = spec->second;
  view.scope = scope;
  for (const auto& entry : impl.state.assignments) {
    if (entry.second.scope_id == scope && is_live(entry.second.state)) {
      view.live.push_back(entry.first);
    }
  }
  const auto scope_holder = impl.state.exclusive_by_scope.find(scope);
  if (scope_holder != impl.state.exclusive_by_scope.end()) {
    view.exclusive_holder = scope_holder->second;
    view.exclusive_holder_is_whole_scope = true;
  }
  ExclusivityKey lower;
  lower.scope = scope;
  lower.cls = static_cast<FunctionClass>(0);
  for (auto it = impl.state.exclusive_by_class.lower_bound(lower);
       it != impl.state.exclusive_by_class.end() && it->first.scope == scope; ++it) {
    view.exclusive_claims.push_back(it->second);
  }
  if (view.exclusive_holder_is_whole_scope) {
    view.exclusive_claims.push_back(view.exclusive_holder);
  }
  std::sort(view.exclusive_claims.begin(), view.exclusive_claims.end());
  view.exclusive_claims.erase(
      std::unique(view.exclusive_claims.begin(), view.exclusive_claims.end()),
      view.exclusive_claims.end());
  view.exclusive_held = !view.exclusive_claims.empty();
  if (!view.exclusive_holder_is_whole_scope && view.exclusive_claims.size() == 1) {
    view.exclusive_holder = view.exclusive_claims.front();
  }
  return view;
}

Result<Explanation> Fabric::explain_assignment(const AssignmentId& id) const {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  const auto it = impl.state.assignments.find(id);
  if (it == impl.state.assignments.end()) {
    return Error(ReasonCode::NotFound, "assignment does not exist");
  }
  const AssignmentRecord& record = it->second;
  Explanation explanation;
  explanation.assignment = record.id;
  explanation.function = record.function;
  explanation.cls = record.cls;
  explanation.scope = record.scope;
  explanation.scope_id = record.scope_id;
  explanation.exclusivity = record.exclusivity;
  explanation.mode = record.mode;
  explanation.binding = record.binding;
  explanation.authority = record.authority;
  explanation.lease = record.lease;
  explanation.fence = record.fence;
  explanation.attempt = record.attempt;
  explanation.selected_device = record.device;
  explanation.input_digest = record.request_fingerprint;
  explanation.decision_digest = assignment_digest(record);
  const Micros at = impl.now();
  const ReasonCode validity = impl.assignment_validity(record, at);
  if (is_terminal(record.state)) {
    explanation.decision = Decision::NoOp;
    explanation.primary_reason = record.state_reason;
    explanation.reasons.push_back(record.state_reason);
    return explanation;
  }
  if (validity == ReasonCode::Ok) {
    explanation.decision = holds_authority(record.state) ? Decision::Accept : Decision::Defer;
    explanation.primary_reason = record.state_reason;
    explanation.reasons.push_back(record.state_reason);
    return explanation;
  }
  explanation.decision = Decision::Suspend;
  explanation.primary_reason = validity;
  explanation.reasons.push_back(validity);
  return explanation;
}

Result<Explanation> Fabric::explain_request(const PlacementRequest& request) const {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  auto planned = impl.plan_locked(request, nullptr);
  if (!planned) {
    return planned.error();
  }
  return planned.value().explanation;
}

Digest Fabric::state_digest() const {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  return detail::compute_state_digest(impl.state, impl.bounds);
}

Status Fabric::export_canonical(ExportFormat format, std::string& out) const {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  switch (format) {
    case ExportFormat::CanonicalJson:
      return detail::export_state_json(impl.state, impl.bounds, out);
    case ExportFormat::CanonicalText:
      return detail::export_state_text(impl.state, impl.bounds, out);
    case ExportFormat::CanonicalBinary: {
      BinWriter writer(impl.bounds.max_canonical_bytes);
      Status status = detail::encode_state(impl.state, writer, impl.bounds);
      if (!status) {
        return status.error();
      }
      if (writer.size() > impl.bounds.max_export_bytes) {
        return Error(ReasonCode::OversizedInput, "canonical export exceeds the configured bound");
      }
      out.assign(reinterpret_cast<const char*>(writer.data().data()), writer.size());
      return ok_status();
    }
  }
  return Error(ReasonCode::UnsupportedValue, "unknown export format");
}

Status Fabric::compact() {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  if (!impl.running) {
    return Error(ReasonCode::ShuttingDown, "runtime is not running");
  }
  if (!impl.store) {
    return ok_status();
  }
  Status status = impl.compact_locked();
  if (!status) {
    return status.error();
  }
  return ok_status();
}

Stats Fabric::stats() const {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  Stats snapshot = impl.stats;
  snapshot.live_hosts = impl.state.has_topology ? impl.state.topology.hosts.size() : 0;
  snapshot.live_devices = impl.state.has_topology ? impl.state.topology.devices.size() : 0;
  snapshot.live_functions = impl.state.functions.size();
  snapshot.live_scopes = impl.state.scope_specs.size();
  snapshot.live_assignments = impl.state.assignments.size();
  snapshot.live_authority_grants = impl.state.authority.size();
  snapshot.live_observations = impl.state.observations.size();
  snapshot.live_idempotency_entries = impl.state.idempotency.size();
  snapshot.live_journal_records = impl.store ? impl.store->record_count() : 0;
  return snapshot;
}

InvariantReport Fabric::verify_invariants() const {
  Impl& impl = *impl_;
  std::unique_lock<std::mutex> lock(impl.mutex);
  InvariantReport report;
  Status status = detail::collect_invariants(impl.state, impl.bounds, report);
  if (!status) {
    report.clean = false;
    InvariantViolation violation;
    violation.invariant = "invariant_collection";
    violation.detail = to_string(status.error());
    report.violations.push_back(violation);
  }
  return report;
}

}  // namespace nof
