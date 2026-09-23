#include "nof/wire.hpp"

#include <string>
#include <vector>

#include "nof/checked.hpp"

namespace nof::wire {

namespace {

// Sticky-error writer: encoders stay readable and a bound failure surfaces once
// at the end instead of being dropped on the floor.
class W {
 public:
  explicit W(BinWriter& writer) : writer_(writer) {}

  void u8(std::uint8_t value) { note(writer_.u8(value)); }
  void u16(std::uint16_t value) { note(writer_.u16(value)); }
  void u32(std::uint32_t value) { note(writer_.u32(value)); }
  void u64(std::uint64_t value) { note(writer_.u64(value)); }
  void i64(std::int64_t value) { note(writer_.i64(value)); }
  void boolean(bool value) { note(writer_.boolean(value)); }
  void text(const std::string& value) { note(writer_.text(value)); }
  void token(const std::string& value) { note(writer_.token(value)); }
  void digest(const Digest& value) { note(writer_.digest(value)); }
  void semantics(const SemanticsMask& value) { note(writer_.u64(value.bits())); }

  template <class Tag>
  void token(const Token<Tag>& value) {
    note(writer_.token(value.view()));
  }

  void token(const BootId& value) { note(writer_.token(value.view())); }

  void count(std::size_t value) {
    std::uint32_t narrowed = 0;
    if (!checked_cast<std::uint32_t>(value, narrowed)) {
      note(Error(ReasonCode::OversizedInput, "collection length exceeds 32 bits"));
      return;
    }
    u32(narrowed);
  }

  Status status() const { return status_; }

 private:
  void note(Status status) {
    if (status_ && !status) {
      status_ = status.error();
    }
  }

  BinWriter& writer_;
  Status status_{};
};

// Sticky-error reader. Every decode helper reads its fields and the public
// entry point checks status() exactly once before returning a value, so a
// truncated or malformed document can never be mistaken for a value.
class R {
 public:
  explicit R(BinReader& reader) : reader_(reader) {}

  std::uint8_t u8() { return read<std::uint8_t>(&BinReader::u8); }
  std::uint16_t u16() { return read<std::uint16_t>(&BinReader::u16); }
  std::uint32_t u32() { return read<std::uint32_t>(&BinReader::u32); }
  std::uint64_t u64() { return read<std::uint64_t>(&BinReader::u64); }
  std::int64_t i64() { return read<std::int64_t>(&BinReader::i64); }
  bool boolean() { return read<bool>(&BinReader::boolean); }
  std::string text() { return read<std::string>(&BinReader::text); }
  std::string token() { return read<std::string>(&BinReader::token); }
  Digest digest() { return read<Digest>(&BinReader::digest); }

  SemanticsMask semantics() { return SemanticsMask::from_bits(u64()); }

  void fail(ReasonCode code, const char* detail) {
    if (status_) {
      status_ = Error(code, detail);
    }
  }

  bool count(std::size_t max_count, std::size_t& out) {
    const std::uint32_t raw = u32();
    if (!status_) {
      return false;
    }
    if (raw > max_count) {
      fail(ReasonCode::LimitExceeded, "collection length exceeds configured bound");
      return false;
    }
    out = static_cast<std::size_t>(raw);
    return true;
  }

  template <class T>
  bool enum8(std::uint8_t raw, T& out, const char* unknown_token) {
    const auto candidate = static_cast<T>(raw);
    if (std::string_view(to_string(candidate)) == unknown_token) {
      fail(ReasonCode::UnsupportedValue, "unrecognized enum value");
      return false;
    }
    out = candidate;
    return true;
  }

  ReasonCode reason_code() {
    const std::uint16_t raw = u16();
    if (!status_) {
      return ReasonCode::Ok;
    }
    if (std::string_view(to_string(static_cast<ReasonCode>(raw))) == "UNKNOWN_REASON") {
      fail(ReasonCode::UnsupportedValue, "unrecognized reason code");
      return ReasonCode::Ok;
    }
    return static_cast<ReasonCode>(raw);
  }

  Status status() const { return status_; }

 private:
  template <class T, class Method>
  T read(Method method) {
    if (!status_) {
      return T{};
    }
    auto value = (reader_.*method)();
    if (!value) {
      status_ = value.error();
      return T{};
    }
    return value.take();
  }

  BinReader& reader_;
  Status status_{};
};

void enc_provenance(const Provenance& value, W& w) {
  w.token(value.source);
  w.u64(value.sequence);
}

Provenance dec_provenance(R& r) {
  Provenance out;
  out.source = SourceId::from_validated(r.token());
  out.sequence = r.u64();
  return out;
}

void enc_freshness(const Freshness& value, W& w) {
  w.i64(value.observed_at.value());
  w.i64(value.valid_until.value());
}

Freshness dec_freshness(R& r) {
  Freshness out;
  out.observed_at = Micros::raw(r.i64());
  out.valid_until = Micros::raw(r.i64());
  return out;
}

void enc_incarnation(const IncarnationId& value, W& w) {
  w.u64(value.generation.value());
  w.token(value.boot);
}

IncarnationId dec_incarnation(R& r) {
  IncarnationId out;
  out.generation = IncarnationGeneration::from_validated(r.u64());
  out.boot = BootId::from_validated(r.token());
  return out;
}

void enc_fence(const FencingToken& value, W& w) {
  w.u64(value.epoch);
  w.u64(value.sequence);
}

FencingToken dec_fence(R& r) {
  FencingToken out;
  out.epoch = r.u64();
  out.sequence = r.u64();
  return out;
}

void enc_epoch(const CoordinatorEpoch& value, W& w) {
  w.u64(value.counter);
  w.token(value.boot);
}

CoordinatorEpoch dec_epoch(R& r) {
  CoordinatorEpoch out;
  out.counter = r.u64();
  out.boot = BootId::from_validated(r.token());
  return out;
}

void enc_binding(const GenerationBinding& value, W& w) {
  w.u64(value.topology.value());
  w.u64(value.capability.value());
  w.u64(value.policy.value());
  w.u64(value.assignment.value());
  w.u64(value.schema.value());
}

GenerationBinding dec_binding(R& r) {
  GenerationBinding out;
  out.topology = TopologyGeneration::from_validated(r.u64());
  out.capability = CapabilityGeneration::from_validated(r.u64());
  out.policy = PolicyGeneration::from_validated(r.u64());
  out.assignment = AssignmentGeneration::from_validated(r.u64());
  out.schema = SchemaGeneration::from_validated(r.u64());
  return out;
}

void enc_demand(const DemandVector& value, W& w) {
  w.u64(value.packets_per_second.value());
  w.u64(value.bytes_per_second.value());
  w.u64(value.flows.value());
  w.u64(value.queues.value());
  w.u64(value.memory.value());
}

DemandVector dec_demand(R& r) {
  DemandVector out;
  out.packets_per_second = PacketRate::raw(r.u64());
  out.bytes_per_second = ByteRate::raw(r.u64());
  out.flows = FlowCount::raw(r.u64());
  out.queues = QueueCount::raw(r.u64());
  out.memory = ByteSize::raw(r.u64());
  return out;
}

void enc_capacity(const CapacityVector& value, W& w) { enc_demand(DemandVector{value.packets_per_second, value.bytes_per_second, value.flows, value.queues, value.memory}, w); }

CapacityVector dec_capacity(R& r) {
  const DemandVector raw = dec_demand(r);
  CapacityVector out;
  out.packets_per_second = raw.packets_per_second;
  out.bytes_per_second = raw.bytes_per_second;
  out.flows = raw.flows;
  out.queues = raw.queues;
  out.memory = raw.memory;
  return out;
}

void enc_version(const SemanticVersion& value, W& w) {
  w.u16(value.major);
  w.u16(value.minor);
}

SemanticVersion dec_version(R& r) {
  SemanticVersion out;
  out.major = r.u16();
  out.minor = r.u16();
  return out;
}

void enc_version_range(const VersionRange& value, W& w) {
  enc_version(value.minimum, w);
  enc_version(value.maximum, w);
}

VersionRange dec_version_range(R& r) {
  VersionRange out;
  out.minimum = dec_version(r);
  out.maximum = dec_version(r);
  return out;
}

void enc_scope_spec(const ScopeSpec& value, W& w) {
  w.u8(static_cast<std::uint8_t>(value.kind));
  w.token(value.domain);
  w.token(value.device);
  w.text(value.selector);
}

ScopeSpec dec_scope_spec(R& r) {
  ScopeSpec out;
  out.kind = static_cast<ScopeKind>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.kind), out.kind, "unknown_scope_kind");
  out.domain = HostId::from_validated(r.token());
  out.device = DeviceId::from_validated(r.token());
  out.selector = r.text();
  return out;
}

void enc_labels(const std::vector<std::string>& labels, W& w) {
  w.count(labels.size());
  for (const std::string& label : labels) {
    w.token(label);
  }
}

std::vector<std::string> dec_labels(R& r, std::size_t max_count) {
  std::size_t count = 0;
  std::vector<std::string> out;
  if (!r.count(max_count, count)) {
    return out;
  }
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    std::string label = r.token();
    if (!r.status()) {
      return out;
    }
    out.push_back(std::move(label));
  }
  return out;
}

void enc_host_record(const HostRecord& value, W& w) {
  w.token(value.id);
  enc_labels(value.labels, w);
}

HostRecord dec_host_record(R& r, const Bounds& bounds) {
  HostRecord out;
  out.id = HostId::from_validated(r.token());
  out.labels = dec_labels(r, bounds.max_anti_affinity_entries * 4u);
  return out;
}

void enc_device_record(const DeviceRecord& value, W& w) {
  w.token(value.id);
  w.token(value.host);
  w.u8(static_cast<std::uint8_t>(value.kind));
  enc_incarnation(value.incarnation, w);
  enc_capacity(value.capacity, w);
  enc_labels(value.labels, w);
  w.boolean(value.decommissioned);
}

DeviceRecord dec_device_record(R& r, const Bounds& bounds) {
  DeviceRecord out;
  out.id = DeviceId::from_validated(r.token());
  out.host = HostId::from_validated(r.token());
  out.kind = static_cast<DeviceKind>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.kind), out.kind, "unknown_device_kind");
  out.incarnation = dec_incarnation(r);
  out.capacity = dec_capacity(r);
  out.labels = dec_labels(r, bounds.max_anti_affinity_entries * 4u);
  out.decommissioned = r.boolean();
  return out;
}

void enc_transition_record(const TransitionRecord& value, W& w) {
  w.u8(static_cast<std::uint8_t>(value.from));
  w.u8(static_cast<std::uint8_t>(value.to));
  w.u16(static_cast<std::uint16_t>(value.reason));
  w.i64(value.at.value());
  enc_fence(value.fence, w);
}

TransitionRecord dec_transition_record(R& r) {
  TransitionRecord out;
  out.from = static_cast<AssignmentState>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.from), out.from, "unknown_assignment_state");
  out.to = static_cast<AssignmentState>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.to), out.to, "unknown_assignment_state");
  out.reason = r.reason_code();
  out.at = Micros::raw(r.i64());
  out.fence = dec_fence(r);
  return out;
}

void enc_effect_record(const EffectRecord& value, W& w) {
  w.u64(value.attempt.value());
  enc_fence(value.fence, w);
  w.u64(value.generation.value());
  enc_incarnation(value.incarnation, w);
  w.u64(value.capability_generation.value());
  w.u8(static_cast<std::uint8_t>(value.outcome));
  w.u16(static_cast<std::uint16_t>(value.reason));
  w.i64(value.observed_at.value());
}

EffectRecord dec_effect_record(R& r) {
  EffectRecord out;
  out.attempt = AttemptId::from_validated(r.u64());
  out.fence = dec_fence(r);
  out.generation = AssignmentGeneration::from_validated(r.u64());
  out.incarnation = dec_incarnation(r);
  out.capability_generation = CapabilityGeneration::from_validated(r.u64());
  out.outcome = static_cast<EffectOutcome>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.outcome), out.outcome, "unknown_effect_outcome");
  out.reason = r.reason_code();
  out.observed_at = Micros::raw(r.i64());
  return out;
}

void enc_id_list(const std::vector<DeviceId>& items, W& w) {
  w.count(items.size());
  for (const DeviceId& item : items) {
    w.token(item);
  }
}

std::vector<DeviceId> dec_device_id_list(R& r, std::size_t max_count) {
  std::size_t count = 0;
  std::vector<DeviceId> out;
  if (!r.count(max_count, count)) {
    return out;
  }
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    out.push_back(DeviceId::from_validated(r.token()));
    if (!r.status()) {
      return out;
    }
  }
  return out;
}

std::vector<HostId> dec_host_id_list(R& r, std::size_t max_count) {
  std::size_t count = 0;
  std::vector<HostId> out;
  if (!r.count(max_count, count)) {
    return out;
  }
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    out.push_back(HostId::from_validated(r.token()));
    if (!r.status()) {
      return out;
    }
  }
  return out;
}

void enc_host_id_list(const std::vector<HostId>& items, W& w) {
  w.count(items.size());
  for (const HostId& item : items) {
    w.token(item);
  }
}

void enc_function_id_list(const std::vector<FunctionId>& items, W& w) {
  w.count(items.size());
  for (const FunctionId& item : items) {
    w.token(item);
  }
}

std::vector<FunctionId> dec_function_id_list(R& r, std::size_t max_count) {
  std::size_t count = 0;
  std::vector<FunctionId> out;
  if (!r.count(max_count, count)) {
    return out;
  }
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    out.push_back(FunctionId::from_validated(r.token()));
    if (!r.status()) {
      return out;
    }
  }
  return out;
}

void enc_assignment_id_list(const std::vector<AssignmentId>& items, W& w) {
  w.count(items.size());
  for (const AssignmentId& item : items) {
    w.token(item);
  }
}

std::vector<AssignmentId> dec_assignment_id_list(R& r, std::size_t max_count) {
  std::size_t count = 0;
  std::vector<AssignmentId> out;
  if (!r.count(max_count, count)) {
    return out;
  }
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    out.push_back(AssignmentId::from_validated(r.token()));
    if (!r.status()) {
      return out;
    }
  }
  return out;
}

void enc_device_kind_list(const std::vector<DeviceKind>& items, W& w) {
  w.count(items.size());
  for (const DeviceKind& item : items) {
    w.u8(static_cast<std::uint8_t>(item));
  }
}

std::vector<DeviceKind> dec_device_kind_list(R& r, std::size_t max_count) {
  std::size_t count = 0;
  std::vector<DeviceKind> out;
  if (!r.count(max_count, count)) {
    return out;
  }
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    DeviceKind kind = DeviceKind::Nic;
    const std::uint8_t raw = r.u8();
    r.enum8(raw, kind, "unknown_device_kind");
    if (!r.status()) {
      return out;
    }
    out.push_back(kind);
  }
  return out;
}

void enc_reason_list(const std::vector<ReasonCode>& items, W& w) {
  w.count(items.size());
  for (const ReasonCode& item : items) {
    w.u16(static_cast<std::uint16_t>(item));
  }
}

std::vector<ReasonCode> dec_reason_list(R& r, std::size_t max_count) {
  std::size_t count = 0;
  std::vector<ReasonCode> out;
  if (!r.count(max_count, count)) {
    return out;
  }
  out.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    const ReasonCode code = r.reason_code();
    if (!r.status()) {
      return out;
    }
    out.push_back(code);
  }
  return out;
}

void enc_function(const FunctionDescriptor& value, W& w) {
  w.token(value.id);
  w.u16(static_cast<std::uint16_t>(value.cls));
  w.semantics(value.required);
  enc_version(value.required_version, w);
  w.boolean(value.exclusive_by_default);
}

FunctionDescriptor dec_function(R& r) {
  FunctionDescriptor out;
  out.id = FunctionId::from_validated(r.token());
  const std::uint16_t cls = r.u16();
  r.enum8(static_cast<std::uint8_t>(cls & 0xFFu), out.cls, "unknown_function_class");
  out.required = r.semantics();
  out.required_version = dec_version(r);
  out.exclusive_by_default = r.boolean();
  return out;
}

void enc_capability_record(const CapabilityRecord& value, W& w) {
  w.token(value.device);
  enc_incarnation(value.incarnation, w);
  w.u16(static_cast<std::uint16_t>(value.cls));
  w.semantics(value.supported);
  w.semantics(value.unsupported);
  w.semantics(value.unknown);
  enc_version_range(value.version_range, w);
  enc_capacity(value.capacity, w);
  w.u64(value.schema.value());
  w.u64(value.generation.value());
  enc_provenance(value.provenance, w);
  enc_freshness(value.freshness, w);
  w.boolean(value.revoked);
}

CapabilityRecord dec_capability_record(R& r) {
  CapabilityRecord out;
  out.device = DeviceId::from_validated(r.token());
  out.incarnation = dec_incarnation(r);
  const std::uint16_t cls = r.u16();
  r.enum8(static_cast<std::uint8_t>(cls & 0xFFu), out.cls, "unknown_function_class");
  out.supported = r.semantics();
  out.unsupported = r.semantics();
  out.unknown = r.semantics();
  out.version_range = dec_version_range(r);
  out.capacity = dec_capacity(r);
  out.schema = SchemaGeneration::from_validated(r.u64());
  out.generation = CapabilityGeneration::from_validated(r.u64());
  out.provenance = dec_provenance(r);
  out.freshness = dec_freshness(r);
  out.revoked = r.boolean();
  return out;
}

void enc_policy_rule(const PolicyRule& value, W& w) {
  w.u16(static_cast<std::uint16_t>(value.cls));
  w.semantics(value.required);
  enc_device_kind_list(value.allowed_kinds, w);
  w.u8(static_cast<std::uint8_t>(value.exclusive_key));
  w.boolean(value.allow_host_fallback);
  w.boolean(value.require_authority);
  w.boolean(value.require_fresh_observation);
  w.boolean(value.require_capability);
  w.u32(value.priority);
  w.u64(value.max_reassignments_per_scope);
  w.u64(value.reassignment_window_micros);
  w.u64(value.max_assignments_per_device);
  enc_demand(value.reserve, w);
}

PolicyRule dec_policy_rule(R& r, const Bounds& bounds) {
  PolicyRule out;
  const std::uint16_t cls = r.u16();
  r.enum8(static_cast<std::uint8_t>(cls & 0xFFu), out.cls, "unknown_function_class");
  out.required = r.semantics();
  out.allowed_kinds = dec_device_kind_list(r, 8);
  out.exclusive_key = static_cast<ExclusiveKeyMode>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.exclusive_key), out.exclusive_key,
          "unknown_exclusive_key_mode");
  out.allow_host_fallback = r.boolean();
  out.require_authority = r.boolean();
  out.require_fresh_observation = r.boolean();
  out.require_capability = r.boolean();
  out.priority = r.u32();
  const std::uint64_t max_reassign = r.u64();
  std::size_t narrowed = 0;
  if (!checked_cast<std::size_t>(max_reassign, narrowed)) {
    r.fail(ReasonCode::OutOfRange, "policy reassignment budget does not fit in size_t");
  }
  out.max_reassignments_per_scope = narrowed;
  out.reassignment_window_micros = r.u64();
  const std::uint64_t max_per_device = r.u64();
  if (!checked_cast<std::size_t>(max_per_device, narrowed)) {
    r.fail(ReasonCode::OutOfRange, "policy device ceiling does not fit in size_t");
  }
  out.max_assignments_per_device = narrowed;
  out.reserve = dec_demand(r);
  (void)bounds;
  return out;
}

void enc_authority(const AuthorityGrant& value, W& w) {
  w.token(value.id);
  w.u64(value.policy_generation.value());
  w.count(value.classes.size());
  for (const FunctionClass cls : value.classes) {
    w.u16(static_cast<std::uint16_t>(cls));
  }
  enc_device_kind_list(value.kinds, w);
  w.count(value.actions.size());
  for (const AuthorityAction action : value.actions) {
    w.u8(static_cast<std::uint8_t>(action));
  }
  w.token(value.host_scope);
  w.token(value.scope);
  w.semantics(value.semantics_ceiling);
  w.i64(value.issued_at.value());
  w.i64(value.expires_at.value());
  enc_provenance(value.provenance, w);
  enc_freshness(value.freshness, w);
  w.boolean(value.revoked);
  w.u64(value.max_uses);
  w.u64(value.used);
}

AuthorityGrant dec_authority(R& r) {
  AuthorityGrant out;
  out.id = AuthorityId::from_validated(r.token());
  out.policy_generation = PolicyGeneration::from_validated(r.u64());
  std::size_t count = 0;
  if (r.count(64, count)) {
    out.classes.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      FunctionClass cls = FunctionClass::RouteLookup;
      const std::uint16_t raw = r.u16();
      r.enum8(static_cast<std::uint8_t>(raw & 0xFFu), cls, "unknown_function_class");
      if (!r.status()) {
        return out;
      }
      out.classes.push_back(cls);
    }
  }
  out.kinds = dec_device_kind_list(r, 8);
  if (r.count(8, count)) {
    out.actions.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      AuthorityAction action = AuthorityAction::Place;
      const std::uint8_t raw = r.u8();
      r.enum8(raw, action, "unknown_authority_action");
      if (!r.status()) {
        return out;
      }
      out.actions.push_back(action);
    }
  }
  out.host_scope = HostId::from_validated(r.token());
  out.scope = ScopeId::from_validated(r.token());
  out.semantics_ceiling = r.semantics();
  out.issued_at = Micros::raw(r.i64());
  out.expires_at = Micros::raw(r.i64());
  out.provenance = dec_provenance(r);
  out.freshness = dec_freshness(r);
  out.revoked = r.boolean();
  out.max_uses = r.u64();
  out.used = r.u64();
  return out;
}

void enc_observation(const DeviceObservation& value, W& w) {
  w.token(value.device);
  enc_incarnation(value.incarnation, w);
  w.u8(static_cast<std::uint8_t>(value.liveness));
  enc_capacity(value.available, w);
  w.boolean(value.available_known);
  enc_freshness(value.freshness, w);
  enc_provenance(value.provenance, w);
}

DeviceObservation dec_observation(R& r) {
  DeviceObservation out;
  out.device = DeviceId::from_validated(r.token());
  out.incarnation = dec_incarnation(r);
  out.liveness = static_cast<Liveness>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.liveness), out.liveness, "unknown_liveness");
  out.available = dec_capacity(r);
  out.available_known = r.boolean();
  out.freshness = dec_freshness(r);
  out.provenance = dec_provenance(r);
  return out;
}

void enc_assignment(const AssignmentRecord& value, W& w) {
  w.token(value.id);
  w.u64(value.generation.value());
  w.token(value.function);
  w.u16(static_cast<std::uint16_t>(value.cls));
  enc_scope_spec(value.scope, w);
  w.token(value.scope_id);
  w.u8(static_cast<std::uint8_t>(value.exclusivity));
  w.u8(static_cast<std::uint8_t>(value.exclusive_key));
  w.u8(static_cast<std::uint8_t>(value.mode));
  w.u8(static_cast<std::uint8_t>(value.state));
  w.token(value.device);
  w.token(value.host);
  w.u8(static_cast<std::uint8_t>(value.kind));
  enc_incarnation(value.incarnation, w);
  enc_demand(value.demand, w);
  enc_binding(value.binding, w);
  w.token(value.authority);
  w.u64(value.lease.value());
  enc_fence(value.fence, w);
  w.u64(value.attempt.value());
  w.digest(value.request_fingerprint);
  enc_provenance(value.provenance, w);
  enc_freshness(value.freshness, w);
  w.u16(static_cast<std::uint16_t>(value.state_reason));
  w.i64(value.created_at.value());
  w.i64(value.updated_at.value());
  w.count(value.history.size());
  for (const TransitionRecord& transition : value.history) {
    enc_transition_record(transition, w);
  }
  w.count(value.effects.size());
  for (const EffectRecord& effect : value.effects) {
    enc_effect_record(effect, w);
  }
}

AssignmentRecord dec_assignment(R& r, const Bounds& bounds) {
  AssignmentRecord out;
  out.id = AssignmentId::from_validated(r.token());
  out.generation = AssignmentGeneration::from_validated(r.u64());
  out.function = FunctionId::from_validated(r.token());
  const std::uint16_t cls = r.u16();
  r.enum8(static_cast<std::uint8_t>(cls & 0xFFu), out.cls, "unknown_function_class");
  out.scope = dec_scope_spec(r);
  out.scope_id = ScopeId::from_validated(r.token());
  out.exclusivity = static_cast<Exclusivity>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.exclusivity), out.exclusivity, "unknown_exclusivity");
  out.exclusive_key = static_cast<ExclusiveKeyMode>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.exclusive_key), out.exclusive_key,
          "unknown_exclusive_key_mode");
  out.mode = static_cast<ExecutionMode>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.mode), out.mode, "unknown_execution_mode");
  out.state = static_cast<AssignmentState>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.state), out.state, "unknown_assignment_state");
  out.device = DeviceId::from_validated(r.token());
  out.host = HostId::from_validated(r.token());
  out.kind = static_cast<DeviceKind>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.kind), out.kind, "unknown_device_kind");
  out.incarnation = dec_incarnation(r);
  out.demand = dec_demand(r);
  out.binding = dec_binding(r);
  out.authority = AuthorityId::from_validated(r.token());
  out.lease = LeaseId::from_validated(r.u64());
  out.fence = dec_fence(r);
  out.attempt = AttemptId::from_validated(r.u64());
  out.request_fingerprint = r.digest();
  out.provenance = dec_provenance(r);
  out.freshness = dec_freshness(r);
  out.state_reason = r.reason_code();
  out.created_at = Micros::raw(r.i64());
  out.updated_at = Micros::raw(r.i64());
  std::size_t count = 0;
  if (r.count(bounds.max_history_per_assignment, count)) {
    out.history.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      out.history.push_back(dec_transition_record(r));
      if (!r.status()) {
        return out;
      }
    }
  }
  if (r.count(bounds.max_effects_per_assignment, count)) {
    out.effects.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      out.effects.push_back(dec_effect_record(r));
      if (!r.status()) {
        return out;
      }
    }
  }
  return out;
}

void enc_placement_request(const PlacementRequest& value, W& w) {
  w.token(value.request_id);
  w.token(value.function);
  w.u16(static_cast<std::uint16_t>(value.cls));
  enc_scope_spec(value.scope, w);
  w.semantics(value.required);
  enc_version(value.required_version, w);
  w.u8(static_cast<std::uint8_t>(value.exclusivity));
  enc_demand(value.demand, w);
  enc_id_list(value.preferred_devices, w);
  enc_host_id_list(value.preferred_hosts, w);
  enc_id_list(value.anti_affinity_devices, w);
  enc_host_id_list(value.anti_affinity_hosts, w);
  enc_labels(value.required_labels, w);
  enc_function_id_list(value.dependencies, w);
  w.u64(value.min_topology.value());
  w.u64(value.min_capability.value());
  w.u64(value.min_policy.value());
  w.boolean(value.allow_host_fallback);
  w.u64(value.max_reassignments);
  w.boolean(value.request_replacement);
}

PlacementRequest dec_placement_request(R& r, const Bounds& bounds) {
  PlacementRequest out;
  out.request_id = RequestId::from_validated(r.token());
  out.function = FunctionId::from_validated(r.token());
  const std::uint16_t cls = r.u16();
  r.enum8(static_cast<std::uint8_t>(cls & 0xFFu), out.cls, "unknown_function_class");
  out.scope = dec_scope_spec(r);
  out.required = r.semantics();
  out.required_version = dec_version(r);
  out.exclusivity = static_cast<Exclusivity>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.exclusivity), out.exclusivity, "unknown_exclusivity");
  out.demand = dec_demand(r);
  out.preferred_devices = dec_device_id_list(r, bounds.max_affinity_entries);
  out.preferred_hosts = dec_host_id_list(r, bounds.max_affinity_entries);
  out.anti_affinity_devices = dec_device_id_list(r, bounds.max_anti_affinity_entries);
  out.anti_affinity_hosts = dec_host_id_list(r, bounds.max_anti_affinity_entries);
  out.required_labels = dec_labels(r, bounds.max_anti_affinity_entries);
  out.dependencies = dec_function_id_list(r, bounds.max_dependencies_per_request);
  out.min_topology = TopologyGeneration::from_validated(r.u64());
  out.min_capability = CapabilityGeneration::from_validated(r.u64());
  out.min_policy = PolicyGeneration::from_validated(r.u64());
  out.allow_host_fallback = r.boolean();
  const std::uint64_t max_reassignments = r.u64();
  std::size_t narrowed = 0;
  if (!checked_cast<std::size_t>(max_reassignments, narrowed)) {
    r.fail(ReasonCode::OutOfRange, "reassignment budget does not fit in size_t");
  }
  out.max_reassignments = narrowed;
  out.request_replacement = r.boolean();
  return out;
}

void enc_candidate(const CandidateEvaluation& value, W& w) {
  w.token(value.device);
  w.token(value.host);
  w.u8(static_cast<std::uint8_t>(value.kind));
  enc_incarnation(value.incarnation, w);
  w.u64(value.capability_generation.value());
  w.boolean(value.eligible);
  w.u8(static_cast<std::uint8_t>(value.verdict));
  w.u16(static_cast<std::uint16_t>(value.reason));
  enc_reason_list(value.contributing, w);
  w.u8(static_cast<std::uint8_t>(value.mode));
  w.u64(value.rank);
  w.u32(value.offload_rank);
  w.u32(value.kind_rank);
  w.u32(value.locality_rank);
  w.u64(value.utilization_ppm);
  w.digest(value.evaluation_digest);
}

CandidateEvaluation dec_candidate(R& r, const Bounds& bounds) {
  CandidateEvaluation out;
  out.device = DeviceId::from_validated(r.token());
  out.host = HostId::from_validated(r.token());
  out.kind = static_cast<DeviceKind>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.kind), out.kind, "unknown_device_kind");
  out.incarnation = dec_incarnation(r);
  out.capability_generation = CapabilityGeneration::from_validated(r.u64());
  out.eligible = r.boolean();
  out.verdict = static_cast<MatchVerdict>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.verdict), out.verdict, "unknown_match_verdict");
  out.reason = r.reason_code();
  out.contributing = dec_reason_list(r, bounds.max_reasons_per_explanation);
  out.mode = static_cast<ExecutionMode>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.mode), out.mode, "unknown_execution_mode");
  out.rank = r.u64();
  out.offload_rank = r.u32();
  out.kind_rank = r.u32();
  out.locality_rank = r.u32();
  out.utilization_ppm = r.u64();
  out.evaluation_digest = r.digest();
  return out;
}

void enc_plan(const AssignmentPlan& value, W& w) {
  w.token(value.request_id);
  w.token(value.function);
  w.u16(static_cast<std::uint16_t>(value.cls));
  enc_scope_spec(value.scope, w);
  w.token(value.scope_id);
  w.u8(static_cast<std::uint8_t>(value.exclusivity));
  w.u8(static_cast<std::uint8_t>(value.exclusive_key));
  w.u8(static_cast<std::uint8_t>(value.mode));
  w.token(value.device);
  w.token(value.host);
  w.u8(static_cast<std::uint8_t>(value.kind));
  enc_incarnation(value.incarnation, w);
  enc_demand(value.demand, w);
  enc_binding(value.binding, w);
  w.token(value.authority);
  w.semantics(value.effective_requirement);
  w.digest(value.plan_digest);
}

AssignmentPlan dec_plan(R& r) {
  AssignmentPlan out;
  out.request_id = RequestId::from_validated(r.token());
  out.function = FunctionId::from_validated(r.token());
  const std::uint16_t cls = r.u16();
  r.enum8(static_cast<std::uint8_t>(cls & 0xFFu), out.cls, "unknown_function_class");
  out.scope = dec_scope_spec(r);
  out.scope_id = ScopeId::from_validated(r.token());
  out.exclusivity = static_cast<Exclusivity>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.exclusivity), out.exclusivity, "unknown_exclusivity");
  out.exclusive_key = static_cast<ExclusiveKeyMode>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.exclusive_key), out.exclusive_key,
          "unknown_exclusive_key_mode");
  out.mode = static_cast<ExecutionMode>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.mode), out.mode, "unknown_execution_mode");
  out.device = DeviceId::from_validated(r.token());
  out.host = HostId::from_validated(r.token());
  out.kind = static_cast<DeviceKind>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.kind), out.kind, "unknown_device_kind");
  out.incarnation = dec_incarnation(r);
  out.demand = dec_demand(r);
  out.binding = dec_binding(r);
  out.authority = AuthorityId::from_validated(r.token());
  out.effective_requirement = r.semantics();
  out.plan_digest = r.digest();
  return out;
}

void enc_explanation(const Explanation& value, W& w) {
  w.u8(static_cast<std::uint8_t>(value.decision));
  w.u16(static_cast<std::uint16_t>(value.primary_reason));
  enc_reason_list(value.reasons, w);
  w.token(value.request_id);
  w.token(value.function);
  w.u16(static_cast<std::uint16_t>(value.cls));
  enc_scope_spec(value.scope, w);
  w.token(value.scope_id);
  w.u8(static_cast<std::uint8_t>(value.exclusivity));
  w.u8(static_cast<std::uint8_t>(value.mode));
  enc_binding(value.binding, w);
  w.token(value.authority);
  w.u64(value.lease.value());
  enc_fence(value.fence, w);
  w.u64(value.attempt.value());
  w.token(value.assignment);
  w.token(value.replaced);
  w.token(value.selected_device);
  w.count(value.candidates.size());
  for (const CandidateEvaluation& candidate : value.candidates) {
    enc_candidate(candidate, w);
  }
  w.u64(value.candidates_total);
  w.boolean(value.candidates_truncated);
  w.digest(value.input_digest);
  w.digest(value.decision_digest);
}

Explanation dec_explanation(R& r, const Bounds& bounds) {
  Explanation out;
  out.decision = static_cast<Decision>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.decision), out.decision, "unknown_decision");
  out.primary_reason = r.reason_code();
  out.reasons = dec_reason_list(r, bounds.max_reasons_per_explanation);
  out.request_id = RequestId::from_validated(r.token());
  out.function = FunctionId::from_validated(r.token());
  const std::uint16_t cls = r.u16();
  r.enum8(static_cast<std::uint8_t>(cls & 0xFFu), out.cls, "unknown_function_class");
  out.scope = dec_scope_spec(r);
  out.scope_id = ScopeId::from_validated(r.token());
  out.exclusivity = static_cast<Exclusivity>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.exclusivity), out.exclusivity, "unknown_exclusivity");
  out.mode = static_cast<ExecutionMode>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.mode), out.mode, "unknown_execution_mode");
  out.binding = dec_binding(r);
  out.authority = AuthorityId::from_validated(r.token());
  out.lease = LeaseId::from_validated(r.u64());
  out.fence = dec_fence(r);
  out.attempt = AttemptId::from_validated(r.u64());
  out.assignment = AssignmentId::from_validated(r.token());
  out.replaced = AssignmentId::from_validated(r.token());
  out.selected_device = DeviceId::from_validated(r.token());
  std::size_t count = 0;
  if (r.count(bounds.max_candidates_per_plan, count)) {
    out.candidates.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      out.candidates.push_back(dec_candidate(r, bounds));
      if (!r.status()) {
        return out;
      }
    }
  }
  const std::uint64_t total = r.u64();
  std::size_t narrowed = 0;
  if (!checked_cast<std::size_t>(total, narrowed)) {
    r.fail(ReasonCode::OutOfRange, "candidate count does not fit in size_t");
  }
  out.candidates_total = narrowed;
  out.candidates_truncated = r.boolean();
  out.input_digest = r.digest();
  out.decision_digest = r.digest();
  return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

Status encode_provenance(const Provenance& value, BinWriter& writer) {
  W w(writer);
  enc_provenance(value, w);
  return w.status();
}

Result<Provenance> decode_provenance(BinReader& reader) {
  R r(reader);
  const Provenance value = dec_provenance(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_freshness(const Freshness& value, BinWriter& writer) {
  W w(writer);
  enc_freshness(value, w);
  return w.status();
}

Result<Freshness> decode_freshness(BinReader& reader) {
  R r(reader);
  const Freshness value = dec_freshness(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_incarnation(const IncarnationId& value, BinWriter& writer) {
  W w(writer);
  enc_incarnation(value, w);
  return w.status();
}

Result<IncarnationId> decode_incarnation(BinReader& reader) {
  R r(reader);
  const IncarnationId value = dec_incarnation(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_fence(const FencingToken& value, BinWriter& writer) {
  W w(writer);
  enc_fence(value, w);
  return w.status();
}

Result<FencingToken> decode_fence(BinReader& reader) {
  R r(reader);
  const FencingToken value = dec_fence(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_epoch(const CoordinatorEpoch& value, BinWriter& writer) {
  W w(writer);
  enc_epoch(value, w);
  return w.status();
}

Result<CoordinatorEpoch> decode_epoch(BinReader& reader) {
  R r(reader);
  const CoordinatorEpoch value = dec_epoch(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_binding(const GenerationBinding& value, BinWriter& writer) {
  W w(writer);
  enc_binding(value, w);
  return w.status();
}

Result<GenerationBinding> decode_binding(BinReader& reader) {
  R r(reader);
  const GenerationBinding value = dec_binding(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_demand(const DemandVector& value, BinWriter& writer) {
  W w(writer);
  enc_demand(value, w);
  return w.status();
}

Result<DemandVector> decode_demand(BinReader& reader) {
  R r(reader);
  const DemandVector value = dec_demand(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_capacity(const CapacityVector& value, BinWriter& writer) {
  W w(writer);
  enc_capacity(value, w);
  return w.status();
}

Result<CapacityVector> decode_capacity(BinReader& reader) {
  R r(reader);
  const CapacityVector value = dec_capacity(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_semantics(const SemanticsMask& value, BinWriter& writer) {
  W w(writer);
  w.semantics(value);
  return w.status();
}

Result<SemanticsMask> decode_semantics(BinReader& reader) {
  R r(reader);
  const SemanticsMask value = r.semantics();
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  if ((value.bits() >> kSemanticCount) != 0) {
    return Error(ReasonCode::SemanticsMismatch, "semantics mask carries unknown bits");
  }
  return value;
}

Status encode_version(const SemanticVersion& value, BinWriter& writer) {
  W w(writer);
  enc_version(value, w);
  return w.status();
}

Result<SemanticVersion> decode_version(BinReader& reader) {
  R r(reader);
  const SemanticVersion value = dec_version(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_version_range(const VersionRange& value, BinWriter& writer) {
  W w(writer);
  enc_version_range(value, w);
  return w.status();
}

Result<VersionRange> decode_version_range(BinReader& reader) {
  R r(reader);
  const VersionRange value = dec_version_range(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_scope_spec(const ScopeSpec& value, BinWriter& writer) {
  W w(writer);
  enc_scope_spec(value, w);
  return w.status();
}

Result<ScopeSpec> decode_scope_spec(BinReader& reader) {
  R r(reader);
  const ScopeSpec value = dec_scope_spec(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_host(const HostRecord& value, BinWriter& writer, const Bounds& bounds) {
  W w(writer);
  enc_host_record(value, w);
  (void)bounds;
  return w.status();
}

Result<HostRecord> decode_host(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  const HostRecord value = dec_host_record(r, bounds);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_device(const DeviceRecord& value, BinWriter& writer, const Bounds& bounds) {
  W w(writer);
  enc_device_record(value, w);
  (void)bounds;
  return w.status();
}

Result<DeviceRecord> decode_device(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  const DeviceRecord value = dec_device_record(r, bounds);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_link(const LinkRecord& value, BinWriter& writer) {
  W w(writer);
  w.token(value.a);
  w.token(value.b);
  w.u8(static_cast<std::uint8_t>(value.kind));
  return w.status();
}

Result<LinkRecord> decode_link(BinReader& reader) {
  R r(reader);
  LinkRecord out;
  out.a = DeviceId::from_validated(r.token());
  out.b = DeviceId::from_validated(r.token());
  out.kind = static_cast<LinkKind>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.kind), out.kind, "unknown_link_kind");
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return out;
}

Status encode_topology(const TopologySnapshot& value, BinWriter& writer, const Bounds& bounds) {
  W w(writer);
  w.u64(value.generation.value());
  enc_provenance(value.provenance, w);
  enc_freshness(value.freshness, w);
  w.count(value.hosts.size());
  for (const HostRecord& host : value.hosts) {
    enc_host_record(host, w);
  }
  w.count(value.devices.size());
  for (const DeviceRecord& device : value.devices) {
    enc_device_record(device, w);
  }
  w.count(value.links.size());
  for (const LinkRecord& link : value.links) {
    w.token(link.a);
    w.token(link.b);
    w.u8(static_cast<std::uint8_t>(link.kind));
  }
  (void)bounds;
  return w.status();
}

Result<TopologySnapshot> decode_topology(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  TopologySnapshot out;
  out.generation = TopologyGeneration::from_validated(r.u64());
  out.provenance = dec_provenance(r);
  out.freshness = dec_freshness(r);
  std::size_t count = 0;
  if (r.count(bounds.max_hosts, count)) {
    out.hosts.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      out.hosts.push_back(dec_host_record(r, bounds));
      if (!r.status()) {
        return r.status().error();
      }
    }
  }
  if (r.count(bounds.max_devices, count)) {
    out.devices.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      out.devices.push_back(dec_device_record(r, bounds));
      if (!r.status()) {
        return r.status().error();
      }
    }
  }
  if (r.count(bounds.max_devices * 8u, count)) {
    out.links.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      LinkRecord link;
      link.a = DeviceId::from_validated(r.token());
      link.b = DeviceId::from_validated(r.token());
      link.kind = static_cast<LinkKind>(r.u8());
      r.enum8(static_cast<std::uint8_t>(link.kind), link.kind, "unknown_link_kind");
      if (!r.status()) {
        return r.status().error();
      }
      out.links.push_back(link);
    }
  }
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return out;
}

Status encode_function(const FunctionDescriptor& value, BinWriter& writer) {
  W w(writer);
  enc_function(value, w);
  return w.status();
}

Result<FunctionDescriptor> decode_function(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  const FunctionDescriptor value = dec_function(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  if (value.required.count() > bounds.max_semantics_per_requirement) {
    return Error(ReasonCode::LimitExceeded, "function requirement exceeds the semantics bound");
  }
  return value;
}

Status encode_capability_record(const CapabilityRecord& value, BinWriter& writer,
                                const Bounds& bounds) {
  W w(writer);
  enc_capability_record(value, w);
  (void)bounds;
  return w.status();
}

Result<CapabilityRecord> decode_capability_record(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  const CapabilityRecord value = dec_capability_record(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  (void)bounds;
  return value;
}

Status encode_capability_report(const CapabilityReport& value, BinWriter& writer,
                                const Bounds& bounds) {
  W w(writer);
  enc_provenance(value.provenance, w);
  enc_freshness(value.freshness, w);
  w.count(value.records.size());
  for (const CapabilityRecord& record : value.records) {
    enc_capability_record(record, w);
  }
  (void)bounds;
  return w.status();
}

Result<CapabilityReport> decode_capability_report(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  CapabilityReport out;
  out.provenance = dec_provenance(r);
  out.freshness = dec_freshness(r);
  std::size_t count = 0;
  if (r.count(bounds.max_capability_records, count)) {
    out.records.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      out.records.push_back(dec_capability_record(r));
      if (!r.status()) {
        return r.status().error();
      }
    }
  }
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return out;
}

Status encode_policy_rule(const PolicyRule& value, BinWriter& writer, const Bounds& bounds) {
  W w(writer);
  enc_policy_rule(value, w);
  (void)bounds;
  return w.status();
}

Result<PolicyRule> decode_policy_rule(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  const PolicyRule value = dec_policy_rule(r, bounds);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_policy(const PolicySnapshot& value, BinWriter& writer, const Bounds& bounds) {
  W w(writer);
  w.u64(value.generation.value());
  enc_provenance(value.provenance, w);
  enc_freshness(value.freshness, w);
  w.boolean(value.default_deny);
  w.count(value.rules.size());
  for (const PolicyRule& rule : value.rules) {
    enc_policy_rule(rule, w);
  }
  (void)bounds;
  return w.status();
}

Result<PolicySnapshot> decode_policy(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  PolicySnapshot out;
  out.generation = PolicyGeneration::from_validated(r.u64());
  out.provenance = dec_provenance(r);
  out.freshness = dec_freshness(r);
  out.default_deny = r.boolean();
  std::size_t count = 0;
  if (r.count(bounds.max_functions, count)) {
    out.rules.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      out.rules.push_back(dec_policy_rule(r, bounds));
      if (!r.status()) {
        return r.status().error();
      }
    }
  }
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return out;
}

Status encode_authority(const AuthorityGrant& value, BinWriter& writer, const Bounds& bounds) {
  W w(writer);
  enc_authority(value, w);
  (void)bounds;
  return w.status();
}

Result<AuthorityGrant> decode_authority(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  const AuthorityGrant value = dec_authority(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  (void)bounds;
  return value;
}

Status encode_observation(const DeviceObservation& value, BinWriter& writer) {
  W w(writer);
  enc_observation(value, w);
  return w.status();
}

Result<DeviceObservation> decode_observation(BinReader& reader) {
  R r(reader);
  const DeviceObservation value = dec_observation(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_observation_report(const ObservationReport& value, BinWriter& writer,
                                 const Bounds& bounds) {
  W w(writer);
  w.u64(value.topology_generation.value());
  enc_provenance(value.provenance, w);
  enc_freshness(value.freshness, w);
  w.count(value.devices.size());
  for (const DeviceObservation& observation : value.devices) {
    enc_observation(observation, w);
  }
  (void)bounds;
  return w.status();
}

Result<ObservationReport> decode_observation_report(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  ObservationReport out;
  out.topology_generation = TopologyGeneration::from_validated(r.u64());
  out.provenance = dec_provenance(r);
  out.freshness = dec_freshness(r);
  std::size_t count = 0;
  if (r.count(bounds.max_observations, count)) {
    out.devices.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      out.devices.push_back(dec_observation(r));
      if (!r.status()) {
        return r.status().error();
      }
    }
  }
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return out;
}

Status encode_transition(const TransitionRecord& value, BinWriter& writer) {
  W w(writer);
  enc_transition_record(value, w);
  return w.status();
}

Result<TransitionRecord> decode_transition(BinReader& reader) {
  R r(reader);
  const TransitionRecord value = dec_transition_record(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_effect(const EffectRecord& value, BinWriter& writer) {
  W w(writer);
  enc_effect_record(value, w);
  return w.status();
}

Result<EffectRecord> decode_effect(BinReader& reader) {
  R r(reader);
  const EffectRecord value = dec_effect_record(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_assignment(const AssignmentRecord& value, BinWriter& writer, const Bounds& bounds) {
  W w(writer);
  enc_assignment(value, w);
  (void)bounds;
  return w.status();
}

Result<AssignmentRecord> decode_assignment(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  const AssignmentRecord value = dec_assignment(r, bounds);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_effect_report(const EffectReport& value, BinWriter& writer) {
  W w(writer);
  w.token(value.request_id);
  w.token(value.assignment);
  w.u64(value.attempt.value());
  w.u64(value.generation.value());
  enc_fence(value.fence, w);
  enc_incarnation(value.incarnation, w);
  w.u64(value.capability_generation.value());
  w.u8(static_cast<std::uint8_t>(value.outcome));
  w.u16(static_cast<std::uint16_t>(value.detail_reason));
  w.i64(value.observed_at.value());
  enc_provenance(value.provenance, w);
  return w.status();
}

Result<EffectReport> decode_effect_report(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  EffectReport out;
  out.request_id = RequestId::from_validated(r.token());
  out.assignment = AssignmentId::from_validated(r.token());
  out.attempt = AttemptId::from_validated(r.u64());
  out.generation = AssignmentGeneration::from_validated(r.u64());
  out.fence = dec_fence(r);
  out.incarnation = dec_incarnation(r);
  out.capability_generation = CapabilityGeneration::from_validated(r.u64());
  out.outcome = static_cast<EffectOutcome>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.outcome), out.outcome, "unknown_effect_outcome");
  out.detail_reason = r.reason_code();
  out.observed_at = Micros::raw(r.i64());
  out.provenance = dec_provenance(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  (void)bounds;
  return out;
}

Status encode_placement_request(const PlacementRequest& value, BinWriter& writer,
                                const Bounds& bounds) {
  W w(writer);
  enc_placement_request(value, w);
  (void)bounds;
  return w.status();
}

Result<PlacementRequest> decode_placement_request(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  const PlacementRequest value = dec_placement_request(r, bounds);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_plan(const AssignmentPlan& value, BinWriter& writer, const Bounds& bounds) {
  W w(writer);
  enc_plan(value, w);
  (void)bounds;
  return w.status();
}

Result<AssignmentPlan> decode_plan(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  const AssignmentPlan value = dec_plan(r);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  (void)bounds;
  return value;
}

Status encode_candidate(const CandidateEvaluation& value, BinWriter& writer) {
  W w(writer);
  enc_candidate(value, w);
  return w.status();
}

Result<CandidateEvaluation> decode_candidate(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  const CandidateEvaluation value = dec_candidate(r, bounds);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_explanation(const Explanation& value, BinWriter& writer, const Bounds& bounds) {
  W w(writer);
  enc_explanation(value, w);
  (void)bounds;
  return w.status();
}

Result<Explanation> decode_explanation(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  const Explanation value = dec_explanation(r, bounds);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return value;
}

Status encode_plan_result(const PlanResult& value, BinWriter& writer, const Bounds& bounds) {
  W w(writer);
  w.u8(static_cast<std::uint8_t>(value.decision));
  w.u16(static_cast<std::uint16_t>(value.primary_reason));
  w.count(value.candidates.size());
  for (const CandidateEvaluation& candidate : value.candidates) {
    enc_candidate(candidate, w);
  }
  w.u64(value.candidates_total);
  w.boolean(value.candidates_truncated);
  enc_plan(value.plan, w);
  enc_explanation(value.explanation, w);
  (void)bounds;
  return w.status();
}

Result<PlanResult> decode_plan_result(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  PlanResult out;
  out.decision = static_cast<Decision>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.decision), out.decision, "unknown_decision");
  out.primary_reason = r.reason_code();
  std::size_t count = 0;
  if (r.count(bounds.max_candidates_per_plan, count)) {
    out.candidates.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      out.candidates.push_back(dec_candidate(r, bounds));
      if (!r.status()) {
        return r.status().error();
      }
    }
  }
  const std::uint64_t total = r.u64();
  std::size_t narrowed = 0;
  if (!checked_cast<std::size_t>(total, narrowed)) {
    r.fail(ReasonCode::OutOfRange, "candidate count does not fit in size_t");
  }
  out.candidates_total = narrowed;
  out.candidates_truncated = r.boolean();
  out.plan = dec_plan(r);
  out.explanation = dec_explanation(r, bounds);
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return out;
}

Status encode_filter(const AssignmentFilter& value, BinWriter& writer) {
  W w(writer);
  w.token(value.function);
  w.token(value.scope);
  w.token(value.device);
  w.u8(static_cast<std::uint8_t>(value.state));
  w.boolean(value.filter_by_state);
  w.boolean(value.include_terminal);
  return w.status();
}

Result<AssignmentFilter> decode_filter(BinReader& reader) {
  R r(reader);
  AssignmentFilter out;
  out.function = FunctionId::from_validated(r.token());
  out.scope = ScopeId::from_validated(r.token());
  out.device = DeviceId::from_validated(r.token());
  out.state = static_cast<AssignmentState>(r.u8());
  r.enum8(static_cast<std::uint8_t>(out.state), out.state, "unknown_assignment_state");
  out.filter_by_state = r.boolean();
  out.include_terminal = r.boolean();
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return out;
}

Status encode_scope_view(const ScopeView& value, BinWriter& writer, const Bounds& bounds) {
  W w(writer);
  enc_scope_spec(value.spec, w);
  w.token(value.scope);
  enc_assignment_id_list(value.live, w);
  enc_assignment_id_list(value.exclusive_claims, w);
  w.token(value.exclusive_holder);
  w.boolean(value.exclusive_holder_is_whole_scope);
  w.boolean(value.exclusive_held);
  (void)bounds;
  return w.status();
}

Result<ScopeView> decode_scope_view(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  ScopeView out;
  out.spec = dec_scope_spec(r);
  out.scope = ScopeId::from_validated(r.token());
  out.live = dec_assignment_id_list(r, bounds.max_assignments);
  out.exclusive_claims = dec_assignment_id_list(r, bounds.max_assignments);
  out.exclusive_holder = AssignmentId::from_validated(r.token());
  out.exclusive_holder_is_whole_scope = r.boolean();
  out.exclusive_held = r.boolean();
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return out;
}

Status encode_revalidation(const RevalidationReport& value, BinWriter& writer,
                           const Bounds& bounds) {
  W w(writer);
  w.u64(value.checked);
  w.u64(value.suspended);
  w.u64(value.degraded);
  w.u64(value.failed);
  w.u64(value.unchanged);
  enc_assignment_id_list(value.affected, w);
  w.u16(static_cast<std::uint16_t>(value.dominant_reason));
  w.boolean(value.truncated);
  (void)bounds;
  return w.status();
}

Result<RevalidationReport> decode_revalidation(BinReader& reader, const Bounds& bounds) {
  R r(reader);
  RevalidationReport out;
  const std::uint64_t checked = r.u64();
  std::size_t narrowed = 0;
  if (!checked_cast<std::size_t>(checked, narrowed)) {
    r.fail(ReasonCode::OutOfRange, "revalidation count does not fit in size_t");
  }
  out.checked = narrowed;
  const std::uint64_t suspended = r.u64();
  if (!checked_cast<std::size_t>(suspended, narrowed)) {
    r.fail(ReasonCode::OutOfRange, "revalidation count does not fit in size_t");
  }
  out.suspended = narrowed;
  const std::uint64_t degraded = r.u64();
  if (!checked_cast<std::size_t>(degraded, narrowed)) {
    r.fail(ReasonCode::OutOfRange, "revalidation count does not fit in size_t");
  }
  out.degraded = narrowed;
  const std::uint64_t failed = r.u64();
  if (!checked_cast<std::size_t>(failed, narrowed)) {
    r.fail(ReasonCode::OutOfRange, "revalidation count does not fit in size_t");
  }
  out.failed = narrowed;
  const std::uint64_t unchanged = r.u64();
  if (!checked_cast<std::size_t>(unchanged, narrowed)) {
    r.fail(ReasonCode::OutOfRange, "revalidation count does not fit in size_t");
  }
  out.unchanged = narrowed;
  out.affected = dec_assignment_id_list(r, bounds.max_assignments);
  out.dominant_reason = r.reason_code();
  out.truncated = r.boolean();
  const Status status = r.status();
  if (!status) {
    return status.error();
  }
  return out;
}

}  // namespace nof::wire
