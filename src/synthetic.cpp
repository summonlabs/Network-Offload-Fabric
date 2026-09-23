#include "nof/synthetic.hpp"

#include <algorithm>

#include "nof/digest.hpp"

namespace nof::synthetic {

namespace {

std::string token(const std::string& prefix, std::size_t index) {
  return prefix + std::to_string(index);
}

// Resolves the scenario's validity window. When the caller leaves the window
// unset the current system time is used, which keeps the synthetic fixtures
// usable from the CLI; deterministic tests always set it explicitly.
Micros resolve_observed_at(const ScenarioOptions& options) {
  if (options.observed_at.value() != 0) {
    return options.observed_at;
  }
  return SystemClock{}.now();
}

Micros resolve_valid_until(const ScenarioOptions& options, Micros observed_at) {
  if (options.valid_until.value() > observed_at.value()) {
    return options.valid_until;
  }
  return Micros::raw(observed_at.value() + options.ttl_micros);
}

Freshness freshness(Micros observed_at, Micros valid_until) {
  Freshness value;
  value.observed_at = observed_at;
  value.valid_until = valid_until;
  return value;
}

CapabilityRecord make_capability(const ScenarioOptions& options, const DeviceId& device,
                                 const IncarnationId& incarnation, DeviceKind kind,
                                 const Freshness& window) {
  CapabilityRecord record;
  record.device = device;
  record.incarnation = incarnation;
  record.cls = options.function_class;
  record.schema = options.schema;
  record.generation = options.capability_generation;
  record.provenance.source = SourceId::from_validated(options.source);
  record.provenance.sequence = options.sequence_base + 2;
  record.freshness = window;
  record.version_range.minimum = SemanticVersion{1, 0};
  record.version_range.maximum = SemanticVersion{3, 0};
  record.capacity.packets_per_second = PacketRate::raw(1000000);
  record.capacity.bytes_per_second = ByteRate::raw(1000000000);
  record.capacity.flows = FlowCount::raw(100000);
  record.capacity.queues = QueueCount::raw(64);
  record.capacity.memory = ByteSize::raw(1u << 30);
  switch (kind) {
    case DeviceKind::Dpu:
      record.supported.set(Semantic::LineRateDeterministic);
      record.supported.set(Semantic::ProgrammablePipeline);
      record.supported.set(Semantic::StatefulFlowTable);
      record.supported.set(Semantic::PerFlowCounters);
      record.supported.set(Semantic::KernelBypass);
      break;
    case DeviceKind::SmartNic:
      // Eligible for a smaller requirement, but explicitly denies a required
      // semantic: the fabric must treat this as UNSUPPORTED, never as unknown.
      record.supported.set(Semantic::LineRateDeterministic);
      record.supported.set(Semantic::PerFlowCounters);
      record.unsupported.set(Semantic::ProgrammablePipeline);
      break;
    case DeviceKind::Nic:
      // Explicitly unresolved: absence of a claim is UNKNOWN, not support.
      record.supported.set(Semantic::LineRateDeterministic);
      record.unknown.set(Semantic::ProgrammablePipeline);
      record.unknown.set(Semantic::StatefulFlowTable);
      break;
    case DeviceKind::HostStack:
      record.supported.set(Semantic::OrderingPreserving);
      record.unknown.set(Semantic::ProgrammablePipeline);
      record.unknown.set(Semantic::StatefulFlowTable);
      break;
  }
  return record;
}

}  // namespace

Scenario make_scenario(const ScenarioOptions& options) {
  Scenario scenario;
  const std::size_t host_count = options.hosts == 0 ? 1 : options.hosts;
  const Micros observed_at = resolve_observed_at(options);
  const Micros valid_until = resolve_valid_until(options, observed_at);
  const Freshness window = freshness(observed_at, valid_until);

  FunctionDescriptor function;
  function.id = FunctionId::from_validated("syn-fn-route");
  function.cls = options.function_class;
  function.required.set(Semantic::LineRateDeterministic);
  function.required.set(Semantic::ProgrammablePipeline);
  function.required_version = SemanticVersion{1, 0};
  function.exclusive_by_default = true;
  scenario.function = function.id;
  scenario.functions.push_back(function);

  TopologySnapshot topology;
  topology.generation = options.topology_generation;
  topology.provenance.source = SourceId::from_validated(options.source);
  topology.provenance.sequence = options.sequence_base;
  topology.freshness = window;

  CapabilityReport capabilities;
  capabilities.provenance.source = SourceId::from_validated(options.source);
  capabilities.provenance.sequence = options.sequence_base + 2;
  capabilities.freshness = window;

  ObservationReport observations;
  observations.topology_generation = topology.generation;
  observations.provenance.source = SourceId::from_validated(options.source);
  observations.provenance.sequence = options.sequence_base + 3;
  observations.freshness = window;

  for (std::size_t host_index = 0; host_index < host_count; ++host_index) {
    HostRecord host;
    host.id = HostId::from_validated(token("syn-h", host_index));
    host.labels.push_back(host_index % 2 == 0 ? "rack-a" : "rack-b");
    topology.hosts.push_back(host);
    if (host_index == 0) {
      scenario.first_host = host.id;
    }
    if (host_index == 1) {
      scenario.second_host = host.id;
    }

    const DeviceKind kinds[4] = {DeviceKind::Dpu, DeviceKind::SmartNic, DeviceKind::Nic,
                                 DeviceKind::HostStack};
    const char* suffixes[4] = {"dpu", "smartnic", "nic", "host"};
    for (int kind_index = 0; kind_index < 4; ++kind_index) {
      DeviceRecord device;
      device.id = DeviceId::from_validated("syn-h" + std::to_string(host_index) + "-" +
                                           suffixes[kind_index]);
      device.host = host.id;
      device.kind = kinds[kind_index];
      device.incarnation.generation = IncarnationGeneration::from_validated(1);
      device.incarnation.boot = BootId::from_validated("0123456789abcdef0123456789abcdef");
      device.capacity.packets_per_second = PacketRate::raw(1000000);
      device.capacity.bytes_per_second = ByteRate::raw(1000000000);
      device.capacity.flows = FlowCount::raw(100000);
      device.capacity.queues = QueueCount::raw(64);
      device.capacity.memory = ByteSize::raw(1u << 30);
      device.labels.push_back(kinds[kind_index] == DeviceKind::Dpu ? "offload-class-a"
                                                                   : "offload-class-b");
      switch (kinds[kind_index]) {
        case DeviceKind::Dpu:
          scenario.dpu_devices.push_back(device.id);
          break;
        case DeviceKind::SmartNic:
          scenario.smartnic_devices.push_back(device.id);
          break;
        case DeviceKind::Nic:
          scenario.nic_devices.push_back(device.id);
          break;
        case DeviceKind::HostStack:
          scenario.host_stack_devices.push_back(device.id);
          break;
      }
      capabilities.records.push_back(
          make_capability(options, device.id, device.incarnation, device.kind, window));

      DeviceObservation observation;
      observation.device = device.id;
      observation.incarnation = device.incarnation;
      observation.liveness = Liveness::Alive;
      observation.available.packets_per_second = PacketRate::raw(1000000);
      observation.available.flows = FlowCount::raw(100000);
      observation.available_known = true;
      observation.freshness = window;
      observation.provenance.source = SourceId::from_validated(options.source);
      observation.provenance.sequence = options.sequence_base + 3;
      observations.devices.push_back(observation);
      topology.devices.push_back(device);
    }
  }
  // Canonical order for every collection the fabric validates.
  std::sort(topology.devices.begin(), topology.devices.end(),
            [](const DeviceRecord& left, const DeviceRecord& right) {
              return left.id < right.id;
            });
  std::sort(observations.devices.begin(), observations.devices.end(),
            [](const DeviceObservation& left, const DeviceObservation& right) {
              return left.device < right.device;
            });
  std::sort(capabilities.records.begin(), capabilities.records.end(),
            [](const CapabilityRecord& left, const CapabilityRecord& right) {
              if (left.device == right.device) {
                return left.cls < right.cls;
              }
              return left.device < right.device;
            });

  PolicySnapshot policy;
  policy.generation = options.policy_generation;
  policy.provenance.source = SourceId::from_validated(options.source);
  policy.provenance.sequence = options.sequence_base + 1;
  policy.freshness = window;
  policy.default_deny = true;
  PolicyRule rule;
  rule.cls = options.function_class;
  rule.required.set(Semantic::LineRateDeterministic);
  rule.allowed_kinds = {DeviceKind::Dpu, DeviceKind::SmartNic, DeviceKind::Nic};
  if (options.host_fallback_allowed) {
    rule.allowed_kinds.push_back(DeviceKind::HostStack);
  }
  // Canonical order: ascending by the durable numeric value of the enum.
  std::sort(rule.allowed_kinds.begin(), rule.allowed_kinds.end());
  rule.exclusive_key = ExclusiveKeyMode::PerClass;
  rule.allow_host_fallback = options.host_fallback_allowed;
  rule.require_authority = true;
  rule.require_fresh_observation = true;
  rule.require_capability = true;
  rule.priority = 10;
  rule.max_reassignments_per_scope = 3;
  rule.reassignment_window_micros = 3600000000ull;
  rule.max_assignments_per_device = options.max_assignments_per_device;
  policy.rules.push_back(rule);

  AuthorityGrant grant;
  // The authority identity is derived from the sequence base so that a fresh
  // evidence set after a restart does not collide with the replayed grant.
  grant.id = AuthorityId::from_validated("syn-authority-" + std::to_string(options.sequence_base));
  grant.policy_generation = options.policy_generation;
  grant.classes = {options.function_class};
  grant.kinds = {DeviceKind::Dpu, DeviceKind::SmartNic, DeviceKind::Nic};
  if (options.host_fallback_allowed) {
    grant.kinds.push_back(DeviceKind::HostStack);
  }
  std::sort(grant.kinds.begin(), grant.kinds.end());
  grant.actions = {AuthorityAction::Place, AuthorityAction::Replace, AuthorityAction::Revoke,
                   AuthorityAction::Reauthorize};
  std::sort(grant.actions.begin(), grant.actions.end());
  grant.issued_at = observed_at;
  grant.expires_at = Micros::raw(valid_until.value() + options.ttl_micros);
  grant.provenance.source = SourceId::from_validated(options.source);
  grant.provenance.sequence = options.sequence_base + 4;
  grant.freshness.observed_at = observed_at;
  grant.freshness.valid_until = valid_until;
  grant.max_uses = 0;

  scenario.topology = std::move(topology);
  scenario.policy = std::move(policy);
  scenario.capabilities = std::move(capabilities);
  scenario.observations = std::move(observations);
  scenario.authority = std::move(grant);

  ScopeSpec scope;
  scope.kind = ScopeKind::Flow;
  scope.domain = scenario.first_host;
  scope.selector = "dir=ingress,proto=tcp,dst=10.0.0.1:443";
  scenario.scope = scope;
  return scenario;
}

PlacementRequest make_request(const Scenario& scenario, const ScenarioOptions& options,
                              const std::string& request_id, bool request_replacement) {
  PlacementRequest request;
  request.request_id = RequestId::from_validated(request_id);
  request.function = scenario.function;
  request.cls = options.function_class;
  request.scope = scenario.scope;
  request.required.set(Semantic::LineRateDeterministic);
  request.required.set(Semantic::ProgrammablePipeline);
  request.required_version = SemanticVersion{1, 0};
  request.exclusivity = Exclusivity::Exclusive;
  request.demand.packets_per_second = PacketRate::raw(options.packets_per_second);
  request.demand.flows = FlowCount::raw(options.flows);
  request.demand.memory = ByteSize::raw(options.memory_bytes);
  request.allow_host_fallback = options.host_fallback_allowed;
  request.request_replacement = request_replacement;
  return request;
}

ObservationReport make_observations(const ScenarioOptions& options, const Scenario& scenario,
                                    std::uint64_t sequence, Micros observed_at, Liveness liveness,
                                    bool degrade_all) {
  ObservationReport report;
  report.topology_generation = scenario.topology.generation;
  report.provenance.source = SourceId::from_validated(options.source);
  report.provenance.sequence = sequence;
  report.freshness.observed_at = observed_at;
  report.freshness.valid_until = Micros::raw(observed_at.value() + 1000000);
  for (const DeviceRecord& device : scenario.topology.devices) {
    DeviceObservation observation;
    observation.device = device.id;
    observation.incarnation = device.incarnation;
    observation.liveness = degrade_all ? liveness
                                       : (device.kind == DeviceKind::HostStack ? Liveness::Alive
                                                                               : liveness);
    observation.available.packets_per_second = PacketRate::raw(1000000);
    observation.available_known = true;
    observation.freshness.observed_at = observed_at;
    observation.freshness.valid_until = Micros::raw(observed_at.value() + 1000000);
    observation.provenance.source = SourceId::from_validated(options.source);
    observation.provenance.sequence = sequence;
    report.devices.push_back(observation);
  }
  std::sort(report.devices.begin(), report.devices.end(),
            [](const DeviceObservation& left, const DeviceObservation& right) {
              return left.device < right.device;
            });
  return report;
}

}  // namespace nof::synthetic
