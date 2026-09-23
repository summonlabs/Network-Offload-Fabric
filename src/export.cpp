#include "detail/fabric_state.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "nof/canonical.hpp"
#include "nof/checked.hpp"
#include "nof/digest.hpp"
#include "nof/journal.hpp"
#include "nof/version.hpp"

// Canonical export surfaces and the invariant collector. Everything rendered
// here is emitted in a fixed order with integers only, so two equal states
// always produce byte-identical documents and identical fingerprints.
namespace nof::detail {

namespace {

using JsonValue = nof::JsonValue;

JsonValue json_string(const std::string& value) { return JsonValue::string(value); }

JsonValue json_bool(bool value) { return JsonValue::boolean(value); }

JsonValue json_u64(std::uint64_t value) { return JsonValue::uinteger(value); }

JsonValue json_i64(std::int64_t value) { return JsonValue::integer(value); }

Result<JsonValue> json_strings(const std::vector<std::string>& values) {
  JsonValue::Array array;
  array.reserve(values.size());
  for (const std::string& value : values) {
    array.push_back(json_string(value));
  }
  return JsonValue::array(std::move(array));
}

Result<JsonValue> json_provenance(const Provenance& value) {
  return JsonValue::object({{"sequence", json_u64(value.sequence)},
                            {"source", json_string(value.source.value())}});
}

Result<JsonValue> json_freshness(const Freshness& value) {
  return JsonValue::object({{"observed_at", json_i64(value.observed_at.value())},
                            {"valid_until", json_i64(value.valid_until.value())}});
}

Result<JsonValue> json_incarnation(const IncarnationId& value) {
  return JsonValue::object({{"boot", json_string(value.boot.value())},
                            {"generation", json_u64(value.generation.value())}});
}

Result<JsonValue> json_fence(const FencingToken& value) {
  return JsonValue::object({{"epoch", json_u64(value.epoch)},
                            {"sequence", json_u64(value.sequence)}});
}

Result<JsonValue> json_binding(const GenerationBinding& value) {
  return JsonValue::object({{"assignment", json_u64(value.assignment.value())},
                            {"capability", json_u64(value.capability.value())},
                            {"policy", json_u64(value.policy.value())},
                            {"schema", json_u64(value.schema.value())},
                            {"topology", json_u64(value.topology.value())}});
}

Result<JsonValue> json_demand(const DemandVector& value) {
  return JsonValue::object({{"bytes_per_second", json_u64(value.bytes_per_second.value())},
                            {"flows", json_u64(value.flows.value())},
                            {"memory_bytes", json_u64(value.memory.value())},
                            {"packets_per_second", json_u64(value.packets_per_second.value())},
                            {"queues", json_u64(value.queues.value())}});
}

Result<JsonValue> json_capacity(const CapacityVector& value) {
  return JsonValue::object({{"bytes_per_second", json_u64(value.bytes_per_second.value())},
                            {"flows", json_u64(value.flows.value())},
                            {"memory_bytes", json_u64(value.memory.value())},
                            {"packets_per_second", json_u64(value.packets_per_second.value())},
                            {"queues", json_u64(value.queues.value())}});
}

Result<JsonValue> json_semantics(const SemanticsMask& value) {
  std::vector<std::string> tokens;
  for (const Semantic semantic : value.values()) {
    tokens.push_back(to_string(semantic));
  }
  return json_strings(tokens);
}

Result<JsonValue> json_scope(const ScopeSpec& value) {
  return JsonValue::object({{"device", json_string(value.device.value())},
                            {"domain", json_string(value.domain.value())},
                            {"kind", json_string(to_string(value.kind))},
                            {"selector", json_string(value.selector)}});
}

Result<JsonValue> json_transition(const TransitionRecord& value) {
  return JsonValue::object({{"at", json_i64(value.at.value())},
                            {"fence", json_fence(value.fence).value()},
                            {"from", json_string(to_string(value.from))},
                            {"reason", json_string(to_string(value.reason))},
                            {"to", json_string(to_string(value.to))}});
}

Result<JsonValue> json_effect(const EffectRecord& value) {
  return JsonValue::object(
      {{"attempt", json_u64(value.attempt.value())},
       {"capability_generation", json_u64(value.capability_generation.value())},
       {"fence", json_fence(value.fence).value()},
       {"generation", json_u64(value.generation.value())},
       {"incarnation", json_incarnation(value.incarnation).value()},
       {"observed_at", json_i64(value.observed_at.value())},
       {"outcome", json_string(to_string(value.outcome))},
       {"reason", json_string(to_string(value.reason))}});
}

Result<JsonValue> json_assignment(const AssignmentRecord& value) {
  JsonValue::Array history;
  history.reserve(value.history.size());
  for (const TransitionRecord& transition : value.history) {
    auto item = json_transition(transition);
    if (!item) {
      return item.error();
    }
    history.push_back(item.take());
  }
  JsonValue::Array effects;
  effects.reserve(value.effects.size());
  for (const EffectRecord& effect : value.effects) {
    auto item = json_effect(effect);
    if (!item) {
      return item.error();
    }
    effects.push_back(item.take());
  }
  auto history_value = JsonValue::array(std::move(history));
  if (!history_value) {
    return history_value.error();
  }
  auto effects_value = JsonValue::array(std::move(effects));
  if (!effects_value) {
    return effects_value.error();
  }
  return JsonValue::object(
      {{"attempt", json_u64(value.attempt.value())},
       {"authority", json_string(value.authority.value())},
       {"binding", json_binding(value.binding).value()},
       {"capability_generation", json_u64(value.binding.capability.value())},
       {"created_at", json_i64(value.created_at.value())},
       {"demand", json_demand(value.demand).value()},
       {"device", json_string(value.device.value())},
       {"digest", json_string(assignment_digest(value).hex())},
       {"effects", effects_value.take()},
       {"exclusive_key", json_string(to_string(value.exclusive_key))},
       {"exclusivity", json_string(to_string(value.exclusivity))},
       {"fence", json_fence(value.fence).value()},
       {"freshness", json_freshness(value.freshness).value()},
       {"function", json_string(value.function.value())},
       {"function_class", json_string(to_string(value.cls))},
       {"generation", json_u64(value.generation.value())},
       {"history", history_value.take()},
       {"host", json_string(value.host.value())},
       {"id", json_string(value.id.value())},
       {"incarnation", json_incarnation(value.incarnation).value()},
       {"kind", json_string(to_string(value.kind))},
       {"lease", json_u64(value.lease.value())},
       {"mode", json_string(to_string(value.mode))},
       {"request_fingerprint", json_string(value.request_fingerprint.hex())},
       {"scope", json_scope(value.scope).value()},
       {"scope_id", json_string(value.scope_id.value())},
       {"state", json_string(to_string(value.state))},
       {"state_reason", json_string(to_string(value.state_reason))},
       {"updated_at", json_i64(value.updated_at.value())}});
}

Result<JsonValue> json_device(const DeviceRecord& value) {
  auto labels = json_strings(value.labels);
  if (!labels) {
    return labels.error();
  }
  return JsonValue::object({{"capacity", json_capacity(value.capacity).value()},
                            {"decommissioned", json_bool(value.decommissioned)},
                            {"host", json_string(value.host.value())},
                            {"id", json_string(value.id.value())},
                            {"incarnation", json_incarnation(value.incarnation).value()},
                            {"kind", json_string(to_string(value.kind))},
                            {"labels", labels.take()}});
}

Result<JsonValue> json_capability(const CapabilityRecord& value) {
  return JsonValue::object(
      {{"capacity", json_capacity(value.capacity).value()},
       {"device", json_string(value.device.value())},
       {"freshness", json_freshness(value.freshness).value()},
       {"function_class", json_string(to_string(value.cls))},
       {"generation", json_u64(value.generation.value())},
       {"incarnation", json_incarnation(value.incarnation).value()},
       {"provenance", json_provenance(value.provenance).value()},
       {"revoked", json_bool(value.revoked)},
       {"schema", json_u64(value.schema.value())},
       {"supported", json_semantics(value.supported).value()},
       {"unknown", json_semantics(value.unknown).value()},
       {"unsupported", json_semantics(value.unsupported).value()},
       {"version_max", json_string(value.version_range.maximum.to_string())},
       {"version_min", json_string(value.version_range.minimum.to_string())}});
}

Result<JsonValue> json_policy_rule(const PolicyRule& value) {
  JsonValue::Array kinds;
  for (const DeviceKind kind : value.allowed_kinds) {
    kinds.push_back(json_string(to_string(kind)));
  }
  auto kinds_value = JsonValue::array(std::move(kinds));
  if (!kinds_value) {
    return kinds_value.error();
  }
  return JsonValue::object(
      {{"allow_host_fallback", json_bool(value.allow_host_fallback)},
       {"allowed_kinds", kinds_value.take()},
       {"exclusive_key", json_string(to_string(value.exclusive_key))},
       {"function_class", json_string(to_string(value.cls))},
       {"max_assignments_per_device", json_u64(value.max_assignments_per_device)},
       {"max_reassignments_per_scope", json_u64(value.max_reassignments_per_scope)},
       {"priority", json_u64(value.priority)},
       {"reassignment_window_micros", json_u64(value.reassignment_window_micros)},
       {"required", json_semantics(value.required).value()},
       {"reserve", json_demand(value.reserve).value()},
       {"require_authority", json_bool(value.require_authority)},
       {"require_capability", json_bool(value.require_capability)},
       {"require_fresh_observation", json_bool(value.require_fresh_observation)}});
}

Result<JsonValue> json_authority(const AuthorityGrant& value) {
  JsonValue::Array classes;
  for (const FunctionClass cls : value.classes) {
    classes.push_back(json_string(to_string(cls)));
  }
  JsonValue::Array kinds;
  for (const DeviceKind kind : value.kinds) {
    kinds.push_back(json_string(to_string(kind)));
  }
  JsonValue::Array actions;
  for (const AuthorityAction action : value.actions) {
    actions.push_back(json_string(to_string(action)));
  }
  auto classes_value = JsonValue::array(std::move(classes));
  if (!classes_value) {
    return classes_value.error();
  }
  auto kinds_value = JsonValue::array(std::move(kinds));
  if (!kinds_value) {
    return kinds_value.error();
  }
  auto actions_value = JsonValue::array(std::move(actions));
  if (!actions_value) {
    return actions_value.error();
  }
  return JsonValue::object(
      {{"actions", actions_value.take()},
       {"classes", classes_value.take()},
       {"expires_at", json_i64(value.expires_at.value())},
       {"freshness", json_freshness(value.freshness).value()},
       {"host_scope", json_string(value.host_scope.value())},
       {"id", json_string(value.id.value())},
       {"issued_at", json_i64(value.issued_at.value())},
       {"kinds", kinds_value.take()},
       {"max_uses", json_u64(value.max_uses)},
       {"policy_generation", json_u64(value.policy_generation.value())},
       {"provenance", json_provenance(value.provenance).value()},
       {"revoked", json_bool(value.revoked)},
       {"scope", json_string(value.scope.value())},
       {"semantics_ceiling", json_semantics(value.semantics_ceiling).value()},
       {"used", json_u64(value.used)}});
}

Result<JsonValue> json_observation(const DeviceObservation& value) {
  return JsonValue::object(
      {{"available", json_capacity(value.available).value()},
       {"available_known", json_bool(value.available_known)},
       {"device", json_string(value.device.value())},
       {"freshness", json_freshness(value.freshness).value()},
       {"incarnation", json_incarnation(value.incarnation).value()},
       {"liveness", json_string(to_string(value.liveness))},
       {"provenance", json_provenance(value.provenance).value()}});
}

Result<JsonValue> json_function(const FunctionDescriptor& value) {
  return JsonValue::object({{"exclusive_by_default", json_bool(value.exclusive_by_default)},
                            {"function_class", json_string(to_string(value.cls))},
                            {"id", json_string(value.id.value())},
                            {"required", json_semantics(value.required).value()},
                            {"required_version", json_string(value.required_version.to_string())}});
}

}  // namespace

Status export_state_json(const FabricState& state, const Bounds& bounds, std::string& out) {
  using JsonValue = nof::JsonValue;
  JsonValue::Array hosts;
  JsonValue::Array devices;
  JsonValue::Array links;
  JsonValue::Array capabilities;
  JsonValue::Array authorities;
  JsonValue::Array observations;
  JsonValue::Array assignments;
  JsonValue::Array scopes;
  JsonValue::Array sources;
  JsonValue::Array rules;
  JsonValue::Array functions;
  JsonValue::Array reassignments;

  if (state.has_topology) {
    for (const HostRecord& host : state.topology.hosts) {
      auto labels = json_strings(host.labels);
      if (!labels) {
        return labels.error();
      }
      auto item = JsonValue::object(
          {{"id", json_string(host.id.value())}, {"labels", labels.take()}});
      if (!item) {
        return item.error();
      }
      hosts.push_back(item.take());
    }
    for (const DeviceRecord& device : state.topology.devices) {
      auto item = json_device(device);
      if (!item) {
        return item.error();
      }
      devices.push_back(item.take());
    }
    for (const LinkRecord& link : state.topology.links) {
      auto item = JsonValue::object({{"a", json_string(link.a.value())},
                                     {"b", json_string(link.b.value())},
                                     {"kind", json_string(to_string(link.kind))}});
      if (!item) {
        return item.error();
      }
      links.push_back(item.take());
    }
  }
  for (const auto& entry : state.capabilities) {
    auto item = json_capability(entry.second);
    if (!item) {
      return item.error();
    }
    capabilities.push_back(item.take());
  }
  if (state.has_policy) {
    for (const PolicyRule& rule : state.policy.rules) {
      auto item = json_policy_rule(rule);
      if (!item) {
        return item.error();
      }
      rules.push_back(item.take());
    }
  }
  for (const auto& entry : state.authority) {
    auto item = json_authority(entry.second);
    if (!item) {
      return item.error();
    }
    authorities.push_back(item.take());
  }
  for (const auto& entry : state.observations) {
    auto item = json_observation(entry.second);
    if (!item) {
      return item.error();
    }
    observations.push_back(item.take());
  }
  for (const auto& entry : state.assignments) {
    auto item = json_assignment(entry.second);
    if (!item) {
      return item.error();
    }
    assignments.push_back(item.take());
  }
  for (const auto& entry : state.scope_specs) {
    auto item = JsonValue::object({{"id", json_string(entry.first.value())},
                                   {"spec", json_scope(entry.second).value()}});
    if (!item) {
      return item.error();
    }
    scopes.push_back(item.take());
  }
  for (const auto& entry : state.sources) {
    auto item = JsonValue::object(
        {{"domain", json_string(to_string(entry.first.domain))},
         {"last_digest", json_string(entry.second.last_digest.hex())},
         {"last_sequence", json_u64(entry.second.last_sequence)},
         {"restart_floor", json_u64(entry.second.restart_floor)},
         {"seen", json_bool(entry.second.seen)},
         {"source", json_string(entry.first.source.value())}});
    if (!item) {
      return item.error();
    }
    sources.push_back(item.take());
  }
  for (const auto& entry : state.reassignments) {
    JsonValue::Array stamps;
    for (const Micros stamp : entry.second) {
      stamps.push_back(json_i64(stamp.value()));
    }
    auto stamps_value = JsonValue::array(std::move(stamps));
    if (!stamps_value) {
      return stamps_value.error();
    }
    auto item = JsonValue::object({{"function_class", json_string(to_string(entry.first.cls))},
                                   {"scope", json_string(entry.first.scope.value())},
                                   {"stamps", stamps_value.take()}});
    if (!item) {
      return item.error();
    }
    reassignments.push_back(item.take());
  }
  for (const auto& entry : state.functions) {
    auto item = json_function(entry.second);
    if (!item) {
      return item.error();
    }
    functions.push_back(item.take());
  }

  const auto to_array = [](JsonValue::Array values) -> Result<JsonValue> {
    return JsonValue::array(std::move(values));
  };
  auto hosts_value = to_array(std::move(hosts));
  auto devices_value = to_array(std::move(devices));
  auto links_value = to_array(std::move(links));
  auto capabilities_value = to_array(std::move(capabilities));
  auto authorities_value = to_array(std::move(authorities));
  auto observations_value = to_array(std::move(observations));
  auto assignments_value = to_array(std::move(assignments));
  auto scopes_value = to_array(std::move(scopes));
  auto sources_value = to_array(std::move(sources));
  auto rules_value = to_array(std::move(rules));
  auto functions_value = to_array(std::move(functions));
  auto reassignments_value = to_array(std::move(reassignments));
  if (!hosts_value || !devices_value || !links_value || !capabilities_value ||
      !authorities_value || !observations_value || !assignments_value || !scopes_value ||
      !sources_value || !rules_value || !functions_value || !reassignments_value) {
    return Error(ReasonCode::InternalInvariant, "canonical export could not be assembled");
  }

  auto coordinator = JsonValue::object(
      {{"boot", json_string(state.epoch.boot.value())},
       {"epoch", json_u64(state.epoch.counter)},
       {"epoch_counter", json_u64(state.epoch_counter)},
       {"next_attempt", json_u64(state.next_attempt)},
       {"next_fence_sequence", json_u64(state.next_fence_sequence)},
       {"next_lease", json_u64(state.next_lease)},
       {"previous_epoch_counter", json_u64(state.previous_epoch_counter)}});
  auto topology_object = JsonValue::object(
      {{"devices", devices_value.take()},
       {"freshness", state.has_topology ? json_freshness(state.topology.freshness).value()
                                        : JsonValue::null()},
       {"generation", json_u64(state.has_topology ? state.topology.generation.value() : 0)},
       {"hosts", hosts_value.take()},
       {"links", links_value.take()},
       {"present", json_bool(state.has_topology)},
       {"provenance", state.has_topology ? json_provenance(state.topology.provenance).value()
                                         : JsonValue::null()}});
  auto policy_object = JsonValue::object(
      {{"default_deny", json_bool(state.has_policy ? state.policy.default_deny : true)},
       {"freshness", state.has_policy ? json_freshness(state.policy.freshness).value()
                                      : JsonValue::null()},
       {"generation", json_u64(state.has_policy ? state.policy.generation.value() : 0)},
       {"present", json_bool(state.has_policy)},
       {"provenance", state.has_policy ? json_provenance(state.policy.provenance).value()
                                       : JsonValue::null()},
       {"rules", rules_value.take()}});
  if (!coordinator || !topology_object || !policy_object) {
    return Error(ReasonCode::InternalInvariant, "canonical export could not be assembled");
  }
  auto document = JsonValue::object(
      {{"assignments", assignments_value.take()},
       {"authority", authorities_value.take()},
       {"capabilities", capabilities_value.take()},
       {"canonical_encoding_version", json_u64(kCanonicalEncodingVersion)},
       {"coordinator", coordinator.take()},
       {"functions", functions_value.take()},
       {"observations", observations_value.take()},
       {"policy", policy_object.take()},
       {"product", json_string(std::string(kProductName))},
       {"reassignments", reassignments_value.take()},
       {"scopes", scopes_value.take()},
       {"sources", sources_value.take()},
       {"state_digest", json_string(compute_state_digest(state, bounds).hex())},
       {"store_format_version", json_u64(kStoreFormatVersion)},
       {"topology", topology_object.take()},
       {"version", json_string(std::string(version_string()))}});
  if (!document) {
    return document.error();
  }
  return document.value().dump(out, bounds.max_export_bytes);
}

Status export_state_text(const FabricState& state, const Bounds& bounds, std::string& out) {
  out.clear();
  const auto line = [&out, &bounds](const std::string& text) {
    out += text;
    out += "\n";
    if (out.size() > bounds.max_export_bytes) {
      return false;
    }
    return true;
  };
  if (!line("network-offload-fabric state")) {
    return Error(ReasonCode::OversizedInput, "text export exceeds the configured bound");
  }
  line("version=" + std::string(version_string()));
  line("epoch=" + std::to_string(state.epoch.counter) + " boot=" + state.epoch.boot.value());
  line("state_digest=" + compute_state_digest(state, bounds).hex());
  line("topology_present=" + std::string(state.has_topology ? "true" : "false"));
  if (state.has_topology) {
    line("topology_generation=" + std::to_string(state.topology.generation.value()));
    line("hosts=" + std::to_string(state.topology.hosts.size()));
    line("devices=" + std::to_string(state.topology.devices.size()));
    for (const DeviceRecord& device : state.topology.devices) {
      line("device " + device.id.value() + " host=" + device.host.value() +
           " kind=" + to_string(device.kind) +
           " incarnation=" + std::to_string(device.incarnation.generation.value()) + "@" +
           device.incarnation.boot.value() +
           (device.decommissioned ? " decommissioned" : ""));
    }
  }
  line("policy_present=" + std::string(state.has_policy ? "true" : "false"));
  if (state.has_policy) {
    line("policy_generation=" + std::to_string(state.policy.generation.value()));
    for (const PolicyRule& rule : state.policy.rules) {
      line(std::string("rule ") + to_string(rule.cls) +
           " priority=" + std::to_string(rule.priority));
    }
  }
  line("capabilities=" + std::to_string(state.capabilities.size()));
  for (const auto& entry : state.capabilities) {
    line("capability " + entry.second.device.value() + " " + to_string(entry.second.cls) +
         " generation=" + std::to_string(entry.second.generation.value()));
  }
  line("authority_grants=" + std::to_string(state.authority.size()));
  for (const auto& entry : state.authority) {
    line("authority " + entry.first.value() +
         (entry.second.revoked ? " revoked" : " active"));
  }
  line("observations=" + std::to_string(state.observations.size()));
  for (const auto& entry : state.observations) {
    line("observation " + entry.first.value() + " liveness=" + to_string(entry.second.liveness));
  }
  line("assignments=" + std::to_string(state.assignments.size()));
  for (const auto& entry : state.assignments) {
    const AssignmentRecord& record = entry.second;
    line("assignment " + record.id.value() + " function=" + record.function.value() +
         " scope=" + record.scope_id.value() + " device=" + record.device.value() +
         " mode=" + to_string(record.mode) + " state=" + to_string(record.state) +
         " generation=" + std::to_string(record.generation.value()) +
         " fence=" + std::to_string(record.fence.epoch) + ":" +
         std::to_string(record.fence.sequence) +
         " reason=" + to_string(record.state_reason));
  }
  line("scopes=" + std::to_string(state.scope_specs.size()));
  for (const auto& entry : state.scope_specs) {
    line("scope " + entry.first.value() + " kind=" + to_string(entry.second.kind));
  }
  line("sources=" + std::to_string(state.sources.size()));
  for (const auto& entry : state.sources) {
    line("source " + entry.first.source.value() + " domain=" + to_string(entry.first.domain) +
         " last_sequence=" + std::to_string(entry.second.last_sequence) +
         " restart_floor=" + std::to_string(entry.second.restart_floor));
  }
  return ok_status();
}

namespace {

void add_violation(InvariantReport& report, const char* invariant, const std::string& detail) {
  InvariantViolation violation;
  violation.invariant = invariant;
  violation.detail = detail;
  report.violations.push_back(violation);
  report.clean = false;
}

}  // namespace

Status collect_invariants(const FabricState& state, const Bounds& bounds, InvariantReport& report) {
  report.clean = true;
  report.violations.clear();
  report.checked = 0;

  std::map<ScopeId, std::size_t> whole_scope_claims;
  std::map<std::pair<ScopeId, FunctionClass>, std::size_t> class_claims;
  std::map<DeviceId, DemandVector> recomputed;
  std::map<FencingToken, AssignmentId> fences;
  std::map<AuthorityId, std::size_t> grant_uses;

  for (const auto& entry : state.assignments) {
    const AssignmentRecord& record = entry.second;
    report.checked += 1;
    if (record.id.empty()) {
      add_violation(report, "assignment_identity", "assignment carries an empty identifier");
    }
    if (!(record.id == entry.first)) {
      add_violation(report, "assignment_identity", "assignment map key does not match its record");
    }
    if (record.scope.kind != ScopeKind::Global) {
      auto derived = derive_scope_id(record.scope);
      if (!derived) {
        add_violation(report, "scope_identity", "assignment scope spec does not canonicalize");
      } else if (!(derived.value() == record.scope_id)) {
        add_violation(report, "scope_identity",
                      "scope identifier does not re-derive from the scope specification");
      }
    }
    if (record.fence.is_set()) {
      const auto existing = fences.find(record.fence);
      if (existing != fences.end() && !(existing->second == record.id)) {
        add_violation(report, "fence_uniqueness",
                      "two assignments carry the same fencing token");
      }
      fences[record.fence] = record.id;
      if (record.fence.epoch > state.epoch.counter) {
        add_violation(report, "fence_epoch", "assignment carries a fencing token from the future");
      }
    }
    if (holds_authority(record.state)) {
      if (record.exclusivity == Exclusivity::Exclusive) {
        if (record.exclusive_key == ExclusiveKeyMode::PerClass) {
          class_claims[std::make_pair(record.scope_id, record.cls)] += 1;
        } else {
          whole_scope_claims[record.scope_id] += 1;
        }
      }
      if (!record.authority.empty()) {
        grant_uses[record.authority] += 1;
      }
      DemandVector& used = recomputed[record.device];
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
    if (state.has_topology && holds_authority(record.state)) {
      const DeviceRecord* device = state.topology.find_device(record.device);
      if (device == nullptr) {
        add_violation(report, "authority_target_present",
                      "an assignment holds authority for an absent target");
      } else if (!(device->incarnation == record.incarnation)) {
        add_violation(report, "authority_target_incarnation",
                      "an assignment holds authority for a stale device incarnation");
      }
    }
  }

  for (const auto& entry : whole_scope_claims) {
    if (entry.second > 1) {
      add_violation(report, "exclusive_scope_uniqueness",
                    "more than one assignment holds exclusive authority over a governed scope");
    }
  }
  for (const auto& entry : class_claims) {
    if (entry.second > 1) {
      add_violation(report, "exclusive_class_uniqueness",
                    "more than one assignment holds exclusive authority over a scope and class");
    }
  }
  for (const auto& entry : whole_scope_claims) {
    ExclusivityKey lower;
    lower.scope = entry.first;
    lower.cls = static_cast<FunctionClass>(0);
    for (auto it = class_claims.lower_bound(std::make_pair(entry.first, FunctionClass::RouteLookup));
         it != class_claims.end() && it->first.first == entry.first; ++it) {
      add_violation(report, "exclusive_key_mode_mix",
                    "a whole-scope claim overlaps a per-class claim on the same scope");
    }
  }
  for (const auto& entry : state.exclusive_by_scope) {
    report.checked += 1;
    const auto record = state.assignments.find(entry.second);
    if (record == state.assignments.end()) {
      add_violation(report, "exclusive_index_consistency",
                    "the exclusivity index references an unknown assignment");
    } else if (!holds_authority(record->second.state)) {
      add_violation(report, "exclusive_index_consistency",
                    "the exclusivity index references an assignment without authority");
    }
  }
  for (const auto& entry : state.exclusive_by_class) {
    report.checked += 1;
    const auto record = state.assignments.find(entry.second);
    if (record == state.assignments.end()) {
      add_violation(report, "exclusive_index_consistency",
                    "the per-class exclusivity index references an unknown assignment");
    } else if (!holds_authority(record->second.state)) {
      add_violation(report, "exclusive_index_consistency",
                    "the per-class exclusivity index references an assignment without authority");
    }
  }
  for (const auto& entry : state.committed) {
    report.checked += 1;
    const auto recomputed_entry = recomputed.find(entry.first);
    const DemandVector expected = recomputed_entry == recomputed.end() ? DemandVector{}
                                                                      : recomputed_entry->second;
    if (!(expected == entry.second)) {
      add_violation(report, "capacity_accounting",
                    "device capacity accounting does not match the live assignments");
    }
  }
  for (const auto& entry : recomputed) {
    report.checked += 1;
    const auto tracked = state.committed.find(entry.first);
    if (tracked == state.committed.end() || !(tracked->second == entry.second)) {
      add_violation(report, "capacity_accounting",
                    "a device with live demand is missing from capacity accounting");
    }
  }
  for (const auto& entry : state.sources) {
    report.checked += 1;
    if (entry.second.restart_floor > entry.second.last_sequence) {
      add_violation(report, "evidence_floor",
                    "the restart floor exceeds the last accepted evidence sequence");
    }
  }
  for (const auto& entry : state.authority) {
    report.checked += 1;
    const auto used = grant_uses.find(entry.first);
    const std::size_t expected = used == grant_uses.end() ? 0 : used->second;
    if (entry.second.used < expected) {
      add_violation(report, "authority_usage",
                    "authority use counter is below the number of live assignments using it");
    }
  }
  if (state.assignments.size() > bounds.max_assignments) {
    add_violation(report, "bounds", "assignment count exceeds the configured bound");
  }
  if (state.scope_specs.size() > bounds.max_scopes) {
    add_violation(report, "bounds", "scope count exceeds the configured bound");
  }
  return ok_status();
}

}  // namespace nof::detail

namespace nof {

std::string render_assignment(const AssignmentRecord& record) {
  std::string out;
  out += "assignment=" + record.id.value() + "\n";
  out += "state=" + std::string(to_string(record.state)) + "\n";
  out += "state_reason=" + std::string(to_string(record.state_reason)) + "\n";
  out += "function=" + record.function.value() + " class=" + to_string(record.cls) + "\n";
  out += "scope=" + record.scope_id.value() + " exclusivity=" + to_string(record.exclusivity) +
         " key=" + to_string(record.exclusive_key) + "\n";
  out += "mode=" + std::string(to_string(record.mode)) + "\n";
  out += "device=" + record.device.value() + " host=" + record.host.value() +
         " kind=" + to_string(record.kind) + "\n";
  out += "incarnation=" + std::to_string(record.incarnation.generation.value()) + "@" +
         record.incarnation.boot.value() + "\n";
  out += "generation=" + std::to_string(record.generation.value()) + "\n";
  out += "binding=topology:" + std::to_string(record.binding.topology.value()) +
         ",capability:" + std::to_string(record.binding.capability.value()) +
         ",policy:" + std::to_string(record.binding.policy.value()) +
         ",assignment:" + std::to_string(record.binding.assignment.value()) +
         ",schema:" + std::to_string(record.binding.schema.value()) + "\n";
  out += "authority=" + record.authority.value() + "\n";
  out += "lease=" + std::to_string(record.lease.value()) +
         " attempt=" + std::to_string(record.attempt.value()) + "\n";
  out += "fence=" + std::to_string(record.fence.epoch) + ":" +
         std::to_string(record.fence.sequence) + "\n";
  out += "digest=" + assignment_digest(record).hex() + "\n";
  for (const TransitionRecord& transition : record.history) {
    out += "history " + std::string(to_string(transition.from)) + "->" +
           to_string(transition.to) + " reason=" + to_string(transition.reason) +
           " at=" + std::to_string(transition.at.value()) + "\n";
  }
  for (const EffectRecord& effect : record.effects) {
    out += "effect attempt=" + std::to_string(effect.attempt.value()) +
           " outcome=" + to_string(effect.outcome) + " reason=" + to_string(effect.reason) +
           " at=" + std::to_string(effect.observed_at.value()) + "\n";
  }
  return out;
}

std::string InvariantReport::render() const {
  std::string out;
  out += clean ? "invariants=clean\n" : "invariants=violated\n";
  out += "checked=" + std::to_string(checked) + "\n";
  out += "violations=" + std::to_string(violations.size()) + "\n";
  for (const InvariantViolation& violation : violations) {
    out += "violation ";
    out += violation.invariant;
    out += ": ";
    out += violation.detail;
    out += "\n";
  }
  return out;
}

std::string RecoveryReport::render() const {
  std::string out;
  out += "recovery_classification=";
  out += to_string(classification);
  out += "\n";
  out += "recovery_reason=";
  out += to_string(reason);
  out += "\n";
  out += "store_generation=" + std::to_string(store_generation.value()) + "\n";
  out += "records_replayed=" + std::to_string(records_replayed) + "\n";
  out += "records_discarded=" + std::to_string(records_discarded) + "\n";
  out += "bytes_discarded=" + std::to_string(bytes_discarded) + "\n";
  out += "previous_epoch=" + std::to_string(previous_epoch) + "\n";
  out += "epoch=" + std::to_string(epoch.counter) + "\n";
  out += "epoch_boot=" + epoch.boot.value() + "\n";
  out += "assignments_suspended=" + std::to_string(assignments_suspended) + "\n";
  out += "observations_invalidated=" + std::to_string(observations_invalidated) + "\n";
  out += "authority_invalidated=" + std::to_string(authority_invalidated) + "\n";
  out += "leases_voided=" + std::to_string(leases_voided) + "\n";
  out += "fences_invalidated=" + std::to_string(fences_invalidated) + "\n";
  out += std::string("authority_restored=") + (authority_restored ? "true" : "false") + "\n";
  return out;
}

std::string Stats::render() const {
  std::string out;
  const auto counter = [&out](const char* name, std::uint64_t value) {
    out += name;
    out += "=";
    out += std::to_string(value);
    out += "\n";
  };
  const auto gauge = [&out](const char* name, std::size_t value) {
    out += name;
    out += "=";
    out += std::to_string(value);
    out += "\n";
  };
  counter("topology_accepted", topology_accepted);
  counter("topology_refused", topology_refused);
  counter("capability_reports_accepted", capability_reports_accepted);
  counter("capability_reports_refused", capability_reports_refused);
  counter("capability_conflicts", capability_conflicts);
  counter("policy_accepted", policy_accepted);
  counter("policy_refused", policy_refused);
  counter("observations_accepted", observations_accepted);
  counter("observations_refused", observations_refused);
  counter("authority_granted", authority_granted);
  counter("authority_refused", authority_refused);
  counter("authority_withdrawn", authority_withdrawn);
  counter("functions_registered", functions_registered);
  counter("functions_refused", functions_refused);
  counter("plans_accepted", plans_accepted);
  counter("plans_refused", plans_refused);
  counter("applies_accepted", applies_accepted);
  counter("applies_refused", applies_refused);
  counter("revokes_accepted", revokes_accepted);
  counter("revokes_refused", revokes_refused);
  counter("replaces_accepted", replaces_accepted);
  counter("replaces_refused", replaces_refused);
  counter("reauthorizations_accepted", reauthorizations_accepted);
  counter("reauthorizations_refused", reauthorizations_refused);
  counter("effects_applied", effects_applied);
  counter("effects_acknowledged", effects_acknowledged);
  counter("effects_rejected", effects_rejected);
  counter("effects_failed", effects_failed);
  counter("effects_unknown", effects_unknown);
  counter("effects_fenced", effects_fenced);
  counter("effects_duplicate", effects_duplicate);
  counter("exclusive_conflicts", exclusive_conflicts);
  counter("reassignment_budget_refusals", reassignment_budget_refusals);
  counter("reassignments", reassignments);
  counter("host_fallbacks", host_fallbacks);
  counter("revalidations", revalidations);
  counter("assignments_suspended", assignments_suspended);
  counter("assignments_degraded", assignments_degraded);
  counter("cancellations", cancellations);
  counter("refusals_after_cancel", refusals_after_cancel);
  counter("evidence_superseded", evidence_superseded);
  counter("evidence_conflicting", evidence_conflicting);
  counter("evidence_stale_refusals", evidence_stale_refusals);
  counter("sequence_regressions", sequence_regressions);
  counter("duplicate_deliveries_idempotent", duplicate_deliveries_idempotent);
  counter("duplicate_deliveries_fenced", duplicate_deliveries_fenced);
  counter("results_truncated", results_truncated);
  counter("entries_evicted", entries_evicted);
  counter("journal_records_appended", journal_records_appended);
  counter("journal_bytes_appended", journal_bytes_appended);
  counter("compactions", compactions);
  counter("commits", commits);
  counter("commit_failures", commit_failures);
  counter("recovery_events", recovery_events);
  counter("frames_accepted", frames_accepted);
  counter("frames_refused", frames_refused);
  counter("connections_accepted", connections_accepted);
  counter("connections_refused", connections_refused);
  counter("requests_handled", requests_handled);
  counter("requests_refused", requests_refused);
  counter("shutdowns", shutdowns);
  gauge("live_hosts", live_hosts);
  gauge("live_devices", live_devices);
  gauge("live_functions", live_functions);
  gauge("live_scopes", live_scopes);
  gauge("live_assignments", live_assignments);
  gauge("live_authority_grants", live_authority_grants);
  gauge("live_observations", live_observations);
  gauge("live_idempotency_entries", live_idempotency_entries);
  gauge("live_journal_records", live_journal_records);
  gauge("open_connections", open_connections);
  gauge("in_flight_requests", in_flight_requests);
  return out;
}

const char* to_string(RecoveryClassification value) noexcept {
  switch (value) {
    case RecoveryClassification::FreshStore:
      return "fresh_store";
    case RecoveryClassification::CleanReopen:
      return "clean_reopen";
    case RecoveryClassification::TornTailTruncated:
      return "torn_tail_truncated";
    case RecoveryClassification::DamagedTailTruncated:
      return "damaged_tail_truncated";
    case RecoveryClassification::RefusedCorrupt:
      return "refused_corrupt";
    case RecoveryClassification::IncompatibleVersion:
      return "incompatible_version";
    case RecoveryClassification::IncompatibleSemantics:
      return "incompatible_semantics";
    case RecoveryClassification::EmptyStore:
      return "empty_store";
    case RecoveryClassification::MemoryOnly:
      return "memory_only";
  }
  return "unknown_recovery_classification";
}

const char* to_string(ExportFormat value) noexcept {
  switch (value) {
    case ExportFormat::CanonicalJson:
      return "canonical_json";
    case ExportFormat::CanonicalText:
      return "canonical_text";
    case ExportFormat::CanonicalBinary:
      return "canonical_binary";
  }
  return "unknown_export_format";
}

bool parse_export_format(std::string_view token, ExportFormat& out) noexcept {
  if (token == "canonical_json" || token == "json") {
    out = ExportFormat::CanonicalJson;
  } else if (token == "canonical_text" || token == "text") {
    out = ExportFormat::CanonicalText;
  } else if (token == "canonical_binary" || token == "binary") {
    out = ExportFormat::CanonicalBinary;
  } else {
    return false;
  }
  return true;
}

const char* to_string(RecoveryPolicy value) noexcept {
  switch (value) {
    case RecoveryPolicy::Refuse:
      return "refuse";
    case RecoveryPolicy::TruncateTornTail:
      return "truncate_torn_tail";
    case RecoveryPolicy::TruncateDamagedTail:
      return "truncate_damaged_tail";
  }
  return "unknown_recovery_policy";
}

bool parse_recovery_policy(std::string_view token, RecoveryPolicy& out) noexcept {
  if (token == "refuse") {
    out = RecoveryPolicy::Refuse;
  } else if (token == "truncate_torn_tail") {
    out = RecoveryPolicy::TruncateTornTail;
  } else if (token == "truncate_damaged_tail") {
    out = RecoveryPolicy::TruncateDamagedTail;
  } else {
    return false;
  }
  return true;
}

}  // namespace nof
