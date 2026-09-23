#include "nof/explanation.hpp"

#include <cstdio>

#include "nof/canonical.hpp"
#include "nof/wire.hpp"

namespace nof {

const char* to_string(Decision value) noexcept {
  switch (value) {
    case Decision::Accept:
      return "accept";
    case Decision::Refuse:
      return "refuse";
    case Decision::Replace:
      return "replace";
    case Decision::Revoke:
      return "revoke";
    case Decision::Defer:
      return "defer";
    case Decision::Suspend:
      return "suspend";
    case Decision::NoOp:
      return "noop";
  }
  return "unknown_decision";
}

bool parse_decision(std::string_view token, Decision& out) noexcept {
  if (token == "accept") {
    out = Decision::Accept;
  } else if (token == "refuse") {
    out = Decision::Refuse;
  } else if (token == "replace") {
    out = Decision::Replace;
  } else if (token == "revoke") {
    out = Decision::Revoke;
  } else if (token == "defer") {
    out = Decision::Defer;
  } else if (token == "suspend") {
    out = Decision::Suspend;
  } else if (token == "noop") {
    out = Decision::NoOp;
  } else {
    return false;
  }
  return true;
}

namespace {

void append_line(std::string& out, const char* key, const std::string& value) {
  out += key;
  out += "=";
  out += value;
  out += "\n";
}

void append_line(std::string& out, const char* key, std::uint64_t value) {
  append_line(out, key, std::to_string(value));
}

std::string scope_text(const ScopeSpec& spec) {
  std::string out(to_string(spec.kind));
  out += "/";
  out += spec.domain.empty() ? "-" : spec.domain.value();
  out += "/";
  out += spec.device.empty() ? "-" : spec.device.value();
  out += "/";
  out += spec.selector.empty() ? "-" : spec.selector;
  return out;
}

std::string generation_text(const GenerationBinding& binding) {
  std::string out;
  out += "topology=" + std::to_string(binding.topology.value());
  out += ",capability=" + std::to_string(binding.capability.value());
  out += ",policy=" + std::to_string(binding.policy.value());
  out += ",assignment=" + std::to_string(binding.assignment.value());
  out += ",schema=" + std::to_string(binding.schema.value());
  return out;
}

std::string incarnation_text(const IncarnationId& incarnation) {
  std::string out = std::to_string(incarnation.generation.value());
  out += "@";
  out += incarnation.boot.value();
  return out;
}

std::string semantics_text(const SemanticsMask& mask) {
  std::string out;
  bool first = true;
  for (const Semantic semantic : mask.values()) {
    if (!first) {
      out += "+";
    }
    out += to_string(semantic);
    first = false;
  }
  if (out.empty()) {
    out = "-";
  }
  return out;
}

}  // namespace

std::string render_explanation(const Explanation& explanation) {
  std::string out;
  out.reserve(1024);
  append_line(out, "decision", to_string(explanation.decision));
  append_line(out, "primary_reason", to_string(explanation.primary_reason));
  std::string reasons;
  for (const ReasonCode reason : explanation.reasons) {
    if (!reasons.empty()) {
      reasons += ",";
    }
    reasons += to_string(reason);
  }
  append_line(out, "reasons", reasons.empty() ? std::string("-") : reasons);
  append_line(out, "request_id", explanation.request_id.empty() ? std::string("-")
                                                               : explanation.request_id.value());
  append_line(out, "function", explanation.function.empty() ? std::string("-")
                                                            : explanation.function.value());
  append_line(out, "function_class", to_string(explanation.cls));
  append_line(out, "scope", scope_text(explanation.scope));
  append_line(out, "scope_id", explanation.scope_id.empty() ? std::string("-")
                                                            : explanation.scope_id.value());
  append_line(out, "exclusivity", to_string(explanation.exclusivity));
  append_line(out, "execution_mode", to_string(explanation.mode));
  append_line(out, "binding", generation_text(explanation.binding));
  append_line(out, "authority", explanation.authority.empty() ? std::string("-")
                                                              : explanation.authority.value());
  append_line(out, "lease", explanation.lease.value());
  append_line(out, "fence", std::to_string(explanation.fence.epoch) + ":" +
                                std::to_string(explanation.fence.sequence));
  append_line(out, "attempt", explanation.attempt.value());
  append_line(out, "assignment", explanation.assignment.empty() ? std::string("-")
                                                                : explanation.assignment.value());
  append_line(out, "replaced", explanation.replaced.empty() ? std::string("-")
                                                            : explanation.replaced.value());
  append_line(out, "selected_device", explanation.selected_device.empty()
                                          ? std::string("-")
                                          : explanation.selected_device.value());
  append_line(out, "candidates_total", explanation.candidates_total);
  append_line(out, "candidates_reported", static_cast<std::uint64_t>(explanation.candidates.size()));
  append_line(out, "candidates_truncated", explanation.candidates_truncated ? "true" : "false");
  append_line(out, "input_digest", explanation.input_digest.hex());
  append_line(out, "decision_digest", explanation.decision_digest.hex());
  for (const CandidateEvaluation& candidate : explanation.candidates) {
    out += "candidate device=";
    out += candidate.device.value();
    out += " host=";
    out += candidate.host.value();
    out += " kind=";
    out += to_string(candidate.kind);
    out += " incarnation=";
    out += incarnation_text(candidate.incarnation);
    out += " capability_generation=";
    out += std::to_string(candidate.capability_generation.value());
    out += " eligible=";
    out += candidate.eligible ? "true" : "false";
    out += " verdict=";
    out += to_string(candidate.verdict);
    out += " reason=";
    out += to_string(candidate.reason);
    out += " mode=";
    out += to_string(candidate.mode);
    out += " rank=";
    out += std::to_string(candidate.rank);
    out += " offload_rank=";
    out += std::to_string(candidate.offload_rank);
    out += " kind_rank=";
    out += std::to_string(candidate.kind_rank);
    out += " locality_rank=";
    out += std::to_string(candidate.locality_rank);
    out += " utilization_ppm=";
    out += std::to_string(candidate.utilization_ppm);
    out += " contributing=";
    for (std::size_t i = 0; i < candidate.contributing.size(); ++i) {
      if (i != 0) {
        out += "+";
      }
      out += to_string(candidate.contributing[i]);
    }
    out += " evaluation_digest=";
    out += candidate.evaluation_digest.hex();
    out += "\n";
  }
  return out;
}

Status explanation_to_json(const Explanation& explanation, std::string& out, std::size_t max_bytes) {
  using JsonValue = nof::JsonValue;
  JsonValue::Array reason_array;
  for (const ReasonCode reason : explanation.reasons) {
    reason_array.push_back(JsonValue::string(to_string(reason)));
  }
  JsonValue::Array candidate_array;
  for (const CandidateEvaluation& candidate : explanation.candidates) {
    JsonValue::Array contributing;
    for (const ReasonCode reason : candidate.contributing) {
      contributing.push_back(JsonValue::string(to_string(reason)));
    }
    auto contributing_value = JsonValue::array(std::move(contributing));
    if (!contributing_value) {
      return contributing_value.error();
    }
    auto candidate_object = JsonValue::object(
        {{"capability_generation", JsonValue::uinteger(candidate.capability_generation.value())},
         {"contributing", contributing_value.take()},
         {"device", JsonValue::string(candidate.device.value())},
         {"eligible", JsonValue::boolean(candidate.eligible)},
         {"evaluation_digest", JsonValue::string(candidate.evaluation_digest.hex())},
         {"host", JsonValue::string(candidate.host.value())},
         {"incarnation_boot", JsonValue::string(candidate.incarnation.boot.value())},
         {"incarnation_generation",
          JsonValue::uinteger(candidate.incarnation.generation.value())},
         {"kind", JsonValue::string(to_string(candidate.kind))},
         {"kind_rank", JsonValue::uinteger(candidate.kind_rank)},
         {"locality_rank", JsonValue::uinteger(candidate.locality_rank)},
         {"mode", JsonValue::string(to_string(candidate.mode))},
         {"offload_rank", JsonValue::uinteger(candidate.offload_rank)},
         {"rank", JsonValue::uinteger(candidate.rank)},
         {"reason", JsonValue::string(to_string(candidate.reason))},
         {"utilization_ppm", JsonValue::uinteger(candidate.utilization_ppm)},
         {"verdict", JsonValue::string(to_string(candidate.verdict))}});
    if (!candidate_object) {
      return candidate_object.error();
    }
    candidate_array.push_back(candidate_object.take());
  }
  auto candidates_value = JsonValue::array(std::move(candidate_array));
  if (!candidates_value) {
    return candidates_value.error();
  }
  auto reasons_value = JsonValue::array(std::move(reason_array));
  if (!reasons_value) {
    return reasons_value.error();
  }
  auto scope_object = JsonValue::object(
      {{"device", JsonValue::string(explanation.scope.device.value())},
       {"domain", JsonValue::string(explanation.scope.domain.value())},
       {"kind", JsonValue::string(to_string(explanation.scope.kind))},
       {"selector", JsonValue::string(explanation.scope.selector)}});
  if (!scope_object) {
    return scope_object.error();
  }
  auto binding_object = JsonValue::object(
      {{"assignment", JsonValue::uinteger(explanation.binding.assignment.value())},
       {"capability", JsonValue::uinteger(explanation.binding.capability.value())},
       {"policy", JsonValue::uinteger(explanation.binding.policy.value())},
       {"schema", JsonValue::uinteger(explanation.binding.schema.value())},
       {"topology", JsonValue::uinteger(explanation.binding.topology.value())}});
  if (!binding_object) {
    return binding_object.error();
  }
  auto document = JsonValue::object(
      {{"assignment", JsonValue::string(explanation.assignment.value())},
       {"attempt", JsonValue::uinteger(explanation.attempt.value())},
       {"authority", JsonValue::string(explanation.authority.value())},
       {"binding", binding_object.take()},
       {"candidate_count", JsonValue::uinteger(explanation.candidates_total)},
       {"candidates", candidates_value.take()},
       {"candidates_truncated", JsonValue::boolean(explanation.candidates_truncated)},
       {"decision", JsonValue::string(to_string(explanation.decision))},
       {"decision_digest", JsonValue::string(explanation.decision_digest.hex())},
       {"exclusivity", JsonValue::string(to_string(explanation.exclusivity))},
       {"execution_mode", JsonValue::string(to_string(explanation.mode))},
       {"fence_epoch", JsonValue::uinteger(explanation.fence.epoch)},
       {"fence_sequence", JsonValue::uinteger(explanation.fence.sequence)},
       {"function", JsonValue::string(explanation.function.value())},
       {"function_class", JsonValue::string(to_string(explanation.cls))},
       {"input_digest", JsonValue::string(explanation.input_digest.hex())},
       {"lease", JsonValue::uinteger(explanation.lease.value())},
       {"primary_reason", JsonValue::string(to_string(explanation.primary_reason))},
       {"reasons", reasons_value.take()},
       {"replaced", JsonValue::string(explanation.replaced.value())},
       {"request_id", JsonValue::string(explanation.request_id.value())},
       {"scope", scope_object.take()},
       {"scope_id", JsonValue::string(explanation.scope_id.value())},
       {"selected_device", JsonValue::string(explanation.selected_device.value())}});
  if (!document) {
    return document.error();
  }
  return document.value().dump(out, max_bytes);
}

}  // namespace nof
