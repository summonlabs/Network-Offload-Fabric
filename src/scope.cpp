#include "nof/scope.hpp"

#include <algorithm>

#include "nof/canonical.hpp"
#include "nof/digest.hpp"

namespace nof {

const char* to_string(ScopeKind value) noexcept {
  switch (value) {
    case ScopeKind::Flow:
      return "flow";
    case ScopeKind::Interface:
      return "interface";
    case ScopeKind::Host:
      return "host";
    case ScopeKind::Queue:
      return "queue";
    case ScopeKind::Global:
      return "global";
  }
  return "unknown_scope_kind";
}

bool parse_scope_kind(std::string_view token, ScopeKind& out) noexcept {
  if (token == "flow") {
    out = ScopeKind::Flow;
  } else if (token == "interface") {
    out = ScopeKind::Interface;
  } else if (token == "host") {
    out = ScopeKind::Host;
  } else if (token == "queue") {
    out = ScopeKind::Queue;
  } else if (token == "global") {
    out = ScopeKind::Global;
  } else {
    return false;
  }
  return true;
}

const char* to_string(ExclusiveKeyMode value) noexcept {
  switch (value) {
    case ExclusiveKeyMode::PerClass:
      return "per_class";
    case ExclusiveKeyMode::PerScope:
      return "per_scope";
  }
  return "unknown_exclusive_key_mode";
}

bool parse_exclusive_key_mode(std::string_view token, ExclusiveKeyMode& out) noexcept {
  if (token == "per_class") {
    out = ExclusiveKeyMode::PerClass;
  } else if (token == "per_scope") {
    out = ExclusiveKeyMode::PerScope;
  } else {
    return false;
  }
  return true;
}

Status ScopeSpec::validate() const {
  switch (kind) {
    case ScopeKind::Global:
      if (!domain.empty() || !device.empty() || !selector.empty()) {
        return Error(ReasonCode::MalformedInput,
                     "global scope must not carry a domain, device, or selector");
      }
      break;
    case ScopeKind::Host:
      if (domain.empty()) {
        return Error(ReasonCode::MalformedInput, "host scope requires a domain host");
      }
      if (!device.empty() || !selector.empty()) {
        return Error(ReasonCode::MalformedInput, "host scope must not carry a device or selector");
      }
      break;
    case ScopeKind::Interface:
    case ScopeKind::Queue:
      if (device.empty()) {
        return Error(ReasonCode::MalformedInput, "device-anchored scope requires a device");
      }
      if (selector.empty()) {
        return Error(ReasonCode::MalformedInput, "device-anchored scope requires a selector");
      }
      break;
    case ScopeKind::Flow:
      if (selector.empty()) {
        return Error(ReasonCode::MalformedInput, "flow scope requires a selector");
      }
      break;
  }
  if (!selector.empty() && !tokens::is_valid_selector(selector)) {
    return Error(ReasonCode::InvalidIdentifier, "scope selector is not canonical");
  }
  return ok_status();
}

Result<std::string> ScopeSpec::canonical_text() const {
  Status status = validate();
  if (!status) {
    return status.error();
  }
  const std::string text = std::string(to_string(kind)) + "|" + domain.value() + "|" +
                           device.value() + "|" + selector;
  return text;
}

Result<ScopeId> derive_scope_id(const ScopeSpec& spec) {
  auto text = spec.canonical_text();
  if (!text) {
    return text.error();
  }
  const Digest digest = sha256(text.value());
  std::string token = "sc-";
  token += digest.hex().substr(0, 16);
  return ScopeId::parse(token);
}

}  // namespace nof
