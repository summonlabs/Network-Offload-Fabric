#pragma once

#include <string>
#include <string_view>

#include "nof/error.hpp"
#include "nof/function.hpp"
#include "nof/ids.hpp"
#include "nof/units.hpp"

// Governed scope: the region of the network over which an assignment claims
// authority. Scope identity is derived canonically from the scope spec, so two
// spellings that denote the same region produce the same ScopeId and can never
// both hold exclusive authority.
namespace nof {

enum class ScopeKind : std::uint8_t {
  Flow = 1,       // a canonical flow selector
  Interface = 2,  // one interface / port
  Host = 3,       // one host's networking as a whole
  Queue = 4,      // one hardware queue / descriptor ring
  Global = 5,     // network-wide
};

const char* to_string(ScopeKind value) noexcept;
bool parse_scope_kind(std::string_view token, ScopeKind& out) noexcept;

// How exclusivity keys are derived. PerClass keeps two different function
// families from blocking each other on the same selector; PerScope makes the
// whole governed scope single-owner regardless of function family.
enum class ExclusiveKeyMode : std::uint8_t {
  PerClass = 1,
  PerScope = 2,
};

const char* to_string(ExclusiveKeyMode value) noexcept;
bool parse_exclusive_key_mode(std::string_view token, ExclusiveKeyMode& out) noexcept;

struct ScopeSpec {
  ScopeKind kind = ScopeKind::Flow;
  // Domain the scope belongs to. Required for every kind except Global.
  HostId domain{};
  // Optional device anchor, for Interface and Queue scopes.
  DeviceId device{};
  // Canonical selector text; required for Flow and Queue scopes.
  std::string selector{};

  friend bool operator==(const ScopeSpec&, const ScopeSpec&) = default;

  Status validate() const;
  // Canonical binary encoding, used for scope identity derivation.
  Result<std::string> canonical_text() const;
};

// Deterministic scope identity: "sc-" followed by the first 16 hex characters
// of SHA-256 over the canonical scope encoding. Collisions across distinct
// specs are possible in principle; the fabric therefore also stores the full
// spec and refuses an id that does not re-derive from the stored spec.
Result<ScopeId> derive_scope_id(const ScopeSpec& spec);

// Exclusivity key: (governed scope, function class) by default.
struct ExclusivityKey {
  ScopeId scope{};
  FunctionClass cls = FunctionClass::RouteLookup;

  friend bool operator==(const ExclusivityKey&, const ExclusivityKey&) = default;
  friend std::strong_ordering operator<=>(const ExclusivityKey&, const ExclusivityKey&) = default;
};

}  // namespace nof
