#pragma once

#include <vector>

#include "nof/bounds.hpp"
#include "nof/error.hpp"
#include "nof/function.hpp"
#include "nof/ids.hpp"
#include "nof/time.hpp"
#include "nof/topology.hpp"
#include "nof/units.hpp"

// Capability evidence: what an adjacent runtime asserts a specific device
// incarnation can do. Absence of a claim is UNKNOWN, never "unsupported" and
// never "supported".
namespace nof {

// Verdict of matching a function requirement against capability evidence.
enum class MatchVerdict : std::uint8_t {
  Eligible = 1,
  Unsupported = 2,
  Unknown = 3,
  Conflicting = 4,
  Stale = 5,
  Superseded = 6,
  VersionIncompatible = 7,
  IncarnationMismatch = 8,
  Revoked = 9,
  Missing = 10,
};

const char* to_string(MatchVerdict value) noexcept;

struct CapabilityRecord {
  DeviceId device{};
  IncarnationId incarnation{};
  FunctionClass cls = FunctionClass::RouteLookup;
  // Explicitly claimed support. Only these bits can satisfy a requirement.
  SemanticsMask supported{};
  // Explicitly denied semantics. A denial always wins over a claim.
  SemanticsMask unsupported{};
  // Explicitly unresolved semantics: distinct from both of the above.
  SemanticsMask unknown{};
  VersionRange version_range{};
  CapacityVector capacity{};
  SchemaGeneration schema{};
  CapabilityGeneration generation{};
  Provenance provenance{};
  Freshness freshness{};
  bool revoked = false;

  friend bool operator==(const CapabilityRecord&, const CapabilityRecord&) = default;
};

struct CapabilityReport {
  Provenance provenance{};
  Freshness freshness{};
  std::vector<CapabilityRecord> records{};

  const CapabilityRecord* find(const DeviceId& device, FunctionClass cls) const noexcept;
};

Status validate_capability_report(const CapabilityReport& report, const Bounds& bounds);

// Exact capability match. Every required semantic must be explicitly supported,
// no required semantic may be explicitly unsupported or explicitly unknown, the
// required version must fall inside the supported range, and the evidence must
// be current for the exact device incarnation.
struct CapabilityMatch {
  MatchVerdict verdict = MatchVerdict::Missing;
  ReasonCode reason = ReasonCode::EvidenceMissing;
  SemanticsMask unsatisfied{};   // required but not explicitly supported
  SemanticsMask denied{};        // required but explicitly unsupported
  SemanticsMask unresolved{};    // required but explicitly unknown

  bool eligible() const noexcept { return verdict == MatchVerdict::Eligible; }
};

CapabilityMatch match_capability(const FunctionDescriptor& function, const CapabilityRecord& record,
                                 const IncarnationId& expected_incarnation, Micros now);

// True when the two records disagree about semantics, version range, or
// capacity for the same (device, incarnation, function class) key.
bool capability_records_conflict(const CapabilityRecord& a, const CapabilityRecord& b) noexcept;

}  // namespace nof
