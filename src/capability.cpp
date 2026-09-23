#include "nof/capability.hpp"

#include <algorithm>

namespace nof {

const char* to_string(MatchVerdict value) noexcept {
  switch (value) {
    case MatchVerdict::Eligible:
      return "eligible";
    case MatchVerdict::Unsupported:
      return "unsupported";
    case MatchVerdict::Unknown:
      return "unknown";
    case MatchVerdict::Conflicting:
      return "conflicting";
    case MatchVerdict::Stale:
      return "stale";
    case MatchVerdict::Superseded:
      return "superseded";
    case MatchVerdict::VersionIncompatible:
      return "version_incompatible";
    case MatchVerdict::IncarnationMismatch:
      return "incarnation_mismatch";
    case MatchVerdict::Revoked:
      return "revoked";
    case MatchVerdict::Missing:
      return "missing";
  }
  return "unknown_match_verdict";
}

const CapabilityRecord* CapabilityReport::find(const DeviceId& device, FunctionClass cls) const noexcept {
  for (const CapabilityRecord& record : records) {
    if (record.device == device && record.cls == cls) {
      return &record;
    }
  }
  return nullptr;
}

namespace {

Status check_record_freshness(const Freshness& freshness, const char* what) {
  if (freshness.observed_at.value() <= 0) {
    return Error(ReasonCode::MalformedInput, std::string(what) + " observation time is missing");
  }
  if (freshness.valid_until.value() <= freshness.observed_at.value()) {
    return Error(ReasonCode::MalformedInput,
                 std::string(what) + " validity interval is empty or inverted");
  }
  return ok_status();
}

}  // namespace

Status validate_capability_report(const CapabilityReport& report, const Bounds& bounds) {
  if (!report.provenance.is_set()) {
    return Error(ReasonCode::ProvenanceMismatch, "capability report provenance is unset");
  }
  Status status = check_record_freshness(report.freshness, "capability report");
  if (!status) {
    return status;
  }
  if (report.records.empty()) {
    return Error(ReasonCode::EmptyInput, "capability report carries no records");
  }
  if (report.records.size() > bounds.max_capability_records) {
    return Error(ReasonCode::LimitExceeded, "capability record count exceeds bound");
  }
  for (const CapabilityRecord& record : report.records) {
    if (record.device.empty()) {
      return Error(ReasonCode::InvalidIdentifier, "capability record has no device");
    }
    if (!record.incarnation.is_set()) {
      return Error(ReasonCode::IncarnationMismatch, "capability record incarnation is unset");
    }
    if (!record.generation.is_set()) {
      return Error(ReasonCode::OutOfRange, "capability record generation is unset");
    }
    if (!record.schema.is_set()) {
      return Error(ReasonCode::OutOfRange, "capability record schema generation is unset");
    }
    if (!record.provenance.is_set()) {
      return Error(ReasonCode::ProvenanceMismatch, "capability record provenance is unset");
    }
    status = check_record_freshness(record.freshness, "capability record");
    if (!status) {
      return status;
    }
    const std::uint64_t supported = record.supported.bits();
    const std::uint64_t unsupported = record.unsupported.bits();
    const std::uint64_t unknown = record.unknown.bits();
    if ((supported & unsupported) != 0 || (supported & unknown) != 0 ||
        (unsupported & unknown) != 0) {
      return Error(ReasonCode::SemanticsMismatch,
                   "capability record classifies a semantic in more than one bucket");
    }
    if (record.supported.count() > bounds.max_semantics_per_requirement * 4u) {
      return Error(ReasonCode::LimitExceeded, "capability record claims too many semantics");
    }
    if (record.version_range.maximum < record.version_range.minimum) {
      return Error(ReasonCode::MalformedInput, "capability version range is inverted");
    }
  }
  for (std::size_t i = 1; i < report.records.size(); ++i) {
    const CapabilityRecord& previous = report.records[i - 1];
    const CapabilityRecord& current = report.records[i];
    if (previous.device == current.device && previous.cls == current.cls) {
      return Error(ReasonCode::DuplicateIdentity,
                   "capability report repeats a device and function class");
    }
    if (current.device < previous.device ||
        (current.device == previous.device && !(previous.cls < current.cls))) {
      return Error(ReasonCode::DuplicateIdentity,
                   "capability records must be ordered by device then function class");
    }
  }
  return ok_status();
}

CapabilityMatch match_capability(const FunctionDescriptor& function, const CapabilityRecord& record,
                                 const IncarnationId& expected_incarnation, Micros now) {
  CapabilityMatch match;
  if (record.revoked) {
    match.verdict = MatchVerdict::Revoked;
    match.reason = ReasonCode::CapabilityUnsupported;
    return match;
  }
  if (!(record.incarnation == expected_incarnation)) {
    match.verdict = MatchVerdict::IncarnationMismatch;
    match.reason = ReasonCode::IncarnationMismatch;
    return match;
  }
  if (record.freshness.is_expired(now)) {
    match.verdict = MatchVerdict::Stale;
    match.reason = ReasonCode::CapabilityStale;
    return match;
  }
  if (!record.version_range.admits(function.required_version)) {
    match.verdict = MatchVerdict::VersionIncompatible;
    match.reason = ReasonCode::CapabilityIncompatible;
    return match;
  }
  const SemanticsMask required = function.required;
  match.denied = required.intersection(record.unsupported);
  if (!match.denied.empty()) {
    match.verdict = MatchVerdict::Unsupported;
    match.reason = ReasonCode::CapabilityUnsupported;
    return match;
  }
  match.unresolved = required.intersection(record.unknown);
  if (!match.unresolved.empty()) {
    match.verdict = MatchVerdict::Unknown;
    match.reason = ReasonCode::CapabilityUnknown;
    return match;
  }
  // Silence is not support: a required semantic that is neither claimed nor
  // denied nor explicitly unknown remains unknown and never becomes eligible.
  match.unsatisfied = required.difference(record.supported);
  if (!match.unsatisfied.empty()) {
    match.verdict = MatchVerdict::Unknown;
    match.reason = ReasonCode::CapabilityUnknown;
    return match;
  }
  match.verdict = MatchVerdict::Eligible;
  match.reason = ReasonCode::Ok;
  return match;
}

bool capability_records_conflict(const CapabilityRecord& a, const CapabilityRecord& b) noexcept {
  if (!(a.device == b.device) || a.cls != b.cls) {
    return false;
  }
  return !(a.supported == b.supported) || !(a.unsupported == b.unsupported) ||
         !(a.unknown == b.unknown) || !(a.version_range == b.version_range) ||
         !(a.capacity == b.capacity) || a.revoked != b.revoked ||
         !(a.incarnation == b.incarnation);
}

}  // namespace nof
