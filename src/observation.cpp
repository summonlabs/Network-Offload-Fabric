#include "nof/observation.hpp"

#include <algorithm>

namespace nof {

const char* to_string(Liveness value) noexcept {
  switch (value) {
    case Liveness::Unknown:
      return "unknown";
    case Liveness::Alive:
      return "alive";
    case Liveness::Degraded:
      return "degraded";
    case Liveness::Dead:
      return "dead";
  }
  return "unknown_liveness";
}

bool parse_liveness(std::string_view token, Liveness& out) noexcept {
  if (token == "unknown") {
    out = Liveness::Unknown;
  } else if (token == "alive") {
    out = Liveness::Alive;
  } else if (token == "degraded") {
    out = Liveness::Degraded;
  } else if (token == "dead") {
    out = Liveness::Dead;
  } else {
    return false;
  }
  return true;
}

const DeviceObservation* ObservationReport::find(const DeviceId& device) const noexcept {
  const auto it = std::lower_bound(
      devices.begin(), devices.end(), device,
      [](const DeviceObservation& observation, const DeviceId& key) {
        return observation.device < key;
      });
  if (it == devices.end() || !(it->device == device)) {
    return nullptr;
  }
  return &*it;
}

Status validate_observation_report(const ObservationReport& report, const Bounds& bounds) {
  if (!report.topology_generation.is_set()) {
    return Error(ReasonCode::TopologyStale, "observation report carries no topology generation");
  }
  if (!report.provenance.is_set()) {
    return Error(ReasonCode::ProvenanceMismatch, "observation report provenance is unset");
  }
  if (report.freshness.observed_at.value() <= 0 ||
      report.freshness.valid_until.value() <= report.freshness.observed_at.value()) {
    return Error(ReasonCode::MalformedInput, "observation report freshness is not usable");
  }
  if (report.devices.empty()) {
    return Error(ReasonCode::EmptyInput, "observation report carries no device observations");
  }
  if (report.devices.size() > bounds.max_observations) {
    return Error(ReasonCode::LimitExceeded, "observation count exceeds bound");
  }
  for (std::size_t i = 0; i < report.devices.size(); ++i) {
    const DeviceObservation& observation = report.devices[i];
    if (observation.device.empty()) {
      return Error(ReasonCode::InvalidIdentifier, "observation has no device");
    }
    if (!observation.incarnation.is_set()) {
      return Error(ReasonCode::IncarnationMismatch, "observation incarnation is unset");
    }
    if (!observation.provenance.is_set()) {
      return Error(ReasonCode::ProvenanceMismatch, "observation provenance is unset");
    }
    if (observation.freshness.observed_at.value() <= 0 ||
        observation.freshness.valid_until.value() <= observation.freshness.observed_at.value()) {
      return Error(ReasonCode::MalformedInput, "observation freshness is not usable");
    }
    if (i > 0 && !(report.devices[i - 1].device < observation.device)) {
      return Error(ReasonCode::DuplicateIdentity,
                   "observations must be sorted by device without duplicates");
    }
  }
  return ok_status();
}

}  // namespace nof
