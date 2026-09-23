#pragma once

#include <vector>

#include "nof/bounds.hpp"
#include "nof/error.hpp"
#include "nof/ids.hpp"
#include "nof/time.hpp"
#include "nof/topology.hpp"
#include "nof/units.hpp"

// Observations are the adjacent runtime's view of liveness and available
// headroom. They are dynamic evidence: they expire, and a restart never
// resurrects them.
namespace nof {

enum class Liveness : std::uint8_t {
  Unknown = 0,
  Alive = 1,
  Degraded = 2,
  Dead = 3,
};

const char* to_string(Liveness value) noexcept;
bool parse_liveness(std::string_view token, Liveness& out) noexcept;

struct DeviceObservation {
  DeviceId device{};
  IncarnationId incarnation{};
  Liveness liveness = Liveness::Unknown;
  CapacityVector available{};
  bool available_known = false;
  Freshness freshness{};
  Provenance provenance{};

  friend bool operator==(const DeviceObservation&, const DeviceObservation&) = default;
};

struct ObservationReport {
  TopologyGeneration topology_generation{};
  Provenance provenance{};
  Freshness freshness{};
  std::vector<DeviceObservation> devices{};

  const DeviceObservation* find(const DeviceId& device) const noexcept;
};

Status validate_observation_report(const ObservationReport& report, const Bounds& bounds);

}  // namespace nof
