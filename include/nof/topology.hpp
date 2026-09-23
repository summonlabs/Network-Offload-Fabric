#pragma once

#include <string>
#include <vector>

#include "nof/bounds.hpp"
#include "nof/error.hpp"
#include "nof/ids.hpp"
#include "nof/time.hpp"
#include "nof/units.hpp"

// Adjacent-runtime supplied topology. The fabric consumes topology; it never
// discovers devices, probes links, or computes routes.
namespace nof {

enum class DeviceKind : std::uint8_t {
  HostStack = 1,  // kernel / host networking stack: the explicit fallback plane
  Nic = 2,
  SmartNic = 3,
  Dpu = 4,
};

const char* to_string(DeviceKind value) noexcept;
bool parse_device_kind(std::string_view token, DeviceKind& out) noexcept;

// Offload planes are the accelerated kinds. HostStack is never an offload
// target: it is only reachable through an explicit fallback decision.
inline bool is_offload_kind(DeviceKind kind) noexcept { return kind != DeviceKind::HostStack; }

enum class LinkKind : std::uint8_t {
  PeerFabric = 1,  // device-to-device fabric adjacency
  HostAttach = 2,  // host-to-device attachment
};

const char* to_string(LinkKind value) noexcept;
bool parse_link_kind(std::string_view token, LinkKind& out) noexcept;

struct HostRecord {
  HostId id{};
  std::vector<std::string> labels{};  // canonical: sorted, unique

  friend bool operator==(const HostRecord&, const HostRecord&) = default;
};

struct DeviceRecord {
  DeviceId id{};
  HostId host{};
  DeviceKind kind = DeviceKind::Nic;
  IncarnationId incarnation{};
  CapacityVector capacity{};
  std::vector<std::string> labels{};  // canonical: sorted, unique
  bool decommissioned = false;

  friend bool operator==(const DeviceRecord&, const DeviceRecord&) = default;
};

struct LinkRecord {
  DeviceId a{};
  DeviceId b{};
  LinkKind kind = LinkKind::PeerFabric;

  friend bool operator==(const LinkRecord&, const LinkRecord&) = default;
  friend std::strong_ordering operator<=>(const LinkRecord&, const LinkRecord&) = default;
};

struct TopologySnapshot {
  TopologyGeneration generation{};
  Provenance provenance{};
  Freshness freshness{};
  std::vector<HostRecord> hosts{};
  std::vector<DeviceRecord> devices{};
  std::vector<LinkRecord> links{};

  const DeviceRecord* find_device(const DeviceId& id) const noexcept;
  const HostRecord* find_host(const HostId& id) const noexcept;
};

// Structural validation: canonical ordering, uniqueness, token validity,
// label validity, freshness sanity, and every declared bound. A snapshot that
// fails validation is refused whole; partial acceptance would silently create
// phantom targets.
Status validate_topology(const TopologySnapshot& snapshot, const Bounds& bounds);

// Canonical ordering normalization returning a refusal instead of silently
// reordering caller input that claims to be canonical.
Status check_canonical_order(const TopologySnapshot& snapshot);

extern const char* const kDeviceKindTokens[];
extern const char* const kLinkKindTokens[];

}  // namespace nof
