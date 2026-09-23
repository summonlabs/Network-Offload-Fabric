#include "nof/topology.hpp"

#include <algorithm>

namespace nof {

const char* to_string(DeviceKind value) noexcept {
  switch (value) {
    case DeviceKind::HostStack:
      return "host_stack";
    case DeviceKind::Nic:
      return "nic";
    case DeviceKind::SmartNic:
      return "smart_nic";
    case DeviceKind::Dpu:
      return "dpu";
  }
  return "unknown_device_kind";
}

bool parse_device_kind(std::string_view token, DeviceKind& out) noexcept {
  if (token == "host_stack") {
    out = DeviceKind::HostStack;
  } else if (token == "nic") {
    out = DeviceKind::Nic;
  } else if (token == "smart_nic") {
    out = DeviceKind::SmartNic;
  } else if (token == "dpu") {
    out = DeviceKind::Dpu;
  } else {
    return false;
  }
  return true;
}

const char* to_string(LinkKind value) noexcept {
  switch (value) {
    case LinkKind::PeerFabric:
      return "peer_fabric";
    case LinkKind::HostAttach:
      return "host_attach";
  }
  return "unknown_link_kind";
}

bool parse_link_kind(std::string_view token, LinkKind& out) noexcept {
  if (token == "peer_fabric") {
    out = LinkKind::PeerFabric;
  } else if (token == "host_attach") {
    out = LinkKind::HostAttach;
  } else {
    return false;
  }
  return true;
}

const DeviceRecord* TopologySnapshot::find_device(const DeviceId& id) const noexcept {
  const auto it = std::lower_bound(
      devices.begin(), devices.end(), id,
      [](const DeviceRecord& record, const DeviceId& key) { return record.id < key; });
  if (it == devices.end() || !(it->id == id)) {
    return nullptr;
  }
  return &*it;
}

const HostRecord* TopologySnapshot::find_host(const HostId& id) const noexcept {
  const auto it = std::lower_bound(
      hosts.begin(), hosts.end(), id,
      [](const HostRecord& record, const HostId& key) { return record.id < key; });
  if (it == hosts.end() || !(it->id == id)) {
    return nullptr;
  }
  return &*it;
}

namespace {

Status check_labels(const std::vector<std::string>& labels, const char* field) {
  std::string previous;
  for (const std::string& label : labels) {
    if (!tokens::is_valid_token(label)) {
      return Error(ReasonCode::InvalidIdentifier,
                   std::string(field) + " label is not a canonical token: " + label);
    }
    if (!previous.empty() && !(previous < label)) {
      return Error(ReasonCode::DuplicateIdentity,
                   std::string(field) + " labels must be sorted and unique");
    }
    previous = label;
  }
  return ok_status();
}

Status check_freshness(const Freshness& freshness, const char* field) {
  if (freshness.observed_at.value() <= 0) {
    return Error(ReasonCode::MalformedInput, std::string(field) + " observation time is missing");
  }
  if (freshness.valid_until.value() <= freshness.observed_at.value()) {
    return Error(ReasonCode::MalformedInput,
                 std::string(field) + " validity interval is empty or inverted");
  }
  return ok_status();
}

}  // namespace

Status check_canonical_order(const TopologySnapshot& snapshot) {
  for (std::size_t i = 1; i < snapshot.hosts.size(); ++i) {
    if (!(snapshot.hosts[i - 1].id < snapshot.hosts[i].id)) {
      return Error(ReasonCode::DuplicateIdentity,
                   "hosts must be sorted by identifier without duplicates");
    }
  }
  for (std::size_t i = 1; i < snapshot.devices.size(); ++i) {
    if (!(snapshot.devices[i - 1].id < snapshot.devices[i].id)) {
      return Error(ReasonCode::DuplicateIdentity,
                   "devices must be sorted by identifier without duplicates");
    }
  }
  for (std::size_t i = 1; i < snapshot.links.size(); ++i) {
    if (!(snapshot.links[i - 1] < snapshot.links[i])) {
      return Error(ReasonCode::DuplicateIdentity,
                   "links must be sorted by endpoints without duplicates");
    }
  }
  return ok_status();
}

Status validate_topology(const TopologySnapshot& snapshot, const Bounds& bounds) {
  Status status = validate_bounds(bounds);
  if (!status) {
    return status;
  }
  if (!snapshot.generation.is_set()) {
    return Error(ReasonCode::OutOfRange, "topology generation is unset");
  }
  if (!snapshot.provenance.is_set()) {
    return Error(ReasonCode::ProvenanceMismatch, "topology provenance is unset");
  }
  status = check_freshness(snapshot.freshness, "topology");
  if (!status) {
    return status;
  }
  if (snapshot.hosts.empty()) {
    return Error(ReasonCode::EmptyInput, "topology carries no hosts");
  }
  if (snapshot.hosts.size() > bounds.max_hosts) {
    return Error(ReasonCode::LimitExceeded, "topology host count exceeds bound");
  }
  if (snapshot.devices.size() > bounds.max_devices) {
    return Error(ReasonCode::LimitExceeded, "topology device count exceeds bound");
  }
  if (snapshot.links.size() > bounds.max_devices * 8u) {
    return Error(ReasonCode::LimitExceeded, "topology link count exceeds bound");
  }
  status = check_canonical_order(snapshot);
  if (!status) {
    return status;
  }
  for (const HostRecord& host : snapshot.hosts) {
    if (host.id.empty()) {
      return Error(ReasonCode::InvalidIdentifier, "host identifier is empty");
    }
    status = check_labels(host.labels, "host");
    if (!status) {
      return status;
    }
  }
  for (const DeviceRecord& device : snapshot.devices) {
    if (device.id.empty()) {
      return Error(ReasonCode::InvalidIdentifier, "device identifier is empty");
    }
    if (device.host.empty()) {
      return Error(ReasonCode::MalformedInput, "device carries no host");
    }
    if (snapshot.find_host(device.host) == nullptr) {
      return Error(ReasonCode::UnknownIdentity,
                   "device references an unknown host: " + device.host.value());
    }
    if (!device.incarnation.is_set()) {
      return Error(ReasonCode::IncarnationMismatch, "device incarnation is unset");
    }
    status = check_labels(device.labels, "device");
    if (!status) {
      return status;
    }
  }
  for (const LinkRecord& link : snapshot.links) {
    if (link.a == link.b) {
      return Error(ReasonCode::MalformedInput, "link endpoints must differ");
    }
    if (snapshot.find_device(link.a) == nullptr || snapshot.find_device(link.b) == nullptr) {
      return Error(ReasonCode::UnknownIdentity, "link references an unknown device");
    }
  }
  return ok_status();
}

const char* const kDeviceKindTokens[] = {"host_stack", "nic", "smart_nic", "dpu"};
const char* const kLinkKindTokens[] = {"peer_fabric", "host_attach"};

}  // namespace nof
