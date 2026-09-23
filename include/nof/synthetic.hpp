#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "nof/authority.hpp"
#include "nof/capability.hpp"
#include "nof/fabric.hpp"
#include "nof/function.hpp"
#include "nof/observation.hpp"
#include "nof/policy.hpp"
#include "nof/topology.hpp"

// SYNTHETIC fixtures.
//
// Everything produced here is synthetic: device identities, capacities,
// capability claims, liveness observations, and authority grants are generated
// deterministically in this process. No switch, ASIC, NIC, SmartNIC, DPU, RDMA
// device, or vendor protocol is contacted, discovered, or validated. These
// fixtures exist so that the fabric's assignment logic, persistence, and
// transport can be exercised and demonstrated without hardware; they never
// constitute hardware validation, and any statement about real device behavior
// must come from the adjacent enforcement plane instead.
namespace nof::synthetic {

struct ScenarioOptions {
  std::size_t hosts = 2;
  std::uint64_t seed = 1;
  std::string source = "syn-source-1";
  std::uint64_t sequence_base = 1;
  // Zero means "use the current system time"; tests that inject a manual clock
  // set both values explicitly so the scenario stays deterministic.
  Micros observed_at = Micros::raw(0);
  Micros valid_until = Micros::raw(0);
  std::int64_t ttl_micros = 3600LL * 1000000LL;
  bool host_fallback_allowed = false;
  FunctionClass function_class = FunctionClass::RouteLookup;
  TopologyGeneration topology_generation = TopologyGeneration::from_validated(1);
  PolicyGeneration policy_generation = PolicyGeneration::from_validated(1);
  CapabilityGeneration capability_generation = CapabilityGeneration::from_validated(1);
  SchemaGeneration schema = SchemaGeneration::from_validated(1);
  std::size_t max_assignments_per_device = 64;
  std::uint64_t packets_per_second = 1000;
  std::uint64_t flows = 100;
  std::uint64_t memory_bytes = 4096;
};

struct Scenario {
  std::vector<FunctionDescriptor> functions{};
  TopologySnapshot topology{};
  PolicySnapshot policy{};
  CapabilityReport capabilities{};
  ObservationReport observations{};
  AuthorityGrant authority{};
  HostId first_host{};
  HostId second_host{};
  std::vector<DeviceId> dpu_devices{};
  std::vector<DeviceId> smartnic_devices{};
  std::vector<DeviceId> nic_devices{};
  std::vector<DeviceId> host_stack_devices{};
  FunctionId function{};
  ScopeSpec scope{};
};

// Builds a deterministic scenario. Device roles:
//   <host>-dpu      supports every required semantic (eligible offload target)
//   <host>-smartnic explicitly denies one required semantic (UNSUPPORTED)
//   <host>-nic      declares one required semantic explicitly unknown (UNKNOWN)
//   <host>-host     host stack: reachable only through explicit host fallback
Scenario make_scenario(const ScenarioOptions& options);

// A placement request that matches the scenario's function and scope.
PlacementRequest make_request(const Scenario& scenario, const ScenarioOptions& options,
                              const std::string& request_id, bool request_replacement = false);

// Freshness window shifted forward, used to model a later observation.
ObservationReport make_observations(const ScenarioOptions& options, const Scenario& scenario,
                                    std::uint64_t sequence, Micros observed_at,
                                    Liveness liveness, bool degrade_all = false);

}  // namespace nof::synthetic
