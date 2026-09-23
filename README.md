# Network Offload Fabric

Vendor-neutral C++20 runtime that owns network-wide **assignment of forwarding
and offload functions** across host networking, NICs, SmartNICs, and DPUs.

The fabric decides *where an eligible function should execute*, binds that
decision to exact generations of evidence, authorizes it against an explicit
grant, fences it so that no two coordinators can both act, records it durably,
and explains it in canonical machine-readable form. It does not program
hardware.

```text
   adjacent runtimes                     Network Offload Fabric                enforcement plane
   ------------------                     ------------------------              -----------------
   topology --------\                     eligibility -> placement              hardware programming
   capability -------\                    exclusivity -> authorization   --->   device drivers
   policy ------------ >  evidence  --->   lease/attempt/fence issuance          firmware
   observations -----/                     durable commit + recovery      <---   effect reports
   authority --------/                     canonical explanation/export          (applied/rejected)
```

## Systems boundary

Owned here: assignment intent and authority for eligible forwarding and offload
functions -- candidate eligibility, exact capability matching, deterministic
placement, conflict resolution, bounded reassignment, durable fencing,
persistence and restart recovery, canonical explanations, and an inspection
surface.

Explicitly **not** owned here: packet forwarding, route computation, congestion
control, firmware, vendor drivers, telemetry collection, hardware discovery,
device liveness probing, or any service-specific business logic. Those belong to
adjacent runtimes and to the enforcement plane. The fabric consumes their
evidence and reports intent; it never executes an offload itself.

## Build

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release      # Debug and Release are both validated
cmake --build build
cd build/tests; ./nof_tests.exe                     # 65 cases, no timeouts, no sleeps
```

First-party code is compiled with `/W4 /WX /permissive- /utf-8` on MSVC and
`-Wall -Wextra -Wpedantic -Werror` elsewhere. Warnings are configured as
`PRIVATE` target options, so nothing leaks into a consuming project.

## Use

```cpp
#include <nof/fabric.hpp>

nof::FabricConfig config;
config.store_path = "fabric.nofjournal";     // empty means memory-only
nof::Fabric fabric(std::move(config));
fabric.start();                               // opens, replays, advances the epoch

fabric.ingest_policy(policy);                 // evidence from adjacent runtimes
fabric.ingest_topology(topology);
fabric.ingest_capabilities(capabilities);
fabric.ingest_observations(observations);
fabric.grant_authority(grant);                // authorization, not a recommendation

auto planned = fabric.plan(request);          // a recommendation: nothing is assigned
nof::ApplyOptions options;
options.request_id = request.request_id;      // idempotency key
auto assignment = fabric.apply(request, options);   // authorization + dispatch

nof::EffectReport effect;                     // from the enforcement plane
effect.outcome = nof::EffectOutcome::Applied; // only this verifies an application
fabric.report_effect(effect);
```

Installed package:

```cmake
find_package(nof 1.0 REQUIRED CONFIG)
target_link_libraries(app PRIVATE nof::nof)
```

Validated from an independent project in `examples/downstream` with
`scripts/validate_downstream.ps1` and from a fresh clone with
`scripts/fresh_clone_closure.ps1`.

## Tooling

```text
nofctl version | inspect | export | verify | digest | scenario | crash | stats | invariants | recovery | assignment | explain
nofd   --store PATH [--bind ADDR] [--port N] [--seed]     framed protocol over real sockets
```

`nofctl scenario --clock-at 1500000 --store s.nofjournal --applies 3` runs a
deterministic synthetic workload. `nofctl crash --boundary
after_commit_before_ack` terminates the process at a durable boundary so crash
recovery can be proven with real processes.

## Core model

* **Typed identities**: function, governed scope, host, device, device
  incarnation, capability/topology/policy/assignment/schema generation,
  coordinator epoch and boot, attempt, lease, fencing token, request, source,
  authority, store. Semantic values are enumerations with stable numeric
  values, never strings. Quantities are typed (`PacketRate`, `FlowCount`,
  `ByteSize`, `Micros`) with checked arithmetic.
* **Explicit uncertainty**: capability semantics are classified as supported,
  unsupported, or unknown. Silence is *unknown*, never support and never a
  denial. Missing evidence never becomes false, zero, or success.
* **Exact matching**: a required semantic is satisfied only by an explicit
  support claim for the exact device incarnation, inside the supported version
  range, with current evidence. No inference from device kind or naming.
* **Authority**: placement requires an explicit, current, in-scope grant bound
  to the current policy generation. A recommendation is not an authorization.
* **Fencing**: every assignment carries an attempt, a lease, and a fencing token
  ordered by `(epoch, sequence)`; epochs advance on every start, so a token
  from a previous process lifetime can never dominate a current one.
* **Lifecycle**: `planned -> authorized -> dispatched -> acknowledged ->
  applied_verified`, plus `degraded`, `suspended`, `revoked`,
  `superseded`, `rejected`, `failed`. Acknowledgement is reception; only a
  verified `applied` report is an application.
* **Exclusivity**: at most one assignment holds exclusive authority over a
  governed scope and function class. Claims are indexed per class and
  whole-scope; a whole-scope claim conflicts with every per-class claim on that
  scope.

## Determinism

Accepted state is a deterministic function of accepted evidence, policy, and
injected time. All iteration over state uses ordered containers, candidate
ranking is a documented integer tuple, ties break on the device identifier,
refusal reasons are chosen by the best-ranked refused target, and canonical
exports and explanations are byte-stable. Identifiers and tokens are issued in
operation-completion order, so two *concurrent* submissions of the same workload
have the same accepted decisions but not the same identifiers; the concurrency
suite asserts the decision-level equality.

## Proof and validation

The repository ships 65 test cases across unit, evidence, placement, lifecycle,
persistence, process, concurrency, and property suites; see
[docs/validation.md](docs/validation.md) for the exact commands and results, and
[docs/proof-obligations.md](docs/proof-obligations.md) for the mapping from each
required proof obligation to the test that discharges it.

Real hardware is not claimed anywhere. All devices, capacities, capabilities,
observations, and effects used by the tests, tools, benchmarks, and the
downstream example are **SYNTHETIC** fixtures generated in-process; no NIC,
SmartNIC, DPU, switch, ASIC, RDMA, or vendor protocol is contacted, discovered,
or validated. See [docs/validation.md](docs/validation.md).

## Documentation

* [docs/architecture.md](docs/architecture.md) -- state model, eligibility, placement, lifecycle, persistence, concurrency, locking.
* [docs/protocol.md](docs/protocol.md) -- framed transport, opcodes, bounds, CLI.
* [docs/proof-obligations.md](docs/proof-obligations.md) -- obligation to test mapping.
* [docs/validation.md](docs/validation.md) -- builds, suites, benchmarks, packaging, REAL/SYNTHETIC/UNSUPPORTED.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
