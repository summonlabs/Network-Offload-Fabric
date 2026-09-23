# Validation

## Builds

| Configuration | Compiler settings | Result |
| --- | --- | --- |
| Debug (MSVC 19.44, x64) | `/W4 /WX /permissive- /utf-8 /Zc:__cplusplus` | clean, all suites pass |
| Release (MSVC 19.44, x64) | `/W4 /WX /permissive- /utf-8 /Zc:__cplusplus` | clean, all suites pass |
| Debug + runtime checks | MSVC Debug adds `/RTC1` (stack frame, uninitialised variable, and conversion checks) | clean, all suites pass |
| AddressSanitizer | `-DNOF_ENABLE_ASAN=ON` | UNSUPPORTED in this environment (see below) |

AddressSanitizer is exposed as an opt-in build option (`-DNOF_ENABLE_ASAN=ON`,
which adds `/fsanitize=address`), but the MSVC installation used for this
closure does not include the ASan runtime component: linking fails with
`LNK1104: cannot open file 'clang_rt.asan_dynamic_runtime_thunk-x86_64.lib'`.
**No AddressSanitizer coverage is claimed for this repository.** Debug builds do
enable MSVC runtime checks (`/RTC1`), and they are part of every recorded run.
The option is kept so that a toolchain which ships the ASan runtime can enable it
without editing the build.

## Suites

```text
nof_tests [--filter=substring] [--list]
65 cases: core, evidence, placement, lifecycle, persistence, process, concurrency, property
```

No test uses a timeout or a sleep; hangs are defects. The process suite spawns
the real `nofd` and `nofctl` binaries, connects over real sockets on ephemeral
ports, and kills the coordinator with a real hard kill.

## Benchmarks

```text
nof_bench [--hosts N] [--placements N]
```

Every phase counts only completed operations and asserts completion, invariant
cleanliness, and a non-zero state fingerprint. Reported rates are completed work
per second, never enqueue latency.

## Packages

```text
cmake --install build --prefix stage
cmake -S examples/downstream -B build/downstream -DCMAKE_PREFIX_PATH=stage
```

The consumer uses only `find_package(nof 1.0 REQUIRED CONFIG)` and
`nof::nof`, and is compiled with its own `/W4 /WX /permissive-` settings to
show that no repository warning configuration leaks through the exported target.
`scripts/fresh_clone_closure.ps1` repeats configure, build, test, install, and
the downstream consumer from a fresh clone of the committed sources.

## REAL / SYNTHETIC / UNSUPPORTED

| Item | Status |
| --- | --- |
| Assignment, eligibility, exclusivity, fencing, persistence, transport logic | REAL -- implemented and exercised by the suites |
| Persistence format, CRC-32C, SHA-256, canonical encodings | REAL -- validated against published vectors and round-trip tests |
| Multi-process transport over real TCP sockets and real hard kills | REAL -- independent OS processes |
| Device identities, capacities, capability claims, observations, authority, effects used by tests, tools, benchmarks, and the downstream example | SYNTHETIC -- generated in-process by `nof::synthetic` |
| NIC, SmartNIC, DPU, switch, ASIC, RDMA, InfiniBand, NVLink, multi-host, CUDA behaviour | UNSUPPORTED -- not implemented, not contacted, not validated |
| Vendor drivers, firmware programming, hardware telemetry | UNSUPPORTED -- outside the boundary; owned by the enforcement plane |
| Sanitizer coverage on non-MSVC toolchains | UNSUPPORTED in this environment |

No hardware validation is claimed anywhere in this repository.

## Limitations

* Time is injected. The runtime never reads a clock behind the caller's back, so
  freshness depends entirely on the evidence the adjacent runtimes supply.
* Acceptance is deterministic given the same evidence, policy, and time.
  Identifier and token issuance follows operation-completion order, so parallel
  submissions of the same workload accept the same decisions but do not produce
  identical identifiers.
* A policy generation change suspends live assignments until they are
  re-authorized; this is deliberate and strict.
* The reassignment budget is bounded per scope and time window; exhausted
  budgets refuse replacement and are counted.
* The service protocol is synchronous request/response with bounded payloads; it
  has no streaming, batching, or compression.
* The fabric trusts an admitted grant. It verifies scope, class, kind, action,
  generation, freshness, expiry, ceiling, and budget, but it does not implement
  cryptographic signatures over grants.
