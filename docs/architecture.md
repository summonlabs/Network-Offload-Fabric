# Architecture

## 1. Boundary

The runtime owns assignment intent and authority. It receives evidence from
adjacent runtimes (topology, capability, policy, observations, authority) and
returns assignment intent plus explanations. Hardware programming belongs to the
enforcement plane, which reports effects back. No packet forwarding, route
computation, congestion control, firmware, driver, or telemetry code exists in
this repository.

## 2. State model

```text
FunctionDescriptor   function identity, class, required semantics, required version
ScopeSpec            governed scope: kind (flow/interface/host/queue/global), domain, device, selector
ScopeId              derived: "sc-" + first 16 hex of SHA-256 over the canonical scope encoding
HostRecord/DeviceRecord   device identity, kind (host_stack/nic/smart_nic/dpu), incarnation, capacity, labels
IncarnationId        (incarnation generation, boot id) -- a device reboot is a new incarnation
CapabilityRecord     per (device, function class): supported/unsupported/unknown semantics, version
                     range, capacity, schema generation, capability generation, provenance, freshness
PolicySnapshot       generation, rules per function class, allowed device kinds, exclusivity key mode,
                     host-fallback permission, reassignment budget, per-device ceiling
AuthorityGrant       policy generation binding, classes, kinds, actions, host scope, scope, semantics
                     ceiling, issue/expiry, freshness, revocation, use budget
DeviceObservation    liveness (unknown/alive/degraded/dead), available capacity, freshness, provenance
AssignmentRecord     id, assignment generation, function, scope, exclusivity, mode, lifecycle state,
                     target (device, host, kind, incarnation), generation binding, authority, lease,
                     attempt, fencing token, provenance, freshness, bounded history and effects
```

Every generation domain is a distinct type, so a topology generation cannot be
compared with a policy generation, and generation value zero means "unset" and is
never current. Provenance is `(source, sequence)` per evidence domain; sequence
zero means "no evidence".

## 3. Eligibility and placement

For a placement request the fabric:

1. validates the request, the scope specification, and the function identity;
2. refuses if topology or policy evidence is absent, superseded by a restart
   floor, or expired;
3. unites the registered function requirement with the request requirement and
   the policy requirement;
4. evaluates every device in the topology in canonical identifier order
   (bounded by `max_candidates_per_plan`), producing a verdict and an exact
   reason for each;
5. ranks eligible candidates by
   `(offload_rank, kind_rank, locality_rank, utilization_ppm, device id)`
   where offload before host fallback, `dpu < smart_nic < nic < host_stack`,
   locality prefers the scope's domain host and then preferred hosts, and
   utilization is integer parts-per-million of committed demand;
6. returns a plan bound to the exact topology, capability, policy, schema and
   assignment generations, plus the authority grant that makes it legal.

Refusals are explicit and typed: an explicitly denied semantic is
`CAPABILITY_UNSUPPORTED`; a semantic that is neither claimed nor denied nor
explicitly unknown is `CAPABILITY_UNKNOWN`; an incompatible version is
`CAPABILITY_INCOMPATIBLE`; stale evidence is `EVIDENCE_STALE` or
`EVIDENCE_SUPERSEDED`; a device that is not alive is refused with the exact
liveness reason. When nothing is eligible, the explanation's primary reason is
the reason of the best-ranked refused target, and every candidate's own verdict
is preserved.

Policy can permit host fallback; a request must also opt in. A host-stack
placement is recorded with `execution_mode = host_fallback`, claims no
capability generation, and reports `HOST_FALLBACK_APPLIED`, so degraded
execution is always explicit.

## 4. Authority

Placement, replacement, revocation, and re-authorization each require an
admitting grant. A grant is admitted only when: it is not revoked; it is bound
to the current policy generation; it has not expired; its freshness window is
current; its use budget is not exhausted; it lists the requested action, class,
and device kind; its host and scope selectors match; and the required semantics
are inside its semantics ceiling. Authority use counters are derived from the
live assignments that reference the grant, never typed in by hand.

## 5. Lifecycle

```text
planned -> authorized -> dispatched -> acknowledged -> applied_verified
                    \-> degraded (target impaired, authority retained)
                    \-> suspended (evidence/authority lost, authority released)
                    \-> rejected / failed (terminal)
                    \-> revoked / superseded (terminal, claim released)
```

* `apply` performs authorization and dispatch; the record is durable before the
  caller sees it.
* An effect report is accepted only when the attempt, assignment generation,
  device incarnation, capability generation, and fencing token match the record
  exactly and the token's epoch is current. Anything else is
  `FENCED_ATTEMPT`, `ATTEMPT_MISMATCH`, `GENERATION_MISMATCH`,
  `INCARNATION_MISMATCH`, or `EPOCH_STALE`, and the assignment is unchanged.
* `acknowledged` is reachable only through an explicit acknowledgement outcome;
  `applied_verified` requires an explicit applied outcome.
* Duplicate delivery of an identical request returns the identical result;
  a reused request identifier with a different payload is
  `DUPLICATE_DELIVERY`.
* Revalidation runs after every evidence change and suspends any live
  assignment whose target disappeared, whose incarnation changed, whose
  capability, topology, or policy generation moved, whose authority was
  withdrawn or expired, or whose observation window lapsed.

## 6. Persistence

```text
<store>            64-byte header (magic NOFJ, format version, canonical version, store id, CRC)
                   followed by records: length, type, flags, sequence, payload, CRC-32C
<store>.snapshot   atomically replaced state snapshot used to bound growth
```

* Appends are complete before they are acknowledged: a record is written, flushed
  and fsynced (configurable, and observable through the statistics).
* The snapshot payload is the canonical encoding of the complete state plus its
  fingerprint, and the snapshot records the sequence it covers, so replay skips
  records it already contains. Compaction installs the snapshot atomically, then
  replaces the journal atomically; a crash between the two is recovered
  consistently in either order.
* Recovery is classified explicitly: `fresh_store`, `empty_store`,
  `clean_reopen`, `torn_tail_truncated`, `damaged_tail_truncated`,
  `refused_corrupt`, `incompatible_version`, `incompatible_semantics`,
  `memory_only`. Damage is never silently accepted; the default recovery policy
  refuses.
* Provenance high-water marks are durable: every accepted evidence record
  restores its `(source, sequence, digest)` mark during replay, so a replayed
  pre-restart sequence is refused as a regression even when no snapshot exists.
* Restart is conservative: the epoch advances, every reference to a pre-restart
  lease or fence becomes stale, all observations are invalidated, every grant
  and every piece of evidence is placed below a restart floor, and every live
  assignment is suspended with `RESTART_AUTHORITY_RESET`. Nothing is
  resurrected, and re-authorization requires current evidence.

## 7. Concurrency, locking, and shutdown

* One mutex serializes fabric operations; the store has its own mutex and is
  only ever acquired after the state mutex, never before. There are no callbacks
  under a lock, no nested state locks, and no lock is held while a thread is
  joined.
* The service keeps a bounded worker pool and a bounded connection queue. Each
  connection is owned by exactly one worker; the connection registry is a leaf
  lock and is released before sockets are shut down.
* Shutdown order: stop accepting, wake the acceptor through a local datagram
  socket (no polling, no timeouts), cancel the in-flight token, shut down the
  live sockets so blocked reads return, join the acceptor and workers, drain the
  queue, then close the listener and the fabric.
* Cancellation is honoured before the durable commit point. A cancelled
  operation reports `CANCELLED` and publishes nothing; an operation that already
  committed reports the committed outcome instead of pretending otherwise.

## 8. Determinism and canonical representations

Canonical binary encoding is little-endian with length-prefixed byte strings and
explicit presence markers. Canonical JSON is integers only, ASCII only, with
sorted keys and duplicate keys refused. Binary and JSON documents are bounded
before they are produced, and an over-bound document is refused rather than
truncated. State fingerprints are SHA-256 over the canonical state encoding;
journal records and protocol frames are guarded by CRC-32C. Both primitives are
implemented in-house and validated against published test vectors.
