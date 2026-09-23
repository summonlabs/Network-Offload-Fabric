# Service protocol and tooling

## Transport

The coordinator service (`nofd`) speaks a framed, bounded protocol over TCP.
Frames are length-prefixed and integrity-checked:

```text
offset 0   magic "NF"            u16, 0x4E46
offset 2   protocol version      u16, currently 1
offset 4   opcode                u16
offset 6   flags                 u16, bit 0 = error response
offset 8   request id            u64
offset 16  payload length        u32, bounded by max_frame_bytes
offset 20  payload               bytes
end - 4    CRC-32C over everything before it
```

The framing decoder refuses a frame whose declared length exceeds the bound
*before* reading the payload, refuses a corrupt checksum, refuses a partial frame
at end of stream, and treats an unimplemented opcode as a request that is
answered with an error rather than a dropped connection. Payloads are decoded
exactly: trailing bytes are a refusal.

## Opcodes

```text
1  hello                 10 withdraw_authority   19 list_assignments
2  ping                  11 report_effect         20 get_scope
3  stats                 12 plan                  21 explain_assignment
4  register_function     13 apply                 22 explain_request
5  ingest_topology       14 revoke                23 state_digest
6  ingest_capabilities   15 replace               24 export
7  ingest_policy         16 reauthorize           25 recovery_report
8  ingest_observations   17 revalidate            26 verify_invariants
9  grant_authority       18 get_assignment        27 compact
                                                   28 shutdown
```

Every request and response payload is the canonical binary encoding of the
corresponding domain object, so a value that travelled over the wire is
bit-identical to the value that was accepted durably.

## Idempotency and duplicates

A non-zero request identifier is cached with a digest of its payload and the
exact response bytes. A duplicate delivery of the identical request replays the
identical response instead of taking effect twice. A reused identifier with a
different payload is refused with `DUPLICATE_DELIVERY`. The cache is bounded;
evictions are counted in the statistics and in the recovery report.

## Bounded concurrency

`max_connections`, `max_workers`, and `max_queue_depth` bound the service.
A connection beyond the bound is refused and counted. A connection is served by
exactly one worker for its whole lifetime, so responses stay ordered per
connection while independent connections progress concurrently.

## Command line

```text
nofctl version
nofctl inspect  --store PATH [--format json|text]      recover and render canonical state
nofctl export   --store PATH --format json|text|binary
nofctl digest   --store PATH
nofctl verify   --store PATH                            header/record scan plus invariants
nofctl scenario --store PATH [--hosts N] [--applies N] [--clock-at MICROS]
                [--sequence-base N] [--policy-generation N] [--topology-generation N]
nofctl crash    --store PATH --boundary B [...]         crash at a durable boundary
nofctl stats|invariants|recovery|assignment --endpoint HOST:PORT [--id ID]
nofctl explain  --endpoint HOST:PORT --id ID

nofd --store PATH [--bind ADDR] [--port N] [--workers N] [--max-connections N]
     [--queue N] [--recovery MODE] [--no-durable] [--seed]
```

`--clock-at` injects a pinned logical clock so that a whole process run is
reproducible: the same evidence and the same time produce byte-identical state.

`--recovery` selects the recovery policy: `refuse` (default),
`truncate_torn_tail`, or `truncate_damaged_tail`.

## Exit codes

`0` success, `1` usage error, `2` operation refused, `3` verification or
invariant failure, `70` the crash-injection boundary was reached.
