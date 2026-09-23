# Proof obligations

Each obligation is discharged by executable evidence. Test names are the suite
and case names printed by `nof_tests`; `--filter=<substring>` runs a subset.

| Obligation | Discharged by |
| --- | --- |
| Unsupported capability never becomes eligible | `evidence.capability_validation_and_exact_matching` (explicit denial is `UNSUPPORTED`), `placement.unsupported_and_unknown_semantics_are_never_eligible` |
| Missing evidence never silently becomes false, zero, or success | `evidence.capability_validation_and_exact_matching` (silence is `UNKNOWN`), `placement.evidence_floors_stale_evidence_and_restart`, `evidence.topology_validation_refusals` |
| Stale generations cannot authorize placement | `evidence.ingest_paths_refuse_stale_and_superseded_evidence`, `placement.evidence_floors_stale_evidence_and_restart`, `lifecycle.capability_policy_and_authority_changes_suspend_assignments` |
| Stale or superseded evidence cannot justify current authority | `lifecycle.restart_fences_pre_restart_authority_and_reauthorization_restores_it`, `persistence.recovery_never_resurrects_liveness_or_authority` |
| Two exclusive assignments cannot overlap | `concurrency.competing_exclusive_claims_leave_exactly_one_holder`, `lifecycle.exclusive_scope_cannot_have_two_holders`, `lifecycle.replace_is_bounded_and_supersedes_the_previous_holder` |
| Replayed pre-restart attempts are fenced | `lifecycle.restart_fences_pre_restart_authority_and_reauthorization_restores_it`, `lifecycle.fencing_refuses_replays_and_mismatches`, `process.crash_after_commit_before_ack_keeps_the_commit` |
| Target disappearance cannot silently leave authority current | `lifecycle.revalidation_suspends_authority_when_evidence_moves`, `lifecycle.capability_policy_and_authority_changes_suspend_assignments` |
| Host fallback is explicit | `placement.host_fallback_is_explicit_and_only_when_permitted`, `placement.unsupported_and_unknown_semantics_are_never_eligible` |
| Acknowledgement never becomes verified application | `lifecycle.dispatched_is_not_applied_until_verified`, `property.acknowledgement_never_becomes_verified_application` |
| Accepted state is deterministic where the contract claims it | `placement.selects_the_best_offload_target_deterministically`, `property.identical_inputs_produce_identical_state`, `property.exports_and_explanations_are_byte_stable`, `process.cli_scenario_is_deterministic_across_processes` |
| Duplicate delivery is idempotent or explicitly fenced | `lifecycle.duplicate_delivery_is_idempotent_or_fenced`, `concurrency.duplicate_delivery_races_create_one_assignment`, `persistence.idempotency_and_effects_survive_restart`, `process.service_transport_over_real_sockets` |
| Every bounded truncation, refusal, and eviction is observable | `placement.candidate_reporting_is_bounded_and_observable`, statistics counters (`results_truncated`, `entries_evicted`, `*_refused`), recovery report (`records_discarded`, `bytes_discarded`) |
| Persistence round-trips correctness-critical state without semantic loss | `persistence.clean_reopen_restores_the_same_state`, `persistence.snapshot_round_trip_is_lossless`, `persistence.idempotency_and_effects_survive_restart` |
| Conservative restart does not resurrect liveness or authority | `persistence.recovery_never_resurrects_liveness_or_authority`, `lifecycle.restart_fences_pre_restart_authority_and_reauthorization_restores_it` |
| Malformed, corrupt, truncated, oversized input cannot look successful | `core.canonical_binary_round_trip_and_bounds`, `core.canonical_json_is_sorted_and_strict`, `evidence.*_validation_refusals`, `persistence.torn_tail_is_classified_and_never_silently_accepted`, `persistence.corruption_truncation_and_version_mismatch`, `process.service_transport_over_real_sockets` |
| Bounded resources return to baseline | `concurrency.resource_accounting_returns_to_baseline`, `concurrency.server_lifecycle_with_work_in_flight` |
| Cancellation cannot publish success | `lifecycle.cancellation_prevents_publication`, `concurrency.cancellation_observed_from_another_thread` |
| Real multi-process behaviour over real sockets | `process.service_transport_over_real_sockets`, `process.hard_kill_is_recoverable`, `process.cli_scenario_is_deterministic_across_processes` |
| Crash safety at meaningful durable boundaries with real processes | `process.crash_before_commit_leaves_no_authority_behind`, `process.crash_after_commit_before_ack_keeps_the_commit`, `persistence.crash_boundaries_are_observed_and_consistent` |
| Invariants hold under adversarial sequences | `property.seeded_sequences_preserve_invariants` (four seeds, sixty steps each, invariants checked after every step) |
