#pragma once

#include <cstddef>
#include <cstdint>

#include "nof/error.hpp"

// Every bounded resource in the runtime is declared here and validated before
// anything is allocated. A configuration that declares a zero or absurd bound
// is refused at construction: the runtime never silently substitutes a default
// for an explicit configuration.
namespace nof {

struct Bounds {
  // State model ceilings.
  std::size_t max_hosts = 4096;
  std::size_t max_devices = 16384;
  std::size_t max_functions = 65536;
  std::size_t max_scopes = 65536;
  std::size_t max_assignments = 65536;
  std::size_t max_active_assignments = 65536;
  std::size_t max_dependencies_per_request = 64;
  std::size_t max_affinity_entries = 64;
  std::size_t max_anti_affinity_entries = 64;

  // Evidence ceilings.
  std::size_t max_sources = 4096;
  std::size_t max_capability_records = 262144;
  std::size_t max_observations = 262144;
  std::size_t max_authority_grants = 65536;
  std::size_t max_semantics_per_requirement = 32;
  std::size_t max_reasons_per_explanation = 24;
  std::size_t max_reason_detail_bytes = 256;
  std::size_t max_candidates_per_plan = 8192;
  std::size_t max_candidates_reported = 256;
  std::size_t max_history_per_assignment = 32;
  std::size_t max_effects_per_assignment = 64;
  std::size_t max_provenance_records = 8192;

  // Canonical representation ceilings.
  std::size_t max_canonical_bytes = 32u * 1024u * 1024u;
  std::size_t max_export_bytes = 32u * 1024u * 1024u;
  std::size_t max_text_bytes = 4096;
  std::size_t max_json_depth = 32;

  // Persistence ceilings.
  std::size_t max_record_bytes = 4u * 1024u * 1024u;
  std::size_t max_journal_bytes = 64u * 1024u * 1024u;
  std::size_t max_snapshot_bytes = 64u * 1024u * 1024u;
  std::size_t max_store_bytes = 256u * 1024u * 1024u;
  std::size_t max_compaction_chain = 1024;

  // Concurrency ceilings.
  std::size_t max_workers = 8;
  std::size_t max_queue_depth = 256;
  std::size_t max_pending_requests = 1024;
  std::size_t max_idempotency_entries = 8192;

  // Transport ceilings.
  std::size_t max_frame_bytes = 1024u * 1024u;
  std::size_t max_connections = 64;
  std::size_t max_request_bytes = 512u * 1024u;

  // Bounded reassignment policy ceiling.
  std::size_t max_reassignments_per_scope = 16;
  std::size_t max_reassignment_window_micros = 24ull * 60ull * 60ull * 1000000ull;

  // Rendered explanation ceiling.
  std::size_t max_explanation_bytes = 1024u * 1024u;
};

// Returns a refusal naming the exact offending field when a bound is zero or
// outside the representable range.
Status validate_bounds(const Bounds& bounds);

}  // namespace nof
