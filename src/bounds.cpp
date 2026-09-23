#include "nof/bounds.hpp"

namespace nof {

namespace {

Status refuse(const char* field, const char* why) {
  return Error(ReasonCode::InvalidConfiguration, std::string(field) + ": " + why);
}

Status require_nonzero(std::size_t value, const char* field) {
  if (value == 0) {
    return refuse(field, "must be greater than zero");
  }
  return ok_status();
}

}  // namespace

Status validate_bounds(const Bounds& bounds) {
  // State ceilings.
  if (bounds.max_hosts == 0 || bounds.max_devices == 0 || bounds.max_functions == 0 ||
      bounds.max_scopes == 0 || bounds.max_assignments == 0) {
    return refuse("state ceilings", "must be greater than zero");
  }
  if (bounds.max_assignments > 100000000u) {
    return refuse("max_assignments", "exceeds the supported ceiling");
  }
  // Canonical representation.
  if (bounds.max_canonical_bytes < 1024u) {
    return refuse("max_canonical_bytes", "must be at least 1024");
  }
  if (bounds.max_text_bytes == 0 || bounds.max_text_bytes > bounds.max_canonical_bytes) {
    return refuse("max_text_bytes", "must be non-zero and no larger than max_canonical_bytes");
  }
  if (bounds.max_json_depth == 0 || bounds.max_json_depth > 256) {
    return refuse("max_json_depth", "must be between 1 and 256");
  }
  if (bounds.max_export_bytes < bounds.max_canonical_bytes) {
    return refuse("max_export_bytes", "must be at least max_canonical_bytes");
  }
  // Persistence.
  if (bounds.max_record_bytes < 256u) {
    return refuse("max_record_bytes", "must be at least 256");
  }
  if (bounds.max_journal_bytes < bounds.max_record_bytes) {
    return refuse("max_journal_bytes", "must be at least max_record_bytes");
  }
  if (bounds.max_snapshot_bytes < bounds.max_record_bytes) {
    return refuse("max_snapshot_bytes", "must be at least max_record_bytes");
  }
  if (bounds.max_store_bytes < bounds.max_snapshot_bytes) {
    return refuse("max_store_bytes", "must be at least max_snapshot_bytes");
  }
  Status status = require_nonzero(bounds.max_compaction_chain, "max_compaction_chain");
  if (!status) {
    return status;
  }
  // Concurrency.
  if (bounds.max_workers == 0 || bounds.max_workers > 1024) {
    return refuse("max_workers", "must be between 1 and 1024");
  }
  if (bounds.max_queue_depth == 0 || bounds.max_queue_depth > 1000000u) {
    return refuse("max_queue_depth", "must be between 1 and 1000000");
  }
  if (bounds.max_pending_requests == 0) {
    return refuse("max_pending_requests", "must be greater than zero");
  }
  if (bounds.max_idempotency_entries == 0) {
    return refuse("max_idempotency_entries", "must be greater than zero");
  }
  // Transport.
  if (bounds.max_frame_bytes < 64u || bounds.max_frame_bytes > 1024u * 1024u * 1024u) {
    return refuse("max_frame_bytes", "must be between 64 and 1 GiB");
  }
  if (bounds.max_request_bytes == 0 || bounds.max_request_bytes > bounds.max_frame_bytes) {
    return refuse("max_request_bytes", "must be non-zero and no larger than max_frame_bytes");
  }
  if (bounds.max_connections == 0 || bounds.max_connections > 4096) {
    return refuse("max_connections", "must be between 1 and 4096");
  }
  // Semantic ceilings.
  if (bounds.max_semantics_per_requirement == 0 ||
      bounds.max_semantics_per_requirement > 64) {
    return refuse("max_semantics_per_requirement", "must be between 1 and 64");
  }
  if (bounds.max_reasons_per_explanation == 0 || bounds.max_reasons_per_explanation > 256) {
    return refuse("max_reasons_per_explanation", "must be between 1 and 256");
  }
  if (bounds.max_reason_detail_bytes == 0 || bounds.max_reason_detail_bytes > 65536u) {
    return refuse("max_reason_detail_bytes", "must be between 1 and 65536");
  }
  if (bounds.max_candidates_per_plan == 0 || bounds.max_candidates_reported == 0) {
    return refuse("candidate bounds", "must be greater than zero");
  }
  if (bounds.max_candidates_reported > bounds.max_candidates_per_plan) {
    return refuse("max_candidates_reported", "must not exceed max_candidates_per_plan");
  }
  if (bounds.max_history_per_assignment == 0 || bounds.max_effects_per_assignment == 0) {
    return refuse("history bounds", "must be greater than zero");
  }
  if (bounds.max_provenance_records == 0) {
    return refuse("max_provenance_records", "must be greater than zero");
  }
  if (bounds.max_dependencies_per_request == 0) {
    return refuse("max_dependencies_per_request", "must be greater than zero");
  }
  if (bounds.max_reassignments_per_scope == 0) {
    return refuse("max_reassignments_per_scope", "must be greater than zero");
  }
  if (bounds.max_reassignment_window_micros == 0) {
    return refuse("max_reassignment_window_micros", "must be greater than zero");
  }
  if (bounds.max_explanation_bytes < 1024u) {
    return refuse("max_explanation_bytes", "must be at least 1024");
  }
  return ok_status();
}

}  // namespace nof
