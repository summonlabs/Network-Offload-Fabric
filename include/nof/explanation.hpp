#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "nof/assignment.hpp"
#include "nof/capability.hpp"
#include "nof/function.hpp"
#include "nof/ids.hpp"
#include "nof/scope.hpp"

// Canonical explanation surface. An explanation answers three questions for
// every decision: what was decided, why it was legal or illegal, and which
// evidence, generations, policy, and authority made it so. Rendering is
// deterministic: identical inputs produce byte-identical output.
namespace nof {

enum class Decision : std::uint8_t {
  Accept = 1,
  Refuse = 2,
  Replace = 3,
  Revoke = 4,
  Defer = 5,
  Suspend = 6,
  NoOp = 7,
};

const char* to_string(Decision value) noexcept;
bool parse_decision(std::string_view token, Decision& out) noexcept;

// One evaluated candidate target. Every candidate the runtime considered is
// reported with its verdict, whether or not it was eligible, so a refusal can
// be explained without re-running the evaluation.
struct CandidateEvaluation {
  DeviceId device{};
  HostId host{};
  DeviceKind kind = DeviceKind::Nic;
  IncarnationId incarnation{};
  CapabilityGeneration capability_generation{};
  bool eligible = false;
  MatchVerdict verdict = MatchVerdict::Missing;
  ReasonCode reason = ReasonCode::EvidenceMissing;
  std::vector<ReasonCode> contributing{};
  ExecutionMode mode = ExecutionMode::Offloaded;

  // Composite rank: lower is better. Composed of typed components so the
  // ordering can never depend on incidental iteration order.
  std::uint64_t rank = 0;
  std::uint32_t offload_rank = 0;
  std::uint32_t kind_rank = 0;
  std::uint32_t locality_rank = 0;
  std::uint64_t utilization_ppm = 0;

  Digest evaluation_digest{};

  friend bool operator==(const CandidateEvaluation&, const CandidateEvaluation&) = default;
};

struct Explanation {
  Decision decision = Decision::Refuse;
  ReasonCode primary_reason = ReasonCode::Ok;
  std::vector<ReasonCode> reasons{};

  RequestId request_id{};
  FunctionId function{};
  FunctionClass cls = FunctionClass::RouteLookup;
  ScopeSpec scope{};
  ScopeId scope_id{};
  Exclusivity exclusivity = Exclusivity::Exclusive;
  ExecutionMode mode = ExecutionMode::Offloaded;

  GenerationBinding binding{};
  AuthorityId authority{};
  LeaseId lease{};
  FencingToken fence{};
  AttemptId attempt{};
  AssignmentId assignment{};
  AssignmentId replaced{};
  DeviceId selected_device{};

  std::vector<CandidateEvaluation> candidates{};
  std::size_t candidates_total = 0;
  bool candidates_truncated = false;

  Digest input_digest{};
  Digest decision_digest{};

  friend bool operator==(const Explanation&, const Explanation&) = default;
};

// Deterministic rendering. Multi-line, ASCII-only, stable field order.
std::string render_explanation(const Explanation& explanation);
// Canonical machine-readable rendering.
Status explanation_to_json(const Explanation& explanation, std::string& out, std::size_t max_bytes);

}  // namespace nof
