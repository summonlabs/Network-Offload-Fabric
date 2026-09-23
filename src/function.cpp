#include "nof/function.hpp"

#include <algorithm>

namespace nof {

namespace {

struct TokenMap {
  std::string_view token;
  int value;
};

constexpr TokenMap kFunctionClasses[] = {
    {"route_lookup", 1},        {"access_control", 2},   {"connection_tracking", 3},
    {"encapsulation", 4},       {"load_balancing", 5},   {"crypto_offload", 6},
    {"rate_limiting", 7},       {"timestamping", 8},     {"packet_capture", 9},
    {"queue_steering", 10},     {"memory_registration", 11}, {"checksum_offload", 12},
    {"traffic_metering", 13},   {"packet_filtering", 14}, {"header_rewrite", 15},
    {"replication_mirroring", 16},
};

constexpr TokenMap kSemantics[] = {
    {"line_rate_deterministic", 0},  {"programmable_pipeline", 1},
    {"stateful_flow_table", 2},      {"per_flow_counters", 3},
    {"hardware_timestamps", 4},      {"inline_crypto", 5},
    {"rdma_capable", 6},             {"kernel_bypass", 7},
    {"header_rewrite_capable", 8},   {"multicast_replication", 9},
    {"ordering_preserving", 10},     {"jumbo_frames", 11},
    {"vlan_aware", 12},              {"tunnel_encapsulation", 13},
    {"traffic_shaping", 14},         {"fail_open", 15},
    {"persistent_across_reboot", 16}, {"atomic_flow_update", 17},
    {"flow_aging_offload", 18},      {"queue_partitioning", 19},
    {"memory_registration_cache", 20}, {"checksum_offload_capable", 21},
    {"large_rule_capacity", 22},     {"sram_table_lookup", 23},
    {"per_queue_rate_limit", 24},    {"sampled_mirroring", 25},
};

template <std::size_t N>
bool lookup(const TokenMap (&table)[N], std::string_view token, int& out) {
  for (const TokenMap& entry : table) {
    if (entry.token.size() == token.size() && entry.token == token) {
      out = entry.value;
      return true;
    }
  }
  return false;
}

}  // namespace

const char* to_string(FunctionClass value) noexcept {
  switch (value) {
    case FunctionClass::RouteLookup:
      return "route_lookup";
    case FunctionClass::AccessControl:
      return "access_control";
    case FunctionClass::ConnectionTracking:
      return "connection_tracking";
    case FunctionClass::Encapsulation:
      return "encapsulation";
    case FunctionClass::LoadBalancing:
      return "load_balancing";
    case FunctionClass::CryptoOffload:
      return "crypto_offload";
    case FunctionClass::RateLimiting:
      return "rate_limiting";
    case FunctionClass::Timestamping:
      return "timestamping";
    case FunctionClass::PacketCapture:
      return "packet_capture";
    case FunctionClass::QueueSteering:
      return "queue_steering";
    case FunctionClass::MemoryRegistration:
      return "memory_registration";
    case FunctionClass::ChecksumOffload:
      return "checksum_offload";
    case FunctionClass::TrafficMetering:
      return "traffic_metering";
    case FunctionClass::PacketFiltering:
      return "packet_filtering";
    case FunctionClass::HeaderRewrite:
      return "header_rewrite";
    case FunctionClass::ReplicationMirroring:
      return "replication_mirroring";
  }
  return "unknown_function_class";
}

bool parse_function_class(std::string_view token, FunctionClass& out) noexcept {
  int value = 0;
  if (!lookup(kFunctionClasses, token, value)) {
    return false;
  }
  out = static_cast<FunctionClass>(value);
  return true;
}

const char* to_string(Semantic value) noexcept {
  const int index = static_cast<int>(value);
  for (const TokenMap& entry : kSemantics) {
    if (entry.value == index) {
      return entry.token.data();
    }
  }
  return "unknown_semantic";
}

bool parse_semantic(std::string_view token, Semantic& out) noexcept {
  int value = 0;
  if (!lookup(kSemantics, token, value)) {
    return false;
  }
  out = static_cast<Semantic>(value);
  return true;
}

std::size_t SemanticsMask::count() const noexcept {
  std::uint64_t bits = bits_;
  std::size_t total = 0;
  while (bits != 0) {
    bits &= (bits - 1);
    ++total;
  }
  return total;
}

std::vector<Semantic> SemanticsMask::values() const {
  std::vector<Semantic> out;
  out.reserve(count());
  for (std::size_t index = 0; index < kSemanticCount; ++index) {
    const auto candidate = static_cast<Semantic>(index);
    if (test(candidate)) {
      out.push_back(candidate);
    }
  }
  return out;
}

SemanticsMask SemanticsMask::from_bits(std::uint64_t bits) noexcept {
  SemanticsMask mask;
  mask.set_bits(bits);
  return mask;
}

Result<SemanticsMask> SemanticsMask::from_tokens(const std::vector<std::string>& tokens) {
  SemanticsMask mask;
  for (const std::string& token : tokens) {
    Semantic semantic = Semantic::LineRateDeterministic;
    if (!parse_semantic(token, semantic)) {
      return Error(ReasonCode::UnsupportedValue, "unknown semantic token: " + token);
    }
    mask.set(semantic);
  }
  return mask;
}

std::string SemanticVersion::to_string() const {
  return std::to_string(static_cast<unsigned>(major)) + "." +
         std::to_string(static_cast<unsigned>(minor));
}

Result<SemanticVersion> SemanticVersion::parse(std::string_view text) {
  const std::size_t dot = text.find('.');
  if (dot == std::string_view::npos || dot == 0 || dot + 1 >= text.size()) {
    return Error(ReasonCode::MalformedInput, "semantic version must be MAJOR.MINOR");
  }
  const auto parse_part = [](std::string_view part, std::uint16_t& out) -> Status {
    if (part.empty() || part.size() > 5) {
      return Error(ReasonCode::MalformedInput, "semantic version component out of range");
    }
    std::uint32_t value = 0;
    for (const char c : part) {
      if (c < '0' || c > '9') {
        return Error(ReasonCode::MalformedInput, "semantic version component is not numeric");
      }
      value = value * 10u + static_cast<std::uint32_t>(c - '0');
      if (value > 65535u) {
        return Error(ReasonCode::OutOfRange, "semantic version component out of range");
      }
    }
    out = static_cast<std::uint16_t>(value);
    return ok_status();
  };
  SemanticVersion out;
  Status status = parse_part(text.substr(0, dot), out.major);
  if (!status) {
    return status.error();
  }
  status = parse_part(text.substr(dot + 1), out.minor);
  if (!status) {
    return status.error();
  }
  return out;
}

}  // namespace nof
