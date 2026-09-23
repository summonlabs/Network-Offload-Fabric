#include "nof/service.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <thread>
#include <vector>

#include "detail/net.hpp"
#include "nof/canonical.hpp"
#include "nof/checked.hpp"
#include "nof/digest.hpp"
#include "nof/journal.hpp"
#include "nof/version.hpp"

namespace nof::service {

namespace {

constexpr std::uint16_t kFlagError = 0x0001;

void store_u16(std::byte* out, std::uint16_t value) {
  out[0] = static_cast<std::byte>(value & 0xFFu);
  out[1] = static_cast<std::byte>((value >> 8) & 0xFFu);
}

void store_u32(std::byte* out, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out[i] = static_cast<std::byte>((value >> (i * 8)) & 0xFFu);
  }
}

void store_u64(std::byte* out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out[i] = static_cast<std::byte>((value >> (i * 8)) & 0xFFu);
  }
}

std::uint16_t load_u16(const std::byte* data) {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[0]) |
                                    (static_cast<std::uint16_t>(data[1]) << 8));
}

std::uint32_t load_u32(const std::byte* data) {
  std::uint32_t value = 0;
  for (int i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(data[i]) << (i * 8);
  }
  return value;
}

std::uint64_t load_u64(const std::byte* data) {
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value |= static_cast<std::uint64_t>(data[i]) << (i * 8);
  }
  return value;
}

// Reads every field of an object and refuses trailing bytes, so a response can
// never be accepted while silently ignoring part of what was sent.
template <class T>
Result<T> decode_exact(std::span<const std::byte> payload, const Bounds& bounds,
                       Result<T> (*decode)(BinReader&, const Bounds&)) {
  BinReader reader(payload, bounds.max_text_bytes);
  auto value = decode(reader, bounds);
  if (!value) {
    return value.error();
  }
  if (!reader.at_end()) {
    return Error(ReasonCode::MalformedInput, "request payload carries trailing bytes");
  }
  return value;
}

Status require_consumed(const BinReader& reader) {
  if (!reader.at_end()) {
    return Error(ReasonCode::MalformedInput, "request payload carries trailing bytes");
  }
  return ok_status();
}

void encode_ok_payload(std::span<const std::byte> payload, std::vector<std::byte>& out) {
  out.assign(payload.begin(), payload.end());
}

}  // namespace

const char* to_string(Opcode value) noexcept {
  switch (value) {
    case Opcode::Hello:
      return "hello";
    case Opcode::Ping:
      return "ping";
    case Opcode::Stats:
      return "stats";
    case Opcode::RegisterFunction:
      return "register_function";
    case Opcode::IngestTopology:
      return "ingest_topology";
    case Opcode::IngestCapabilities:
      return "ingest_capabilities";
    case Opcode::IngestPolicy:
      return "ingest_policy";
    case Opcode::IngestObservations:
      return "ingest_observations";
    case Opcode::GrantAuthority:
      return "grant_authority";
    case Opcode::WithdrawAuthority:
      return "withdraw_authority";
    case Opcode::ReportEffect:
      return "report_effect";
    case Opcode::Plan:
      return "plan";
    case Opcode::Apply:
      return "apply";
    case Opcode::Revoke:
      return "revoke";
    case Opcode::Replace:
      return "replace";
    case Opcode::Reauthorize:
      return "reauthorize";
    case Opcode::Revalidate:
      return "revalidate";
    case Opcode::GetAssignment:
      return "get_assignment";
    case Opcode::ListAssignments:
      return "list_assignments";
    case Opcode::GetScope:
      return "get_scope";
    case Opcode::ExplainAssignment:
      return "explain_assignment";
    case Opcode::ExplainRequest:
      return "explain_request";
    case Opcode::StateDigest:
      return "state_digest";
    case Opcode::Export:
      return "export";
    case Opcode::RecoveryReport:
      return "recovery_report";
    case Opcode::VerifyInvariants:
      return "verify_invariants";
    case Opcode::Compact:
      return "compact";
    case Opcode::Shutdown:
      return "shutdown";
  }
  return "unknown_opcode";
}

bool parse_opcode(std::uint16_t value, Opcode& out) noexcept {
  if (value < 1 || value > 28) {
    return false;
  }
  out = static_cast<Opcode>(value);
  return true;
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

Status encode_frame(const Frame& frame, std::vector<std::byte>& out, const FrameLimits& limits) {
  if (frame.payload.size() > limits.max_frame_bytes) {
    return Error(ReasonCode::PayloadTooLarge, "frame payload exceeds the configured bound");
  }
  std::size_t total = 0;
  if (!checked_add(kFrameHeaderBytes, frame.payload.size(), total) ||
      !checked_add(total, kFrameTrailerBytes, total)) {
    return Error(ReasonCode::ArithmeticOverflow, "frame size overflow");
  }
  out.assign(total, std::byte{0});
  store_u16(out.data(), kFrameMagic);
  store_u16(out.data() + 2, kProtocolVersion);
  store_u16(out.data() + 4, static_cast<std::uint16_t>(frame.opcode));
  store_u16(out.data() + 6, frame.flags);
  store_u64(out.data() + 8, frame.request_id);
  store_u32(out.data() + 16, static_cast<std::uint32_t>(frame.payload.size()));
  if (!frame.payload.empty()) {
    std::memcpy(out.data() + kFrameHeaderBytes, frame.payload.data(), frame.payload.size());
  }
  const std::uint32_t crc =
      crc32c(std::span<const std::byte>(out.data(), total - kFrameTrailerBytes));
  store_u32(out.data() + total - kFrameTrailerBytes, crc);
  return ok_status();
}

Result<Frame> decode_frame(std::span<const std::byte> bytes, const FrameLimits& limits) {
  if (bytes.size() < kFrameHeaderBytes + kFrameTrailerBytes) {
    return Error(ReasonCode::TruncatedInput, "frame is shorter than its header");
  }
  if (load_u16(bytes.data()) != kFrameMagic) {
    return Error(ReasonCode::FrameInvalid, "frame magic does not match");
  }
  if (load_u16(bytes.data() + 2) != kProtocolVersion) {
    return Error(ReasonCode::ProtocolVersionMismatch, "frame protocol version is not supported");
  }
  // The opcode is carried through even when it is not implemented: a peer that
  // asks for something unsupported is answered with a refusal rather than
  // having its connection dropped.
  const auto opcode = static_cast<Opcode>(load_u16(bytes.data() + 4));
  const std::uint32_t payload_length = load_u32(bytes.data() + 16);
  if (payload_length > limits.max_frame_bytes) {
    return Error(ReasonCode::PayloadTooLarge, "frame payload length exceeds the configured bound");
  }
  std::size_t expected = 0;
  if (!checked_add(kFrameHeaderBytes, static_cast<std::size_t>(payload_length), expected) ||
      !checked_add(expected, kFrameTrailerBytes, expected)) {
    return Error(ReasonCode::ArithmeticOverflow, "frame length overflow");
  }
  if (bytes.size() != expected) {
    return Error(ReasonCode::FrameInvalid, "frame length does not match its header");
  }
  if (load_u32(bytes.data() + expected - kFrameTrailerBytes) !=
      crc32c(bytes.subspan(0, expected - kFrameTrailerBytes))) {
    return Error(ReasonCode::IntegrityFailure, "frame integrity check failed");
  }
  Frame frame;
  frame.opcode = opcode;
  frame.flags = load_u16(bytes.data() + 6);
  frame.request_id = load_u64(bytes.data() + 8);
  frame.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(kFrameHeaderBytes),
                       bytes.begin() + static_cast<std::ptrdiff_t>(kFrameHeaderBytes + payload_length));
  return frame;
}

void FrameDecoder::feed(std::span<const std::byte> bytes) {
  buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
}

Result<bool> FrameDecoder::next(Frame& out) {
  const std::size_t available = buffer_.size() - consumed_;
  if (available < kFrameHeaderBytes + kFrameTrailerBytes) {
    return false;
  }
  const std::byte* base = buffer_.data() + consumed_;
  if (load_u16(base) != kFrameMagic) {
    return Error(ReasonCode::FrameInvalid, "frame magic does not match");
  }
  if (load_u16(base + 2) != kProtocolVersion) {
    return Error(ReasonCode::ProtocolVersionMismatch, "frame protocol version is not supported");
  }
  const std::uint32_t payload_length = load_u32(base + 16);
  if (payload_length > limits_.max_frame_bytes) {
    return Error(ReasonCode::PayloadTooLarge, "frame payload length exceeds the configured bound");
  }
  const std::size_t total = kFrameHeaderBytes + payload_length + kFrameTrailerBytes;
  if (available < total) {
    return false;
  }
  auto frame = decode_frame(std::span<const std::byte>(base, total), limits_);
  if (!frame) {
    return frame.error();
  }
  consumed_ += total;
  if (consumed_ == buffer_.size()) {
    buffer_.clear();
    consumed_ = 0;
  }
  out = frame.take();
  return true;
}

Status FrameDecoder::finish() const {
  if (buffer_.size() != consumed_) {
    return Error(ReasonCode::TruncatedInput, "connection ended inside a frame");
  }
  return ok_status();
}

// ---------------------------------------------------------------------------
// Payload helpers
// ---------------------------------------------------------------------------

void encode_error_payload(const Error& error, std::vector<std::byte>& out, const Bounds& bounds) {
  BinWriter writer(bounds.max_reason_detail_bytes + 64);
  Status status = writer.u16(static_cast<std::uint16_t>(error.code));
  if (status) {
    std::string detail = error.detail;
    if (detail.size() > bounds.max_reason_detail_bytes) {
      detail.resize(bounds.max_reason_detail_bytes);
    }
    status = writer.text(detail);
  }
  if (!status) {
    out.clear();
    return;
  }
  out.assign(writer.data().begin(), writer.data().end());
}

Result<Error> decode_error_payload(std::span<const std::byte> payload, const Bounds& bounds) {
  BinReader reader(payload, bounds.max_text_bytes);
  auto code = reader.u16();
  if (!code) {
    return code.error();
  }
  if (std::string_view(to_string(static_cast<ReasonCode>(code.value()))) == "UNKNOWN_REASON") {
    return Error(ReasonCode::UnsupportedValue, "error payload carries an unknown reason code");
  }
  auto detail = reader.text();
  if (!detail) {
    return detail.error();
  }
  Error error;
  error.code = static_cast<ReasonCode>(code.value());
  error.detail = detail.take();
  return error;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

namespace {

struct ConnectionEntry {
  std::uint64_t id = 0;
  std::uintptr_t handle = 0;
};

struct CachedResponse {
  Digest request_digest{};
  std::vector<std::byte> payload{};
  std::uint16_t flags = 0;
};

}  // namespace

struct Server::Impl {
  Fabric* fabric = nullptr;
  ServerConfig config{};
  Bounds bounds{};
  FrameLimits limits{};

  std::atomic<bool> stopping{false};
  std::atomic<bool> running{false};
  std::atomic<std::uint16_t> port{0};

  detail::Socket listener{};
  detail::Socket wakeup{};
  std::uint16_t wakeup_port = 0;
  std::thread acceptor{};
  std::vector<std::thread> workers{};

  mutable std::mutex stats_mutex{};
  ServerStats stats{};

  std::mutex queue_mutex{};
  std::condition_variable queue_cv{};
  std::deque<detail::Socket> queue{};

  std::mutex connections_mutex{};
  std::map<std::uint64_t, ConnectionEntry> connections{};
  std::uint64_t next_connection_id = 0;

  std::mutex cache_mutex{};
  std::map<std::uint64_t, CachedResponse> cache{};
  std::deque<std::uint64_t> cache_order{};

  CancelToken cancel{};
  bool net_initialized = false;

  Status submit(detail::Socket socket);
  void accept_loop();
  void worker_loop();
  void handle_connection(detail::Socket socket);
  Status handle_request(const Frame& request, Frame& response);
  ServerStats snapshot_stats() const;
};

Status Server::Impl::submit(detail::Socket socket) {
  std::unique_lock<std::mutex> lock(queue_mutex);
  if (stopping.load(std::memory_order_relaxed)) {
    return Error(ReasonCode::ShuttingDown, "server is stopping");
  }
  if (queue.size() >= config.max_queue_depth) {
    return Error(ReasonCode::QueueFull, "connection queue is full");
  }
  queue.push_back(std::move(socket));
  queue_cv.notify_one();
  return ok_status();
}

void Server::Impl::accept_loop() {
  for (;;) {
    if (stopping.load(std::memory_order_acquire)) {
      return;
    }
    bool listener_ready = false;
    bool wakeup_ready = false;
    Status wait = detail::wait_readable(listener, wakeup, listener_ready, wakeup_ready);
    if (!wait) {
      if (stopping.load(std::memory_order_acquire)) {
        return;
      }
      continue;
    }
    if (wakeup_ready) {
      std::byte scratch[64];
      (void)wakeup.receive_bytes(std::span<std::byte>(scratch, sizeof(scratch)));
    }
    if (stopping.load(std::memory_order_acquire)) {
      return;
    }
    if (!listener_ready) {
      continue;
    }
    auto accepted = detail::accept_tcp(listener);
    if (!accepted) {
      if (stopping.load(std::memory_order_acquire)) {
        return;
      }
      continue;
    }
    {
      std::unique_lock<std::mutex> lock(stats_mutex);
      stats.open_connections += 1;
    }
    detail::Socket socket = accepted.take();
    {
      std::unique_lock<std::mutex> lock(connections_mutex);
      if (connections.size() >= config.max_connections) {
        lock.unlock();
        (void)socket.close();
        std::unique_lock<std::mutex> stats_lock(stats_mutex);
        stats.connections_refused += 1;
        stats.open_connections -= 1;
        continue;
      }
      next_connection_id += 1;
      ConnectionEntry entry;
      entry.id = next_connection_id;
      entry.handle = socket.handle();
      connections[entry.id] = entry;
    }
    Status queued = submit(std::move(socket));
    if (!queued) {
      std::unique_lock<std::mutex> lock(connections_mutex);
      const auto last = connections.rbegin();
      if (last != connections.rend()) {
        connections.erase(last->first);
      }
      std::unique_lock<std::mutex> stats_lock(stats_mutex);
      stats.connections_refused += 1;
      stats.open_connections -= 1;
    }
  }
}

void Server::Impl::worker_loop() {
  for (;;) {
    detail::Socket socket;
    {
      std::unique_lock<std::mutex> lock(queue_mutex);
      queue_cv.wait(lock, [this]() {
        return stopping.load(std::memory_order_acquire) || !queue.empty();
      });
      if (queue.empty()) {
        if (stopping.load(std::memory_order_acquire)) {
          return;
        }
        continue;
      }
      socket = std::move(queue.front());
      queue.pop_front();
    }
    handle_connection(std::move(socket));
  }
}

void Server::Impl::handle_connection(detail::Socket socket) {
  FrameDecoder decoder(limits);
  bool first = true;
  std::uint64_t connection_id = 0;
  {
    std::unique_lock<std::mutex> lock(connections_mutex);
    for (const auto& entry : connections) {
      if (entry.second.handle == socket.handle()) {
        connection_id = entry.first;
        break;
      }
    }
  }
  (void)first;
  for (;;) {
    if (stopping.load(std::memory_order_acquire) && queue.empty()) {
      break;
    }
    std::byte buffer[16384];
    auto received = socket.receive_bytes(std::span<std::byte>(buffer, sizeof(buffer)));
    if (!received) {
      std::unique_lock<std::mutex> lock(stats_mutex);
      stats.frames_refused += 1;
      break;
    }
    if (received.value() == 0) {
      break;
    }
    {
      std::unique_lock<std::mutex> lock(stats_mutex);
      stats.bytes_received += received.value();
    }
    decoder.feed(std::span<const std::byte>(buffer, received.value()));
    bool broken = false;
    for (;;) {
      Frame request;
      auto next = decoder.next(request);
      if (!next) {
        std::unique_lock<std::mutex> lock(stats_mutex);
        stats.frames_refused += 1;
        broken = true;
        break;
      }
      if (!next.value()) {
        break;
      }
      {
        std::unique_lock<std::mutex> lock(stats_mutex);
        stats.in_flight_requests += 1;
      }
      Frame response;
      Status status = handle_request(request, response);
      {
        std::unique_lock<std::mutex> lock(stats_mutex);
        stats.in_flight_requests -= 1;
        if (status) {
          stats.requests_handled += 1;
        } else {
          stats.requests_refused += 1;
        }
      }
      if (!status) {
        response.opcode = request.opcode;
        response.request_id = request.request_id;
        response.flags = kFlagError;
        encode_error_payload(status.error(), response.payload, bounds);
      }
      std::vector<std::byte> bytes;
      Status encoded = encode_frame(response, bytes, limits);
      if (!encoded) {
        broken = true;
        break;
      }
      auto sent = socket.send_bytes(bytes);
      if (!sent) {
        broken = true;
        break;
      }
      {
        std::unique_lock<std::mutex> lock(stats_mutex);
        stats.bytes_sent += sent.value();
        stats.frames_accepted += 1;
      }
      if (request.opcode == Opcode::Shutdown) {
        stopping.store(true, std::memory_order_release);
        if (config.shutdown_hook) {
          config.shutdown_hook();
        }
        return;
      }
    }
    if (broken) {
      break;
    }
  }
  (void)decoder.finish();
  (void)socket.shutdown_both();
  (void)socket.close();
  {
    std::unique_lock<std::mutex> lock(connections_mutex);
    if (connection_id != 0) {
      connections.erase(connection_id);
    }
  }
  {
    std::unique_lock<std::mutex> lock(stats_mutex);
    if (stats.open_connections > 0) {
      stats.open_connections -= 1;
    }
  }
}

Status Server::Impl::handle_request(const Frame& request, Frame& response) {
  response.opcode = request.opcode;
  response.request_id = request.request_id;
  response.flags = 0;
  response.payload.clear();

  const auto digest_of = [&](std::span<const std::byte> payload) {
    Sha256 hasher;
    const std::uint16_t opcode = static_cast<std::uint16_t>(request.opcode);
    hasher.update(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&opcode), 2));
    hasher.update(payload);
    return hasher.finish();
  };
  if (request.request_id != 0) {
    std::unique_lock<std::mutex> lock(cache_mutex);
    const auto it = cache.find(request.request_id);
    if (it != cache.end()) {
      if (it->second.request_digest == digest_of(request.payload)) {
        std::unique_lock<std::mutex> stats_lock(stats_mutex);
        stats.requests_handled += 1;
        response.flags = it->second.flags;
        response.payload = it->second.payload;
        return ok_status();
      }
      return Error(ReasonCode::DuplicateDelivery,
                   "request identifier was reused with a different payload");
    }
  }

  const auto remember = [&](const std::vector<std::byte>& payload, std::uint16_t flags,
                            bool cacheable) {
    if (request.request_id == 0 || !cacheable) {
      return;
    }
    std::unique_lock<std::mutex> lock(cache_mutex);
    CachedResponse entry;
    entry.request_digest = digest_of(request.payload);
    entry.payload = payload;
    entry.flags = flags;
    cache[request.request_id] = std::move(entry);
    cache_order.push_back(request.request_id);
    while (cache.size() > bounds.max_idempotency_entries) {
      const std::uint64_t oldest = cache_order.front();
      cache_order.pop_front();
      cache.erase(oldest);
      std::unique_lock<std::mutex> stats_lock(stats_mutex);
      stats.requests_refused += 0;
    }
  };

  switch (request.opcode) {
    case Opcode::Hello: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      auto version = reader.u16();
      if (!version) {
        return version.error();
      }
      if (version.value() != kProtocolVersion) {
        return Error(ReasonCode::ProtocolVersionMismatch, "peer protocol version is not supported");
      }
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      BinWriter writer(256);
      Status status = writer.text(std::string(kProductName));
      if (!status) {
        return status.error();
      }
      status = writer.text(std::string(version_string()));
      if (!status) {
        return status.error();
      }
      status = writer.u64(kProtocolVersion);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      return ok_status();
    }
    case Opcode::Ping: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      BinWriter writer(128);
      const CoordinatorEpoch epoch = fabric->epoch();
      Status status = writer.u64(epoch.counter);
      if (!status) {
        return status.error();
      }
      status = writer.text(epoch.boot.value());
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      return ok_status();
    }
    case Opcode::Stats: {
      const std::string rendered = fabric->stats().render();
      BinWriter writer(rendered.size() + 64);
      Status status = writer.text(rendered);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      return ok_status();
    }
    case Opcode::RegisterFunction: {
      auto function = decode_exact<FunctionDescriptor>(request.payload, bounds,
                                                       wire::decode_function);
      if (!function) {
        return function.error();
      }
      Status status = fabric->register_function(function.value());
      if (!status) {
        return status.error();
      }
      remember(response.payload, 0, true);
      return ok_status();
    }
    case Opcode::IngestTopology: {
      auto topology = decode_exact<TopologySnapshot>(request.payload, bounds, wire::decode_topology);
      if (!topology) {
        return topology.error();
      }
      Status status = fabric->ingest_topology(topology.value());
      if (!status) {
        return status.error();
      }
      remember(response.payload, 0, true);
      return ok_status();
    }
    case Opcode::IngestCapabilities: {
      auto report = decode_exact<CapabilityReport>(request.payload, bounds,
                                                   wire::decode_capability_report);
      if (!report) {
        return report.error();
      }
      Status status = fabric->ingest_capabilities(report.value());
      if (!status) {
        return status.error();
      }
      remember(response.payload, 0, true);
      return ok_status();
    }
    case Opcode::IngestPolicy: {
      auto policy = decode_exact<PolicySnapshot>(request.payload, bounds, wire::decode_policy);
      if (!policy) {
        return policy.error();
      }
      Status status = fabric->ingest_policy(policy.value());
      if (!status) {
        return status.error();
      }
      remember(response.payload, 0, true);
      return ok_status();
    }
    case Opcode::IngestObservations: {
      auto report = decode_exact<ObservationReport>(request.payload, bounds,
                                                    wire::decode_observation_report);
      if (!report) {
        return report.error();
      }
      Status status = fabric->ingest_observations(report.value());
      if (!status) {
        return status.error();
      }
      remember(response.payload, 0, true);
      return ok_status();
    }
    case Opcode::GrantAuthority: {
      auto grant = decode_exact<AuthorityGrant>(request.payload, bounds, wire::decode_authority);
      if (!grant) {
        return grant.error();
      }
      Status status = fabric->grant_authority(grant.value());
      if (!status) {
        return status.error();
      }
      remember(response.payload, 0, true);
      return ok_status();
    }
    case Opcode::WithdrawAuthority: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      auto authority = reader.token();
      if (!authority) {
        return authority.error();
      }
      auto reason = reader.u16();
      if (!reason) {
        return reason.error();
      }
      if (std::string_view(to_string(static_cast<ReasonCode>(reason.value()))) ==
          "UNKNOWN_REASON") {
        return Error(ReasonCode::UnsupportedValue, "withdrawal carries an unknown reason code");
      }
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      Status status = fabric->withdraw_authority(AuthorityId::from_validated(authority.take()),
                                                 static_cast<ReasonCode>(reason.value()));
      if (!status) {
        return status.error();
      }
      remember(response.payload, 0, true);
      return ok_status();
    }
    case Opcode::ReportEffect: {
      auto report = decode_exact<EffectReport>(request.payload, bounds, wire::decode_effect_report);
      if (!report) {
        return report.error();
      }
      auto record = fabric->report_effect(report.value());
      if (!record) {
        return record.error();
      }
      BinWriter writer(bounds.max_request_bytes);
      Status status = wire::encode_assignment(record.value(), writer, bounds);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      remember(response.payload, 0, true);
      return ok_status();
    }
    case Opcode::Plan: {
      auto placement = decode_exact<PlacementRequest>(request.payload, bounds,
                                                      wire::decode_placement_request);
      if (!placement) {
        return placement.error();
      }
      auto result = fabric->plan(placement.value());
      if (!result) {
        return result.error();
      }
      BinWriter writer(bounds.max_request_bytes);
      Status status = wire::encode_plan_result(result.value(), writer, bounds);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      return ok_status();
    }
    case Opcode::Apply: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      auto placement = wire::decode_placement_request(reader, bounds);
      if (!placement) {
        return placement.error();
      }
      auto allow_replace = reader.boolean();
      if (!allow_replace) {
        return allow_replace.error();
      }
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      ApplyOptions options;
      options.request_id = placement.value().request_id;
      options.allow_replacement = allow_replace.value();
      options.cancel = &cancel;
      auto record = fabric->apply(placement.value(), options);
      if (!record) {
        return record.error();
      }
      BinWriter writer(bounds.max_request_bytes);
      Status status = wire::encode_assignment(record.value(), writer, bounds);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      remember(response.payload, 0, true);
      return ok_status();
    }
    case Opcode::Revoke: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      auto request_id = reader.token();
      if (!request_id) {
        return request_id.error();
      }
      auto assignment = reader.token();
      if (!assignment) {
        return assignment.error();
      }
      auto reason = reader.u16();
      if (!reason) {
        return reason.error();
      }
      if (std::string_view(to_string(static_cast<ReasonCode>(reason.value()))) ==
          "UNKNOWN_REASON") {
        return Error(ReasonCode::UnsupportedValue, "revocation carries an unknown reason code");
      }
      auto authority = reader.token();
      if (!authority) {
        return authority.error();
      }
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      RevokeRequest revoke;
      revoke.request_id = RequestId::from_validated(request_id.take());
      revoke.assignment = AssignmentId::from_validated(assignment.take());
      revoke.reason = static_cast<ReasonCode>(reason.value());
      revoke.authority = AuthorityId::from_validated(authority.take());
      revoke.cancel = &cancel;
      auto record = fabric->revoke(revoke);
      if (!record) {
        return record.error();
      }
      BinWriter writer(bounds.max_request_bytes);
      Status status = wire::encode_assignment(record.value(), writer, bounds);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      remember(response.payload, 0, true);
      return ok_status();
    }
    case Opcode::Replace: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      auto request_id = reader.token();
      if (!request_id) {
        return request_id.error();
      }
      auto current = reader.token();
      if (!current) {
        return current.error();
      }
      auto placement = wire::decode_placement_request(reader, bounds);
      if (!placement) {
        return placement.error();
      }
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      ReplaceRequest replace;
      replace.request_id = RequestId::from_validated(request_id.take());
      replace.current = AssignmentId::from_validated(current.take());
      replace.placement = placement.take();
      replace.cancel = &cancel;
      auto record = fabric->replace(replace);
      if (!record) {
        return record.error();
      }
      BinWriter writer(bounds.max_request_bytes);
      Status status = wire::encode_assignment(record.value(), writer, bounds);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      remember(response.payload, 0, true);
      return ok_status();
    }
    case Opcode::Reauthorize: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      auto request_id = reader.token();
      if (!request_id) {
        return request_id.error();
      }
      auto assignment = reader.token();
      if (!assignment) {
        return assignment.error();
      }
      auto authority = reader.token();
      if (!authority) {
        return authority.error();
      }
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      ReauthorizeRequest request_payload;
      request_payload.request_id = RequestId::from_validated(request_id.take());
      request_payload.assignment = AssignmentId::from_validated(assignment.take());
      request_payload.authority = AuthorityId::from_validated(authority.take());
      request_payload.cancel = &cancel;
      auto record = fabric->reauthorize(request_payload);
      if (!record) {
        return record.error();
      }
      BinWriter writer(bounds.max_request_bytes);
      Status status = wire::encode_assignment(record.value(), writer, bounds);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      remember(response.payload, 0, true);
      return ok_status();
    }
    case Opcode::Revalidate: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      auto report = fabric->revalidate(&cancel);
      if (!report) {
        return report.error();
      }
      BinWriter writer(bounds.max_request_bytes);
      Status status = wire::encode_revalidation(report.value(), writer, bounds);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      return ok_status();
    }
    case Opcode::GetAssignment: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      auto id = reader.token();
      if (!id) {
        return id.error();
      }
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      auto record = fabric->get_assignment(AssignmentId::from_validated(id.take()));
      if (!record) {
        return record.error();
      }
      BinWriter writer(bounds.max_request_bytes);
      Status status = wire::encode_assignment(record.value(), writer, bounds);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      return ok_status();
    }
    case Opcode::ListAssignments: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      auto filter = wire::decode_filter(reader);
      if (!filter) {
        return filter.error();
      }
      auto offset = reader.u64();
      if (!offset) {
        return offset.error();
      }
      auto limit = reader.u64();
      if (!limit) {
        return limit.error();
      }
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      std::size_t offset_value = 0;
      std::size_t limit_value = 0;
      if (!checked_cast<std::size_t>(offset.value(), offset_value) ||
          !checked_cast<std::size_t>(limit.value(), limit_value)) {
        return Error(ReasonCode::OutOfRange, "paging bounds do not fit in size_t");
      }
      bool truncated = false;
      auto records = fabric->list_assignments(filter.value(), offset_value, limit_value, truncated);
      if (!records) {
        return records.error();
      }
      BinWriter writer(bounds.max_request_bytes);
      Status status = writer.boolean(truncated);
      if (!status) {
        return status.error();
      }
      status = writer.u32(static_cast<std::uint32_t>(records.value().size()));
      if (!status) {
        return status.error();
      }
      for (const AssignmentRecord& record : records.value()) {
        status = wire::encode_assignment(record, writer, bounds);
        if (!status) {
          return status.error();
        }
      }
      encode_ok_payload(writer.data(), response.payload);
      return ok_status();
    }
    case Opcode::GetScope: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      auto id = reader.token();
      if (!id) {
        return id.error();
      }
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      auto view = fabric->get_scope(ScopeId::from_validated(id.take()));
      if (!view) {
        return view.error();
      }
      BinWriter writer(bounds.max_request_bytes);
      Status status = wire::encode_scope_view(view.value(), writer, bounds);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      return ok_status();
    }
    case Opcode::ExplainAssignment: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      auto id = reader.token();
      if (!id) {
        return id.error();
      }
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      auto explanation = fabric->explain_assignment(AssignmentId::from_validated(id.take()));
      if (!explanation) {
        return explanation.error();
      }
      std::string document;
      Status status = explanation_to_json(explanation.value(), document, bounds.max_export_bytes);
      if (!status) {
        return status.error();
      }
      BinWriter writer(document.size() + 64);
      status = writer.text(document);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      return ok_status();
    }
    case Opcode::ExplainRequest: {
      auto placement = decode_exact<PlacementRequest>(request.payload, bounds,
                                                      wire::decode_placement_request);
      if (!placement) {
        return placement.error();
      }
      auto explanation = fabric->explain_request(placement.value());
      if (!explanation) {
        return explanation.error();
      }
      std::string document;
      Status status = explanation_to_json(explanation.value(), document, bounds.max_export_bytes);
      if (!status) {
        return status.error();
      }
      BinWriter writer(document.size() + 64);
      status = writer.text(document);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      return ok_status();
    }
    case Opcode::StateDigest: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      const std::string digest = fabric->state_digest().hex();
      BinWriter writer(digest.size() + 16);
      Status status = writer.text(digest);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      return ok_status();
    }
    case Opcode::Export: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      auto format_raw = reader.u8();
      if (!format_raw) {
        return format_raw.error();
      }
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      ExportFormat format = ExportFormat::CanonicalJson;
      if (format_raw.value() < 1 || format_raw.value() > 3) {
        return Error(ReasonCode::UnsupportedValue, "export format is not supported");
      }
      format = static_cast<ExportFormat>(format_raw.value());
      std::string document;
      Status status = fabric->export_canonical(format, document);
      if (!status) {
        return status.error();
      }
      if (document.size() > limits.max_frame_bytes) {
        return Error(ReasonCode::ResponseTooLarge, "export exceeds the frame bound");
      }
      response.payload.assign(reinterpret_cast<const std::byte*>(document.data()),
                              reinterpret_cast<const std::byte*>(document.data()) + document.size());
      return ok_status();
    }
    case Opcode::RecoveryReport: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      const std::string rendered = fabric->recovery_report().render();
      BinWriter writer(rendered.size() + 64);
      Status status = writer.text(rendered);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      return ok_status();
    }
    case Opcode::VerifyInvariants: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      const std::string rendered = fabric->verify_invariants().render();
      BinWriter writer(rendered.size() + 64);
      Status status = writer.text(rendered);
      if (!status) {
        return status.error();
      }
      encode_ok_payload(writer.data(), response.payload);
      return ok_status();
    }
    case Opcode::Compact: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      Status status = fabric->compact();
      if (!status) {
        return status.error();
      }
      return ok_status();
    }
    case Opcode::Shutdown: {
      BinReader reader(request.payload, bounds.max_text_bytes);
      Status consumed = require_consumed(reader);
      if (!consumed) {
        return consumed.error();
      }
      return ok_status();
    }
  }
  return Error(ReasonCode::UnsupportedOpcode, "opcode is not implemented");
}

ServerStats Server::Impl::snapshot_stats() const {
  std::unique_lock<std::mutex> lock(stats_mutex);
  ServerStats copy = stats;
  copy.running = running.load(std::memory_order_acquire);
  return copy;
}

Server::Server(Fabric& fabric, ServerConfig config) : impl_(std::make_unique<Impl>()) {
  impl_->fabric = &fabric;
  impl_->config = std::move(config);
  impl_->bounds = impl_->fabric->bounds();
  impl_->limits.max_frame_bytes = impl_->bounds.max_frame_bytes;
}

Server::~Server() { (void)stop(); }

Status Server::start() {
  Impl& impl = *impl_;
  if (impl.running.load(std::memory_order_acquire)) {
    return Error(ReasonCode::AlreadyExists, "server is already running");
  }
  if (impl.config.max_workers == 0 || impl.config.max_workers > impl.bounds.max_workers) {
    return Error(ReasonCode::InvalidConfiguration, "worker count is outside the configured bound");
  }
  if (impl.config.max_queue_depth == 0 || impl.config.max_connections == 0) {
    return Error(ReasonCode::InvalidConfiguration, "connection bounds must be non-zero");
  }
  if (!detail::is_local_address(impl.config.bind_address) && impl.config.bind_address.empty()) {
    return Error(ReasonCode::EndpointInvalid, "bind address is empty");
  }
  Status status = detail::net_init();
  if (!status) {
    return status.error();
  }
  impl.net_initialized = true;
  auto listener = detail::listen_tcp(impl.config.bind_address, impl.config.port);
  if (!listener) {
    detail::net_shutdown();
    impl.net_initialized = false;
    return listener.error();
  }
  impl.listener = std::move(listener.value().socket);
  impl.port.store(listener.value().port, std::memory_order_release);
  auto wakeup = detail::make_wakeup_socket(impl.wakeup_port);
  if (!wakeup) {
    (void)impl.listener.close();
    detail::net_shutdown();
    impl.net_initialized = false;
    return wakeup.error();
  }
  impl.wakeup = wakeup.take();
  impl.stopping.store(false, std::memory_order_release);
  impl.running.store(true, std::memory_order_release);
  impl.acceptor = std::thread([&impl]() { impl.accept_loop(); });
  impl.workers.reserve(impl.config.max_workers);
  for (std::size_t i = 0; i < impl.config.max_workers; ++i) {
    impl.workers.emplace_back([&impl]() { impl.worker_loop(); });
  }
  {
    std::unique_lock<std::mutex> lock(impl.stats_mutex);
    impl.stats.running = true;
  }
  return ok_status();
}

Status Server::stop() {
  Impl& impl = *impl_;
  if (!impl.running.exchange(false)) {
    if (impl.net_initialized) {
      detail::net_shutdown();
      impl.net_initialized = false;
    }
    return ok_status();
  }
  impl.stopping.store(true, std::memory_order_release);
  impl.cancel.cancel();
  (void)detail::send_wakeup(impl.wakeup, impl.wakeup_port);
  {
    std::unique_lock<std::mutex> lock(impl.queue_mutex);
    impl.queue_cv.notify_all();
  }
  if (impl.acceptor.joinable()) {
    impl.acceptor.join();
  }
  std::vector<std::uintptr_t> handles;
  {
    std::unique_lock<std::mutex> lock(impl.connections_mutex);
    handles.reserve(impl.connections.size());
    for (const auto& entry : impl.connections) {
      handles.push_back(entry.second.handle);
    }
  }
  for (const std::uintptr_t handle : handles) {
    detail::Socket socket(handle);
    (void)socket.shutdown_both();
  }
  {
    std::unique_lock<std::mutex> lock(impl.queue_mutex);
    impl.queue_cv.notify_all();
  }
  for (std::thread& worker : impl.workers) {
    if (worker.joinable()) {
      worker.join();
    }
  }
  impl.workers.clear();
  {
    std::unique_lock<std::mutex> lock(impl.queue_mutex);
    while (!impl.queue.empty()) {
      detail::Socket socket = std::move(impl.queue.front());
      impl.queue.pop_front();
      (void)socket.close();
    }
  }
  {
    std::unique_lock<std::mutex> lock(impl.connections_mutex);
    impl.connections.clear();
  }
  (void)impl.listener.close();
  (void)impl.wakeup.close();
  {
    std::unique_lock<std::mutex> lock(impl.stats_mutex);
    impl.stats.running = false;
    impl.stats.open_connections = 0;
    impl.stats.in_flight_requests = 0;
    impl.stats.shutdowns += 1;
  }
  if (impl.net_initialized) {
    detail::net_shutdown();
    impl.net_initialized = false;
  }
  return ok_status();
}

bool Server::running() const noexcept { return impl_->running.load(std::memory_order_acquire); }

std::uint16_t Server::port() const noexcept { return impl_->port.load(std::memory_order_acquire); }

std::string Server::endpoint() const {
  return impl_->config.bind_address + ":" + std::to_string(port());
}

ServerStats Server::stats() const { return impl_->snapshot_stats(); }

Status Server::dispatch(const Frame& request, Frame& response) {
  return impl_->handle_request(request, response);
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

struct Client::Impl {
  detail::Socket socket{};
  Bounds bounds{};
  FrameLimits limits{};
  FrameDecoder decoder{FrameLimits{}};
  bool closed = false;
};

Client::Client() : impl_(std::make_unique<Impl>()) {}

Client::~Client() { (void)close(); }

Result<std::unique_ptr<Client>> Client::connect(const std::string& host, std::uint16_t port,
                                                Bounds bounds) {
  Status status = detail::net_init();
  if (!status) {
    return status.error();
  }
  auto socket = detail::connect_tcp(host, port);
  if (!socket) {
    detail::net_shutdown();
    return socket.error();
  }
  auto client = std::unique_ptr<Client>(new Client());
  client->impl_->socket = socket.take();
  client->impl_->bounds = bounds;
  client->impl_->limits.max_frame_bytes = bounds.max_frame_bytes;
  client->impl_->decoder = FrameDecoder(client->impl_->limits);
  return client;
}

Status Client::send(const Frame& request) {
  Impl& impl = *impl_;
  if (impl.closed) {
    return Error(ReasonCode::PeerClosed, "client is closed");
  }
  std::vector<std::byte> bytes;
  Status status = encode_frame(request, bytes, impl.limits);
  if (!status) {
    return status.error();
  }
  auto sent = impl.socket.send_bytes(bytes);
  if (!sent) {
    return sent.error();
  }
  return ok_status();
}

Result<Frame> Client::receive() {
  Impl& impl = *impl_;
  if (impl.closed) {
    return Error(ReasonCode::PeerClosed, "client is closed");
  }
  for (;;) {
    Frame frame;
    auto next = impl.decoder.next(frame);
    if (!next) {
      return next.error();
    }
    if (next.value()) {
      return frame;
    }
    std::byte buffer[16384];
    auto received = impl.socket.receive_bytes(std::span<std::byte>(buffer, sizeof(buffer)));
    if (!received) {
      return Error(ReasonCode::PeerClosed, "peer closed the connection");
    }
    if (received.value() == 0) {
      return Error(ReasonCode::PeerClosed, "peer closed the connection");
    }
    impl.decoder.feed(std::span<const std::byte>(buffer, received.value()));
  }
}

Result<Frame> Client::call(const Frame& request) {
  Status status = send(request);
  if (!status) {
    return status.error();
  }
  auto response = receive();
  if (!response) {
    return response.error();
  }
  if (response.value().request_id != request.request_id) {
    return Error(ReasonCode::RequestDigestMismatch,
                 "response does not correlate with the request identifier");
  }
  if ((response.value().flags & kFlagError) != 0) {
    auto error = decode_error_payload(response.value().payload, impl_->bounds);
    if (!error) {
      return error.error();
    }
    return error.value();
  }
  return response;
}

Status Client::close() {
  Impl& impl = *impl_;
  if (impl.closed) {
    return ok_status();
  }
  impl.closed = true;
  (void)impl.socket.shutdown_both();
  Status status = impl.socket.close();
  detail::net_shutdown();
  return status;
}

bool Client::closed() const noexcept { return impl_->closed; }

}  // namespace nof::service
