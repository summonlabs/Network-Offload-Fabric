#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "nof/bounds.hpp"
#include "nof/cancel.hpp"
#include "nof/error.hpp"
#include "nof/fabric.hpp"
#include "nof/wire.hpp"

// Framed, bounded service transport. Threads alone cannot prove multiprocess
// behaviour, so the protocol is exercised by independent OS processes over real
// sockets in the test suite.
namespace nof::service {

enum class Opcode : std::uint16_t {
  Hello = 1,
  Ping = 2,
  Stats = 3,
  RegisterFunction = 4,
  IngestTopology = 5,
  IngestCapabilities = 6,
  IngestPolicy = 7,
  IngestObservations = 8,
  GrantAuthority = 9,
  WithdrawAuthority = 10,
  ReportEffect = 11,
  Plan = 12,
  Apply = 13,
  Revoke = 14,
  Replace = 15,
  Reauthorize = 16,
  Revalidate = 17,
  GetAssignment = 18,
  ListAssignments = 19,
  GetScope = 20,
  ExplainAssignment = 21,
  ExplainRequest = 22,
  StateDigest = 23,
  Export = 24,
  RecoveryReport = 25,
  VerifyInvariants = 26,
  Compact = 27,
  Shutdown = 28,
};

const char* to_string(Opcode value) noexcept;
bool parse_opcode(std::uint16_t value, Opcode& out) noexcept;

struct Frame {
  Opcode opcode = Opcode::Hello;
  std::uint16_t flags = 0;
  std::uint64_t request_id = 0;
  std::vector<std::byte> payload{};

  friend bool operator==(const Frame&, const Frame&) = default;
};

struct FrameLimits {
  std::size_t max_frame_bytes = 1024u * 1024u;
};

// Frame layout: magic "NF" (2), protocol version (2), opcode (2), flags (2),
// request id (8), payload length (4), payload, CRC-32C over everything before
// it (4). Total header 20 bytes plus payload plus 4 bytes of CRC.
inline constexpr std::size_t kFrameHeaderBytes = 20;
inline constexpr std::size_t kFrameTrailerBytes = 4;
inline constexpr std::uint16_t kFrameMagic = 0x4E46;  // 'N','F'

Status encode_frame(const Frame& frame, std::vector<std::byte>& out, const FrameLimits& limits);
Result<Frame> decode_frame(std::span<const std::byte> bytes, const FrameLimits& limits);

// Streaming decoder for socket reads that arrive in arbitrary chunks. It never
// allocates more than max_frame_bytes and refuses a frame whose declared length
// exceeds the bound before reading the payload.
class FrameDecoder {
 public:
  explicit FrameDecoder(FrameLimits limits) : limits_(limits) {}

  void feed(std::span<const std::byte> bytes);
  // Pops one complete, CRC-valid frame. Returns a refusal for a frame that is
  // structurally invalid; the caller must close the connection.
  Result<bool> next(Frame& out);
  // Called at EOF. A pending partial frame is a refusal.
  Status finish() const;
  std::size_t buffered() const noexcept { return buffer_.size(); }
  std::size_t consumed() const noexcept { return consumed_; }

 private:
  FrameLimits limits_;
  std::vector<std::byte> buffer_;
  std::size_t consumed_ = 0;
};

struct ServerConfig {
  std::string bind_address = "127.0.0.1";
  std::uint16_t port = 0;  // 0 asks the OS for an ephemeral port
  Bounds bounds{};
  std::size_t max_connections = 32;
  std::size_t max_workers = 4;
  std::size_t max_queue_depth = 64;
  // Invoked when a peer requests an orderly shutdown, so an embedding process
  // can begin teardown without polling for it.
  std::function<void()> shutdown_hook{};
};

struct ServerStats {
  std::uint64_t connections_accepted = 0;
  std::uint64_t connections_refused = 0;
  std::uint64_t frames_accepted = 0;
  std::uint64_t frames_refused = 0;
  std::uint64_t requests_handled = 0;
  std::uint64_t requests_refused = 0;
  std::uint64_t shutdowns = 0;
  std::uint64_t bytes_received = 0;
  std::uint64_t bytes_sent = 0;
  std::size_t open_connections = 0;
  std::size_t in_flight_requests = 0;
  std::size_t queued_connections = 0;
  bool running = false;
};

// Bounded worker pool serving a Fabric over TCP. Shutdown ordering is explicit:
// the listener stops accepting, in-flight requests are cancelled and drained,
// workers are joined without holding any lock a worker needs, and only then is
// the fabric shut down.
class Server {
 public:
  Server(Fabric& fabric, ServerConfig config);
  ~Server();
  Server(const Server&) = delete;
  Server& operator=(const Server&) = delete;

  Status start();
  Status stop();
  bool running() const noexcept;
  std::uint16_t port() const noexcept;
  std::string endpoint() const;
  ServerStats stats() const;
  // Handles exactly one request against the fabric. Shared by the server and by
  // in-process tests so that the transport path and the direct path agree.
  Status dispatch(const Frame& request, Frame& response);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

class Client {
 public:
  ~Client();
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;

  static Result<std::unique_ptr<Client>> connect(const std::string& host, std::uint16_t port,
                                                Bounds bounds);

  // Sends one request and waits for its response. Bounded payloads only; a
  // response larger than the bound is a refusal, not a truncated success.
  Result<Frame> call(const Frame& request);

  // Sends a request without waiting, for reordering and pipelining tests.
  Status send(const Frame& request);
  Result<Frame> receive();

  Status close();
  bool closed() const noexcept;

 private:
  Client();

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

// Payload helpers shared by client and server.
void encode_error_payload(const Error& error, std::vector<std::byte>& out, const Bounds& bounds);
Result<Error> decode_error_payload(std::span<const std::byte> payload, const Bounds& bounds);

}  // namespace nof::service
