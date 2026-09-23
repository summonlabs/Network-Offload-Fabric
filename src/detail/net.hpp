#pragma once

#include <cstdint>
#include <span>
#include <string>

#include "nof/error.hpp"

// Thin, explicit socket layer. Blocking sockets plus select() on the listener
// and a local wakeup datagram socket: shutdown never polls, never sleeps, and
// never depends on a timeout to notice that the listener must stop.
namespace nof::detail {

Status net_init();
void net_shutdown();

class Socket {
 public:
  Socket() = default;
  explicit Socket(std::uintptr_t handle) : handle_(handle) {}
  ~Socket();

  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept : handle_(other.handle_) { other.handle_ = kInvalidHandle; }
  Socket& operator=(Socket&& other) noexcept;

  bool valid() const noexcept { return handle_ != kInvalidHandle; }
  std::uintptr_t handle() const noexcept { return handle_; }

  Status set_reuse_address();
  Status shutdown_both() noexcept;
  Status close() noexcept;

  // Returns 0 when the peer closed cleanly.
  Result<std::size_t> send_bytes(std::span<const std::byte> data);
  Result<std::size_t> receive_bytes(std::span<std::byte> buffer);

  static constexpr std::uintptr_t kInvalidHandle = static_cast<std::uintptr_t>(~0ull);

 private:
  std::uintptr_t handle_ = kInvalidHandle;
};

struct BoundListener {
  Socket socket{};
  std::uint16_t port = 0;
};

// Binds and listens on the given address. Port 0 asks the operating system for
// an ephemeral port, which the returned value reports.
Result<BoundListener> listen_tcp(const std::string& address, std::uint16_t port);
Result<Socket> accept_tcp(const Socket& listener);

// Connects to a literal IPv4 address or the name "localhost".
Result<Socket> connect_tcp(const std::string& host, std::uint16_t port);

// Local datagram socket used only to interrupt select() during shutdown.
Result<Socket> make_wakeup_socket(std::uint16_t& bound_port);
Status send_wakeup(const Socket& wakeup, std::uint16_t port);

// Waits until either socket becomes readable. `readable` reports which one.
Status wait_readable(const Socket& a, const Socket& b, bool& a_ready, bool& b_ready);

bool is_local_address(const std::string& address) noexcept;

}  // namespace nof::detail
