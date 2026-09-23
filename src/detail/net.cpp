#include "detail/net.hpp"

#include <atomic>
#include <cstring>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace nof::detail {

namespace {

#if defined(_WIN32)
using native_socket = SOCKET;
constexpr native_socket kInvalid = INVALID_SOCKET;
std::atomic<int> g_winsock_refs{0};

native_socket to_native(std::uintptr_t handle) { return static_cast<native_socket>(handle); }
std::uintptr_t from_native(native_socket handle) { return static_cast<std::uintptr_t>(handle); }
int last_error() { return WSAGetLastError(); }
#else
using native_socket = int;
constexpr native_socket kInvalid = -1;
int last_error() { return errno; }

native_socket to_native(std::uintptr_t handle) { return static_cast<native_socket>(handle); }
std::uintptr_t from_native(native_socket handle) { return static_cast<std::uintptr_t>(handle); }
#endif

Error socket_error(const char* what) {
  return Error(ReasonCode::ConnectionRefused, std::string(what) + " failed");
}

bool parse_ipv4(const std::string& address, std::uint32_t& out) {
  in_addr parsed{};
  if (inet_pton(AF_INET, address.c_str(), &parsed) != 1) {
    return false;
  }
  out = parsed.s_addr;
  return true;
}

}  // namespace

Status net_init() {
  // Winsock reference counting: the first caller initializes, the last one
  // tears down. No hidden global state is required from the caller.
#if defined(_WIN32)
  if (g_winsock_refs.fetch_add(1) == 0) {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
      g_winsock_refs.fetch_sub(1);
      return Error(ReasonCode::ConnectionRefused, "winsock initialization failed");
    }
  }
#endif
  return ok_status();
}

void net_shutdown() {
#if defined(_WIN32)
  if (g_winsock_refs.fetch_sub(1) == 1) {
    WSACleanup();
  }
#endif
}

Socket::~Socket() { (void)close(); }

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    (void)close();
    handle_ = other.handle_;
    other.handle_ = kInvalidHandle;
  }
  return *this;
}

Status Socket::set_reuse_address() {
  if (!valid()) {
    return socket_error("set_reuse_address");
  }
  int one = 1;
  if (setsockopt(to_native(handle_), SOL_SOCKET, SO_REUSEADDR,
                 reinterpret_cast<const char*>(&one), sizeof(one)) != 0) {
    return socket_error("setsockopt(SO_REUSEADDR)");
  }
  return ok_status();
}

Status Socket::shutdown_both() noexcept {
  if (!valid()) {
    return ok_status();
  }
#if defined(_WIN32)
  if (::shutdown(to_native(handle_), SD_BOTH) != 0) {
    const int code = last_error();
    if (code != WSAENOTCONN && code != WSAEINVAL) {
      return socket_error("shutdown");
    }
  }
#else
  if (::shutdown(to_native(handle_), SHUT_RDWR) != 0) {
    if (errno != ENOTCONN && errno != EINVAL) {
      return socket_error("shutdown");
    }
  }
#endif
  return ok_status();
}

Status Socket::close() noexcept {
  if (!valid()) {
    return ok_status();
  }
#if defined(_WIN32)
  const int result = closesocket(to_native(handle_));
#else
  const int result = ::close(to_native(handle_));
#endif
  handle_ = kInvalidHandle;
  if (result != 0) {
    return socket_error("close");
  }
  return ok_status();
}

Result<std::size_t> Socket::send_bytes(std::span<const std::byte> data) {
  if (!valid()) {
    return socket_error("send on closed socket");
  }
  std::size_t sent = 0;
  while (sent < data.size()) {
    const std::size_t chunk = data.size() - sent;
    const int request = static_cast<int>(chunk > 1u << 20 ? (1u << 20) : chunk);
    const int written = ::send(to_native(handle_),
                               reinterpret_cast<const char*>(data.data() + sent), request, 0);
    if (written <= 0) {
      return socket_error("send");
    }
    sent += static_cast<std::size_t>(written);
  }
  return sent;
}

Result<std::size_t> Socket::receive_bytes(std::span<std::byte> buffer) {
  if (!valid()) {
    return socket_error("receive on closed socket");
  }
  if (buffer.empty()) {
    return std::size_t{0};
  }
  const std::size_t request = buffer.size() > (1u << 20) ? (1u << 20) : buffer.size();
  const int read = ::recv(to_native(handle_), reinterpret_cast<char*>(buffer.data()),
                          static_cast<int>(request), 0);
  if (read < 0) {
    return socket_error("recv");
  }
  return static_cast<std::size_t>(read);
}

Result<BoundListener> listen_tcp(const std::string& address, std::uint16_t port) {
  std::uint32_t parsed = 0;
  if (!parse_ipv4(address, parsed)) {
    return Error(ReasonCode::EndpointInvalid, "listen address must be a literal IPv4 address");
  }
  native_socket handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle == kInvalid) {
    return socket_error("socket");
  }
  Socket socket(from_native(handle));
  Status status = socket.set_reuse_address();
  if (!status) {
    return status.error();
  }
  sockaddr_in endpoint{};
  endpoint.sin_family = AF_INET;
  endpoint.sin_port = htons(port);
  endpoint.sin_addr.s_addr = parsed;
  if (::bind(handle, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint)) != 0) {
    return socket_error("bind");
  }
  if (::listen(handle, 64) != 0) {
    return socket_error("listen");
  }
  sockaddr_in actual{};
#if defined(_WIN32)
  int length = sizeof(actual);
#else
  socklen_t length = sizeof(actual);
#endif
  if (getsockname(handle, reinterpret_cast<sockaddr*>(&actual), &length) != 0) {
    return socket_error("getsockname");
  }
  BoundListener out;
  out.socket = std::move(socket);
  out.port = ntohs(actual.sin_port);
  return out;
}

Result<Socket> accept_tcp(const Socket& listener) {
  if (!listener.valid()) {
    return socket_error("accept on closed listener");
  }
  const native_socket accepted = ::accept(to_native(listener.handle()), nullptr, nullptr);
  if (accepted == kInvalid) {
    return socket_error("accept");
  }
  return Socket(from_native(accepted));
}

Result<Socket> connect_tcp(const std::string& host, std::uint16_t port) {
  std::string address = host;
  if (host == "localhost" || host.empty()) {
    address = "127.0.0.1";
  }
  std::uint32_t parsed = 0;
  if (!parse_ipv4(address, parsed)) {
    return Error(ReasonCode::EndpointInvalid, "connect address must be a literal IPv4 address");
  }
  native_socket handle = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (handle == kInvalid) {
    return socket_error("socket");
  }
  Socket socket(from_native(handle));
  sockaddr_in endpoint{};
  endpoint.sin_family = AF_INET;
  endpoint.sin_port = htons(port);
  endpoint.sin_addr.s_addr = parsed;
  if (::connect(handle, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint)) != 0) {
    return socket_error("connect");
  }
  return socket;
}

Result<Socket> make_wakeup_socket(std::uint16_t& bound_port) {
  native_socket handle = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (handle == kInvalid) {
    return socket_error("socket(udp)");
  }
  Socket socket(from_native(handle));
  sockaddr_in endpoint{};
  endpoint.sin_family = AF_INET;
  endpoint.sin_port = htons(0);
  endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::bind(handle, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint)) != 0) {
    return socket_error("bind(udp)");
  }
  sockaddr_in actual{};
#if defined(_WIN32)
  int length = sizeof(actual);
#else
  socklen_t length = sizeof(actual);
#endif
  if (getsockname(handle, reinterpret_cast<sockaddr*>(&actual), &length) != 0) {
    return socket_error("getsockname(udp)");
  }
  bound_port = ntohs(actual.sin_port);
  return socket;
}

Status send_wakeup(const Socket& wakeup, std::uint16_t port) {
  if (!wakeup.valid()) {
    return socket_error("wakeup socket is closed");
  }
  sockaddr_in endpoint{};
  endpoint.sin_family = AF_INET;
  endpoint.sin_port = htons(port);
  endpoint.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  const char payload = 1;
  if (::sendto(to_native(wakeup.handle()), &payload, 1, 0, reinterpret_cast<sockaddr*>(&endpoint),
               sizeof(endpoint)) < 0) {
    return socket_error("sendto(wakeup)");
  }
  return ok_status();
}

Status wait_readable(const Socket& a, const Socket& b, bool& a_ready, bool& b_ready) {
  a_ready = false;
  b_ready = false;
  if (!a.valid() && !b.valid()) {
    return Error(ReasonCode::ShuttingDown, "no socket to wait on");
  }
  fd_set read_set;
  FD_ZERO(&read_set);
  native_socket max_handle = 0;
  if (a.valid()) {
    const native_socket handle = to_native(a.handle());
    FD_SET(handle, &read_set);
    if (handle > max_handle) {
      max_handle = handle;
    }
  }
  if (b.valid()) {
    const native_socket handle = to_native(b.handle());
    FD_SET(handle, &read_set);
    if (handle > max_handle) {
      max_handle = handle;
    }
  }
#if defined(_WIN32)
  const int ready = ::select(0, &read_set, nullptr, nullptr, nullptr);
#else
  const int ready = ::select(max_handle + 1, &read_set, nullptr, nullptr, nullptr);
#endif
  if (ready < 0) {
    return socket_error("select");
  }
  a_ready = a.valid() && FD_ISSET(to_native(a.handle()), &read_set) != 0;
  b_ready = b.valid() && FD_ISSET(to_native(b.handle()), &read_set) != 0;
  return ok_status();
}

bool is_local_address(const std::string& address) noexcept {
  return address == "127.0.0.1" || address == "localhost" || address == "::1";
}

}  // namespace nof::detail
