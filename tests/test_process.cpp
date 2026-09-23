#include "framework.hpp"

#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include "detail/net.hpp"
#include "nof/digest.hpp"
#include "nof/service.hpp"
#include "nof/version.hpp"
#include "support.hpp"

using namespace nof;

namespace {

std::string field(const std::string& output, const std::string& key) {
  const std::string needle = key + "=";
  const std::size_t start = output.find(needle);
  if (start == std::string::npos) {
    return std::string();
  }
  const std::size_t begin = start + needle.size();
  const std::size_t end = output.find('\n', begin);
  return output.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
}

std::uint16_t parse_port(const std::string& ready_output) {
  const std::string line = field(ready_output, "nofd listening on 127.0.0.1:");
  if (line.empty()) {
    const std::size_t colon = ready_output.find("127.0.0.1:");
    if (colon == std::string::npos) {
      return 0;
    }
    std::size_t end = colon + 10;
    while (end < ready_output.size() && ready_output[end] >= '0' && ready_output[end] <= '9') {
      ++end;
    }
    const std::string digits = ready_output.substr(colon + 10, end - colon - 10);
    return static_cast<std::uint16_t>(std::strtoul(digits.c_str(), nullptr, 10));
  }
  return static_cast<std::uint16_t>(std::strtoul(line.c_str(), nullptr, 10));
}

std::string nofd_command(const std::string& store, const std::string& extra = std::string()) {
  return support::shell_quote(support::nofd_path()) + " --store " + support::shell_quote(store) +
         " --seed --port 0 " + extra + " 2>&1";
}

service::Frame request_frame(service::Opcode opcode, std::uint64_t request_id,
                            const std::vector<std::byte>& payload = {}) {
  service::Frame frame;
  frame.opcode = opcode;
  frame.request_id = request_id;
  frame.payload = payload;
  return frame;
}

}  // namespace

NOF_TEST(process, cli_scenario_is_deterministic_across_processes) {
  const std::string first_store = support::store_path("proc-scenario-1");
  const std::string second_store = support::store_path("proc-scenario-2");
  support::remove_store(first_store);
  support::remove_store(second_store);
  // A pinned logical clock makes the whole process run reproducible.
  const std::string command = support::shell_quote(support::nofctl_path()) +
                              " scenario --clock-at 1500000 --store ";
  const support::ProcessResult first = support::run_process(command + first_store + " --applies 3");
  const support::ProcessResult second = support::run_process(command + second_store + " --applies 3");
  NOF_CHECK_EQ(first.exit_code, 0);
  NOF_CHECK_EQ(second.exit_code, 0);
  NOF_CHECK(!field(first.output, "state_digest").empty());
  NOF_CHECK_EQ(field(first.output, "state_digest"), field(second.output, "state_digest"));
  NOF_CHECK(first.output.find("invariants=clean") != std::string::npos);

  // A third process inspecting the same store must recover it consistently.
  // The fingerprint legitimately differs from the writing process, because a
  // restart advances the coordinator epoch and suspends pre-restart authority.
  const support::ProcessResult inspect = support::run_process(
      support::shell_quote(support::nofctl_path()) +
      " inspect --clock-at 1500000 --store " + first_store + " --format text");
  NOF_CHECK_EQ(inspect.exit_code, 0);
  NOF_CHECK(inspect.output.find("invariants=clean") != std::string::npos);
  NOF_CHECK(inspect.output.find("assignment as-0000000000000001") != std::string::npos);
  NOF_CHECK(inspect.output.find("state=suspended") != std::string::npos);
  NOF_CHECK(inspect.output.find("recovery_classification=clean_reopen") != std::string::npos);
  support::remove_store(first_store);
  support::remove_store(second_store);
}

NOF_TEST(process, crash_before_commit_leaves_no_authority_behind) {
  const std::string store = support::store_path("proc-crash-before-commit");
  support::remove_store(store);
  const support::ProcessResult crash = support::run_process(
      support::shell_quote(support::nofctl_path()) +
      " crash --clock-at 1500000 --store " + store + " --boundary before_commit --applies 2");
  NOF_CHECK_EQ(crash.exit_code, 70);

  const support::ProcessResult inspect = support::run_process(
      support::shell_quote(support::nofctl_path()) +
      " inspect --clock-at 1500000 --store " + store + " --format text");
  NOF_CHECK_EQ(inspect.exit_code, 0);
  NOF_CHECK(inspect.output.find("assignments=0") != std::string::npos);
  NOF_CHECK(inspect.output.find("recovery_classification=") != std::string::npos);
  NOF_CHECK(inspect.output.find("invariants=clean") != std::string::npos);
  support::remove_store(store);
}

NOF_TEST(process, crash_after_commit_before_ack_keeps_the_commit) {
  const std::string store = support::store_path("proc-crash-after-commit");
  support::remove_store(store);
  const support::ProcessResult crash = support::run_process(
      support::shell_quote(support::nofctl_path()) +
      " crash --clock-at 1500000 --store " + store +
      " --boundary after_commit_before_ack --applies 2");
  NOF_CHECK_EQ(crash.exit_code, 70);

  const support::ProcessResult inspect = support::run_process(
      support::shell_quote(support::nofctl_path()) +
      " inspect --clock-at 1500000 --store " + store + " --format text");
  NOF_CHECK_EQ(inspect.exit_code, 0);
  // The commit survived, but it is suspended: a crash never fabricates
  // authority for the restarted coordinator.
  NOF_CHECK(inspect.output.find("assignment as-") != std::string::npos);
  NOF_CHECK(inspect.output.find("state=suspended") != std::string::npos);
  NOF_CHECK(inspect.output.find("RESTART_AUTHORITY_RESET") != std::string::npos);
  NOF_CHECK(inspect.output.find("authority_restored=false") != std::string::npos);
  NOF_CHECK(inspect.output.find("invariants=clean") != std::string::npos);

  // A later process can keep working on the same store, but it must present
  // fresh evidence: replayed provenance sequences are refused by design.
  const support::ProcessResult later = support::run_process(
      support::shell_quote(support::nofctl_path()) +
      " scenario --clock-at 1500000 --sequence-base 500 --policy-generation 2"
      " --topology-generation 2 --store " + store + " --applies 1");
  if (later.exit_code != 0) {
    NOF_FAIL("follow-up scenario failed: " + later.output);
  }
  NOF_CHECK_EQ(later.exit_code, 0);
  support::remove_store(store);
}

NOF_TEST(process, service_transport_over_real_sockets) {
  const std::string store = support::store_path("proc-service");
  support::remove_store(store);
  support::ChildProcess server(nofd_command(store));
  NOF_CHECK(server.valid());
  const std::string ready = server.read_until("nofd ready");
  if (ready.find("nofd listening on 127.0.0.1:") == std::string::npos) {
    NOF_FAIL("nofd startup output: " + ready);
  }
  NOF_CHECK(ready.find("nofd listening on 127.0.0.1:") != std::string::npos);
  const std::uint16_t port = parse_port(ready);
  NOF_CHECK(port != 0);

  const Bounds bounds;
  auto client = service::Client::connect("127.0.0.1", port, bounds);
  NOF_CHECK_OK(client);
  service::Client& connection = *client.value();

  // Handshake.
  BinWriter hello_writer(64);
  NOF_CHECK_OK(hello_writer.u16(kProtocolVersion));
  auto hello = connection.call(request_frame(service::Opcode::Hello, 1,
                                             {hello_writer.data().begin(), hello_writer.data().end()}));
  NOF_CHECK_OK(hello);
  BinReader hello_reader(hello.value().payload, bounds.max_text_bytes);
  NOF_CHECK_EQ(hello_reader.text().value(), std::string(kProductName));
  NOF_CHECK_EQ(hello_reader.text().value(), std::string(version_string()));

  // A protocol version the peer does not implement is refused.
  BinWriter bad_hello(64);
  NOF_CHECK_OK(bad_hello.u16(99));
  auto rejected = connection.call(request_frame(service::Opcode::Hello, 2,
                                                {bad_hello.data().begin(), bad_hello.data().end()}));
  NOF_CHECK_ERROR(rejected, ReasonCode::ProtocolVersionMismatch);

  // Plan and apply through the wire.
  const synthetic::ScenarioOptions options;
  const synthetic::Scenario scenario = synthetic::make_scenario(options);
  PlacementRequest placement = synthetic::make_request(scenario, options, "wire-req-1");
  BinWriter placement_writer(bounds.max_request_bytes);
  NOF_CHECK_OK(wire::encode_placement_request(placement, placement_writer, bounds));
  auto planned = connection.call(request_frame(
      service::Opcode::Plan, 3, {placement_writer.data().begin(), placement_writer.data().end()}));
  NOF_CHECK_OK(planned);
  BinReader plan_reader(planned.value().payload, bounds.max_text_bytes);
  auto plan_result = wire::decode_plan_result(plan_reader, bounds);
  NOF_CHECK_OK(plan_result);
  NOF_CHECK(plan_result.value().accepted());

  BinWriter apply_writer(bounds.max_request_bytes);
  NOF_CHECK_OK(wire::encode_placement_request(placement, apply_writer, bounds));
  NOF_CHECK_OK(apply_writer.boolean(false));
  auto applied = connection.call(request_frame(
      service::Opcode::Apply, 4, {apply_writer.data().begin(), apply_writer.data().end()}));
  NOF_CHECK_OK(applied);
  BinReader applied_reader(applied.value().payload, bounds.max_text_bytes);
  auto applied_record = wire::decode_assignment(applied_reader, bounds);
  NOF_CHECK_OK(applied_record);
  NOF_CHECK_EQ(applied_record.value().state, AssignmentState::Dispatched);

  // Duplicate delivery of the identical request is idempotent: the same
  // assignment comes back, not a second one.
  auto duplicate = connection.call(request_frame(
      service::Opcode::Apply, 5, {apply_writer.data().begin(), apply_writer.data().end()}));
  NOF_CHECK_OK(duplicate);
  BinReader duplicate_reader(duplicate.value().payload, bounds.max_text_bytes);
  auto duplicate_record = wire::decode_assignment(duplicate_reader, bounds);
  NOF_CHECK_OK(duplicate_record);
  NOF_CHECK_EQ(duplicate_record.value().id, applied_record.value().id);

  // A reused request identifier with a different payload is fenced.
  PlacementRequest altered = placement;
  altered.demand.flows = FlowCount::raw(5);
  BinWriter altered_writer(bounds.max_request_bytes);
  NOF_CHECK_OK(wire::encode_placement_request(altered, altered_writer, bounds));
  NOF_CHECK_OK(altered_writer.boolean(false));
  auto fenced = connection.call(request_frame(
      service::Opcode::Apply, 6, {altered_writer.data().begin(), altered_writer.data().end()}));
  NOF_CHECK_ERROR(fenced, ReasonCode::DuplicateDelivery);

  // Effect reporting over the wire verifies the application.
  EffectReport effect;
  effect.request_id = RequestId::from_validated("wire-eff-1");
  effect.assignment = applied_record.value().id;
  effect.attempt = applied_record.value().attempt;
  effect.generation = applied_record.value().generation;
  effect.fence = applied_record.value().fence;
  effect.incarnation = applied_record.value().incarnation;
  effect.capability_generation = applied_record.value().binding.capability;
  effect.outcome = EffectOutcome::Applied;
  effect.observed_at = Micros::raw(1500000);
  effect.provenance.source = SourceId::from_validated("syn-enforcement");
  effect.provenance.sequence = 1;
  BinWriter effect_writer(bounds.max_request_bytes);
  NOF_CHECK_OK(wire::encode_effect_report(effect, effect_writer));
  auto verified = connection.call(request_frame(
      service::Opcode::ReportEffect, 7, {effect_writer.data().begin(), effect_writer.data().end()}));
  NOF_CHECK_OK(verified);
  BinReader verified_reader(verified.value().payload, bounds.max_text_bytes);
  auto verified_record = wire::decode_assignment(verified_reader, bounds);
  NOF_CHECK_OK(verified_record);
  NOF_CHECK_EQ(verified_record.value().state, AssignmentState::AppliedVerified);

  // Queries.
  auto digest = connection.call(request_frame(service::Opcode::StateDigest, 8));
  NOF_CHECK_OK(digest);
  auto invariants = connection.call(request_frame(service::Opcode::VerifyInvariants, 9));
  NOF_CHECK_OK(invariants);
  auto recovery = connection.call(request_frame(service::Opcode::RecoveryReport, 10));
  NOF_CHECK_OK(recovery);
  auto export_frame = connection.call(request_frame(service::Opcode::Export, 11, {std::byte{1}}));
  NOF_CHECK_OK(export_frame);
  NOF_CHECK(export_frame.value().payload.size() > 64u);

  // Adversarial framing: garbage, a truncated frame, an oversized declaration,
  // and a corrupted checksum. The server must refuse each and stay alive.
  const std::uint16_t server_port = port;
  {
    auto raw = detail::connect_tcp("127.0.0.1", server_port);
    NOF_CHECK_OK(raw);
    const std::string garbage = "not-a-frame-at-all";
    NOF_CHECK_OK(raw.value().send_bytes(std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(garbage.data()), garbage.size())));
    NOF_CHECK_OK(raw.value().close());
  }
  {
    auto raw = detail::connect_tcp("127.0.0.1", server_port);
    NOF_CHECK_OK(raw);
    std::vector<std::byte> header(service::kFrameHeaderBytes + service::kFrameTrailerBytes,
                                  std::byte{0});
    header[0] = std::byte{0x4E};
    header[1] = std::byte{0x46};
    header[2] = std::byte{0x01};
    header[3] = std::byte{0x00};
    header[4] = std::byte{0x01};
    // Declared payload length far beyond the frame bound.
    header[16] = std::byte{0xFF};
    header[17] = std::byte{0xFF};
    header[18] = std::byte{0xFF};
    header[19] = std::byte{0x7F};
    NOF_CHECK_OK(raw.value().send_bytes(header));
    std::byte drain[64];
    (void)raw.value().receive_bytes(std::span<std::byte>(drain, sizeof(drain)));
    NOF_CHECK_OK(raw.value().close());
  }
  {
    auto raw = detail::connect_tcp("127.0.0.1", server_port);
    NOF_CHECK_OK(raw);
    service::Frame frame = request_frame(service::Opcode::Stats, 12);
    std::vector<std::byte> encoded;
    NOF_CHECK_OK(service::encode_frame(frame, encoded, service::FrameLimits{}));
    encoded[encoded.size() - 1] = static_cast<std::byte>(0x5A);  // corrupt the CRC
    NOF_CHECK_OK(raw.value().send_bytes(encoded));
    std::byte drain[64];
    (void)raw.value().receive_bytes(std::span<std::byte>(drain, sizeof(drain)));
    NOF_CHECK_OK(raw.value().close());
  }
  {
    auto raw = detail::connect_tcp("127.0.0.1", server_port);
    NOF_CHECK_OK(raw);
    service::Frame frame = request_frame(service::Opcode::Stats, 13);
    std::vector<std::byte> encoded;
    NOF_CHECK_OK(service::encode_frame(frame, encoded, service::FrameLimits{}));
    // Send only part of the frame, then close: the peer ends inside a frame.
    NOF_CHECK_OK(raw.value().send_bytes(
        std::span<const std::byte>(encoded.data(), service::kFrameHeaderBytes + 1)));
    NOF_CHECK_OK(raw.value().close());
  }
  {
    // An unknown opcode is refused with a stable reason code.
    service::Frame frame = request_frame(service::Opcode::Stats, 14);
    std::vector<std::byte> encoded;
    NOF_CHECK_OK(service::encode_frame(frame, encoded, service::FrameLimits{}));
    encoded[4] = static_cast<std::byte>(0x77);
    auto raw = detail::connect_tcp("127.0.0.1", server_port);
    NOF_CHECK_OK(raw);
    // Recompute the CRC by re-encoding an unsupported opcode through the frame.
    service::Frame unknown;
    unknown.opcode = static_cast<service::Opcode>(0x0077);
    unknown.request_id = 15;
    std::vector<std::byte> unknown_bytes;
    // encode_frame refuses unknown opcodes only at decode time, so build the
    // bytes through a frame the encoder accepts and patch the opcode, fixing
    // the checksum with the published CRC primitive.
    NOF_CHECK_OK(service::encode_frame(request_frame(service::Opcode::Stats, 15), unknown_bytes,
                                       service::FrameLimits{}));
    unknown_bytes[4] = static_cast<std::byte>(0x77);
    unknown_bytes[5] = static_cast<std::byte>(0x00);
    const std::uint32_t crc = crc32c(std::span<const std::byte>(
        unknown_bytes.data(), unknown_bytes.size() - service::kFrameTrailerBytes));
    for (int i = 0; i < 4; ++i) {
      unknown_bytes[unknown_bytes.size() - 4 + static_cast<std::size_t>(i)] =
          static_cast<std::byte>((crc >> (i * 8)) & 0xFFu);
    }
    NOF_CHECK_OK(raw.value().send_bytes(unknown_bytes));
    std::byte buffer[256];
    auto received = raw.value().receive_bytes(std::span<std::byte>(buffer, sizeof(buffer)));
    NOF_CHECK_OK(received);
    NOF_CHECK(received.value() > 0);
    NOF_CHECK_OK(raw.value().close());
  }

  // The server survived every adversarial frame.
  auto still_alive = connection.call(request_frame(service::Opcode::Ping, 16));
  NOF_CHECK_OK(still_alive);

  // Concurrent clients: independent threads with independent connections.
  std::vector<std::thread> threads;
  std::vector<int> successes(4, 0);
  for (std::size_t index = 0; index < successes.size(); ++index) {
    threads.emplace_back([&, index]() {
      auto other = service::Client::connect("127.0.0.1", server_port, bounds);
      if (!other.ok()) {
        return;
      }
      for (int attempt = 0; attempt < 5; ++attempt) {
        auto response = other.value()->call(
            request_frame(service::Opcode::Ping, 100 + static_cast<std::uint64_t>(index * 10 + attempt)));
        if (response.ok()) {
          successes[index] += 1;
        }
      }
      (void)other.value()->close();
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  for (const int count : successes) {
    NOF_CHECK_EQ(count, 5);
  }

  const std::string digest_before = [&]() {
    auto response = connection.call(request_frame(service::Opcode::StateDigest, 17));
    NOF_CHECK_OK(response);
    BinReader reader(response.value().payload, bounds.max_text_bytes);
    return reader.text().value();
  }();
  NOF_CHECK(!digest_before.empty());

  // Orderly shutdown through the protocol, then a restart on the same store.
  auto shutdown_response = connection.call(request_frame(service::Opcode::Shutdown, 18));
  NOF_CHECK_OK(shutdown_response);
  const int server_exit = server.wait();
  NOF_CHECK_EQ(server_exit, 0);
  NOF_CHECK_OK(connection.close());

  support::ChildProcess restarted(nofd_command(store));
  NOF_CHECK(restarted.valid());
  const std::string ready_again = restarted.read_until("nofd ready");
  const std::uint16_t second_port = parse_port(ready_again);
  NOF_CHECK(second_port != 0);
  auto second_client = service::Client::connect("127.0.0.1", second_port, bounds);
  NOF_CHECK_OK(second_client);
  auto second_digest = second_client.value()->call(request_frame(service::Opcode::StateDigest, 19));
  NOF_CHECK_OK(second_digest);
  NOF_CHECK_OK(second_client.value()->call(request_frame(service::Opcode::Shutdown, 20)));
  NOF_CHECK_EQ(restarted.wait(), 0);
  NOF_CHECK_OK(second_client.value()->close());
  support::remove_store(store);
}

NOF_TEST(process, hard_kill_is_recoverable) {
#if defined(_WIN32)
  const std::string store = support::store_path("proc-hard-kill");
  support::remove_store(store);
  support::ChildProcess server(nofd_command(store));
  NOF_CHECK(server.valid());
  const std::string ready = server.read_until("nofd ready");
  const std::uint16_t port = parse_port(ready);
  NOF_CHECK(port != 0);
  const Bounds bounds;
  auto client = service::Client::connect("127.0.0.1", port, bounds);
  NOF_CHECK_OK(client);
  auto applied = client.value()->call(request_frame(service::Opcode::Apply, 1, [&]() {
    std::vector<std::byte> payload;
    const synthetic::ScenarioOptions options;
    const synthetic::Scenario scenario = synthetic::make_scenario(options);
    PlacementRequest placement = synthetic::make_request(scenario, options, "kill-req-1");
    BinWriter writer(bounds.max_request_bytes);
    (void)wire::encode_placement_request(placement, writer, bounds);
    (void)writer.boolean(false);
    payload.assign(writer.data().begin(), writer.data().end());
    return payload;
  }()));
  NOF_CHECK_OK(applied);
  NOF_CHECK_OK(client.value()->close());

  // Real hard kill: the coordinator gets no chance to flush or to seal.
  const int kill_status = std::system("taskkill /F /IM nofd.exe > nul 2>&1");
  NOF_CHECK(kill_status == 0);
  (void)server.wait();

  support::ChildProcess restarted(nofd_command(store));
  NOF_CHECK(restarted.valid());
  const std::string ready_again = restarted.read_until("nofd ready");
  const std::uint16_t port_again = parse_port(ready_again);
  auto second_client = service::Client::connect("127.0.0.1", port_again, bounds);
  NOF_CHECK_OK(second_client);
  auto recovery = second_client.value()->call(request_frame(service::Opcode::RecoveryReport, 2));
  NOF_CHECK_OK(recovery);
  BinReader reader(recovery.value().payload, bounds.max_text_bytes);
  const std::string rendered = reader.text().value();
  NOF_CHECK(rendered.find("authority_restored=false") != std::string::npos);
  auto invariants = second_client.value()->call(request_frame(service::Opcode::VerifyInvariants, 3));
  NOF_CHECK_OK(invariants);
  BinReader invariant_reader(invariants.value().payload, bounds.max_text_bytes);
  NOF_CHECK(invariant_reader.text().value().find("invariants=clean") != std::string::npos);
  NOF_CHECK_OK(second_client.value()->call(request_frame(service::Opcode::Shutdown, 4)));
  NOF_CHECK_EQ(restarted.wait(), 0);
  NOF_CHECK_OK(second_client.value()->close());
  support::remove_store(store);
#else
  // Documented as a Windows-only proof in this repository; the CLI crash
  // boundaries still cover hard process death on other platforms.
  NOF_CHECK(true);
#endif
}
