#include "framework.hpp"

#include <string>
#include <vector>

#include "nof/canonical.hpp"
#include "nof/checked.hpp"
#include "nof/digest.hpp"
#include "nof/error.hpp"
#include "nof/function.hpp"
#include "nof/journal.hpp"
#include "nof/units.hpp"

using namespace nof;

namespace {

std::string to_hex(const Digest& digest) { return digest.hex(); }

}  // namespace

NOF_TEST(core, digest_vectors) {
  // Published test vectors: the in-house primitives must match them exactly.
  NOF_CHECK_EQ(sha256(std::string("")).hex(),
               std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
  NOF_CHECK_EQ(sha256(std::string("abc")).hex(),
               std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
  NOF_CHECK_EQ(
      sha256(std::string("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).hex(),
      std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
  NOF_CHECK_EQ(crc32c(std::string("123456789")), 0xE3069283u);
  NOF_CHECK_EQ(crc32c(std::string("")), 0u);

  // Incremental hashing must equal one-shot hashing.
  Sha256 hasher;
  hasher.update(std::string("ab"));
  hasher.update(std::string("c"));
  NOF_CHECK_EQ(hasher.finish().hex(), sha256(std::string("abc")).hex());
}

NOF_TEST(core, tokens_are_strict) {
  NOF_CHECK(Token<HostTag>::parse("host-1").ok());
  NOF_CHECK(Token<HostTag>::parse("h.1_2:3").ok());
  NOF_CHECK_ERROR(Token<HostTag>::parse(""), ReasonCode::InvalidIdentifier);
  NOF_CHECK_ERROR(Token<HostTag>::parse("Host1"), ReasonCode::InvalidIdentifier);
  NOF_CHECK_ERROR(Token<HostTag>::parse("-host"), ReasonCode::InvalidIdentifier);
  NOF_CHECK_ERROR(Token<HostTag>::parse("host 1"), ReasonCode::InvalidIdentifier);
  NOF_CHECK_ERROR(Token<HostTag>::parse("hôst"), ReasonCode::InvalidIdentifier);
  NOF_CHECK_ERROR(Token<HostTag>::parse(std::string(65, 'a')), ReasonCode::InvalidIdentifier);

  NOF_CHECK(BootId::parse("0123456789abcdef0123456789abcdef").ok());
  NOF_CHECK_ERROR(BootId::parse("0123456789ABCDEF0123456789abcdef"), ReasonCode::InvalidIdentifier);
  NOF_CHECK_ERROR(BootId::parse("0123"), ReasonCode::InvalidIdentifier);

  const Digest digest = sha256(std::string("x"));
  auto parsed = Digest::from_hex(digest.hex());
  NOF_CHECK_OK(parsed);
  NOF_CHECK_EQ(parsed.value().hex(), digest.hex());
  NOF_CHECK_ERROR(Digest::from_hex("xyz"), ReasonCode::InvalidIdentifier);
}

NOF_TEST(core, generations_are_monotonic_and_unset_is_never_current) {
  const TopologyGeneration unset;
  NOF_CHECK(!unset.is_set());
  NOF_CHECK_ERROR(TopologyGeneration::from_u64(0), ReasonCode::OutOfRange);
  auto first = TopologyGeneration::from_u64(1);
  NOF_CHECK_OK(first);
  auto second = first.value().next();
  NOF_CHECK_OK(second);
  NOF_CHECK_EQ(second.value().value(), 2u);
  NOF_CHECK(first.value() < second.value());

  const TopologyGeneration maximum = TopologyGeneration::from_validated(UINT64_MAX);
  NOF_CHECK_ERROR(maximum.next(), ReasonCode::ArithmeticOverflow);
}

NOF_TEST(core, fencing_tokens_order_across_epochs) {
  const FencingToken old_token{1, 9};
  const FencingToken new_epoch{2, 1};
  NOF_CHECK(old_token < new_epoch);
  NOF_CHECK(!(new_epoch < old_token));
  const FencingToken later{2, 2};
  const FencingToken earlier{2, 1};
  NOF_CHECK(later > earlier);
  const FencingToken unset_token{};
  NOF_CHECK(!unset_token.is_set());
}

NOF_TEST(core, checked_arithmetic_refuses_extremes) {
  std::uint64_t out = 0;
  NOF_CHECK(checked_add(std::uint64_t{1}, std::uint64_t{2}, out));
  NOF_CHECK_EQ(out, 3u);
  NOF_CHECK(!checked_add(std::numeric_limits<std::uint64_t>::max(), std::uint64_t{1}, out));
  NOF_CHECK(!checked_mul(std::uint64_t{1} << 40, std::uint64_t{1} << 40, out));
  NOF_CHECK(checked_mul(std::uint64_t{4096}, std::uint64_t{4096}, out));
  NOF_CHECK_EQ(out, 16777216u);
  std::uint32_t narrowed = 0;
  NOF_CHECK(checked_cast<std::uint32_t>(std::uint64_t{7}, narrowed));
  NOF_CHECK_EQ(narrowed, 7u);
  NOF_CHECK(!checked_cast<std::uint32_t>(std::uint64_t{1} << 40, narrowed));
  std::int64_t signed_out = 0;
  NOF_CHECK(checked_sub(std::int64_t{-5}, std::int64_t{5}, signed_out));
  NOF_CHECK_EQ(signed_out, -10);
  NOF_CHECK(!checked_sub(std::numeric_limits<std::int64_t>::min(), std::int64_t{1}, signed_out));
  NOF_CHECK(!checked_ceil_div(std::uint64_t{5}, std::uint64_t{0}, out));
}

NOF_TEST(core, capacity_accounting_is_exact) {
  CapacityVector capacity;
  capacity.packets_per_second = PacketRate::raw(100);
  capacity.flows = FlowCount::raw(10);
  DemandVector committed;
  committed.packets_per_second = PacketRate::raw(90);
  DemandVector demand;
  demand.flows = FlowCount::raw(10);
  DemandVector projected{};
  NOF_CHECK(capacity_admits(capacity, committed, demand, projected));
  NOF_CHECK_EQ(projected.flows.value(), 10u);
  demand.flows = FlowCount::raw(11);
  NOF_CHECK(!capacity_admits(capacity, committed, demand, projected));
  demand.flows = FlowCount::raw(0);
  committed.packets_per_second = PacketRate::raw(101);
  NOF_CHECK(!capacity_admits(capacity, committed, demand, projected));
  // An overflowing projection is a refusal, never a wrapped value.
  committed.packets_per_second = PacketRate::raw(UINT64_MAX);
  demand.packets_per_second = PacketRate::raw(1);
  NOF_CHECK(!capacity_admits(capacity, committed, demand, projected));
}

NOF_TEST(core, quantity_arithmetic_is_typed_and_checked) {
  const PacketRate high = PacketRate::raw(UINT64_MAX);
  const auto sum = high.add(PacketRate::raw(1));
  NOF_CHECK(!sum.ok());
  NOF_CHECK_EQ(sum.error().code, ReasonCode::ArithmeticOverflow);
  const auto product = PacketRate::raw(1ull << 33).mul(1ull << 33);
  NOF_CHECK(!product.ok());
  NOF_CHECK(high.sub(PacketRate::raw(1)).ok());
}

NOF_TEST(core, canonical_binary_round_trip_and_bounds) {
  BinWriter writer(1024);
  NOF_CHECK_OK(writer.u8(7));
  NOF_CHECK_OK(writer.u16(300));
  NOF_CHECK_OK(writer.u32(70000));
  NOF_CHECK_OK(writer.u64(1ull << 40));
  NOF_CHECK_OK(writer.i64(-9));
  NOF_CHECK_OK(writer.boolean(true));
  NOF_CHECK_OK(writer.text("hello"));
  NOF_CHECK_OK(writer.token("host-1"));
  const Digest digest = writer.fingerprint();

  BinReader reader(writer.data(), 64);
  NOF_CHECK_EQ(reader.u8().value(), 7u);
  NOF_CHECK_EQ(reader.u16().value(), 300u);
  NOF_CHECK_EQ(reader.u32().value(), 70000u);
  NOF_CHECK_EQ(reader.u64().value(), 1ull << 40);
  NOF_CHECK_EQ(reader.i64().value(), -9);
  NOF_CHECK(reader.boolean().value());
  NOF_CHECK_EQ(reader.text().value(), std::string("hello"));
  NOF_CHECK_EQ(reader.token().value(), std::string("host-1"));
  NOF_CHECK(reader.at_end());

  // A truncated buffer is refused, never silently defaulted.
  BinReader truncated(std::span<const std::byte>(writer.data().data(), 2), 64);
  NOF_CHECK_OK(truncated.u8());
  NOF_CHECK_ERROR(truncated.u16(), ReasonCode::TruncatedInput);

  // A writer bound is enforced before the buffer grows past it.
  BinWriter small(8);
  NOF_CHECK_OK(small.u64(1));
  NOF_CHECK_ERROR(small.u64(1), ReasonCode::OversizedInput);

  // A non-canonical boolean byte is refused.
  BinWriter bad(8);
  NOF_CHECK_OK(bad.u8(2));
  BinReader bad_reader(bad.data(), 8);
  NOF_CHECK_ERROR(bad_reader.boolean(), ReasonCode::MalformedInput);

  // A non-canonical token is refused on read.
  BinWriter bad_token(64);
  NOF_CHECK_OK(bad_token.text("Host"));
  BinReader bad_token_reader(bad_token.data(), 64);
  NOF_CHECK_ERROR(bad_token_reader.token(), ReasonCode::InvalidIdentifier);

  // Text longer than the reader bound is refused before allocation.
  BinWriter long_text(512);
  NOF_CHECK_OK(long_text.text(std::string(200, 'a')));
  BinReader bounded(long_text.data(), 16);
  NOF_CHECK_ERROR(bounded.text(), ReasonCode::OversizedInput);
  NOF_CHECK(!digest.is_zero());
}

NOF_TEST(core, canonical_json_is_sorted_and_strict) {
  JsonValue::Array numbers;
  numbers.push_back(JsonValue::boolean(true));
  numbers.push_back(JsonValue::integer(-3));
  auto numbers_value = JsonValue::array(std::move(numbers));
  NOF_CHECK_OK(numbers_value);
  JsonValue::Object members;
  members.emplace_back("b", JsonValue::uinteger(2));
  members.emplace_back("a", JsonValue::string("x"));
  members.emplace_back("c", numbers_value.take());
  auto value = JsonValue::object(std::move(members));
  NOF_CHECK_OK(value);
  std::string dumped;
  NOF_CHECK_OK(value.value().dump(dumped, 1024));
  const std::string expected = "{\"a\":\"x\",\"b\":2,\"c\":[true,-3]}";
  NOF_CHECK_EQ(dumped, expected);

  // Duplicate keys are refused at construction.
  JsonValue::Object duplicated;
  duplicated.emplace_back("a", JsonValue::uinteger(1));
  duplicated.emplace_back("a", JsonValue::uinteger(2));
  auto duplicate = JsonValue::object(std::move(duplicated));
  NOF_CHECK_ERROR(duplicate, ReasonCode::DuplicateIdentity);

  // Oversized output is refused instead of silently truncated.
  std::string small;
  NOF_CHECK_ERROR(value.value().dump(small, 4), ReasonCode::OversizedInput);
  NOF_CHECK(small.empty());

  auto parsed = JsonReader(expected).parse();
  NOF_CHECK_OK(parsed);
  NOF_CHECK_EQ(parsed.value().as_object().size(), 3u);

  const std::string trailing_comma = "{\"a\":1,}";
  const std::string trailing_garbage = "{\"a\":1} trailing";
  const std::string float_value = "{\"a\":1.5}";
  const std::string duplicate_keys = "{\"a\":1,\"a\":2}";
  const std::string empty_document = "";
  const std::string non_ascii = "{\"a\":\"\\u00ff\"}";
  const std::string huge_integer = "{\"a\":99999999999999999999999}";
  NOF_CHECK_ERROR(JsonReader(trailing_comma).parse(), ReasonCode::MalformedInput);
  NOF_CHECK_ERROR(JsonReader(trailing_garbage).parse(), ReasonCode::MalformedInput);
  NOF_CHECK_ERROR(JsonReader(float_value).parse(), ReasonCode::UnsupportedValue);
  NOF_CHECK_ERROR(JsonReader(duplicate_keys).parse(), ReasonCode::DuplicateIdentity);
  NOF_CHECK_ERROR(JsonReader(empty_document).parse(), ReasonCode::TruncatedInput);
  NOF_CHECK_ERROR(JsonReader(non_ascii).parse(), ReasonCode::UnsupportedValue);
  NOF_CHECK_ERROR(JsonReader(huge_integer).parse(), ReasonCode::ArithmeticOverflow);
}

NOF_TEST(core, reason_codes_are_stable_and_parseable) {
  NOF_CHECK_EQ(std::string(to_string(ReasonCode::Ok)), std::string("OK"));
  NOF_CHECK_EQ(std::string(to_string(ReasonCode::FencedAttempt)), std::string("FENCED_ATTEMPT"));
  // The numeric values are part of the durable contract, so they are pinned.
  const std::uint16_t fenced_value = static_cast<std::uint16_t>(ReasonCode::FencedAttempt);
  const std::uint16_t conflict_value = static_cast<std::uint16_t>(ReasonCode::ExclusiveConflict);
  NOF_CHECK_EQ(fenced_value, static_cast<std::uint16_t>(0x0503));
  NOF_CHECK_EQ(conflict_value, static_cast<std::uint16_t>(0x0401));
  NOF_CHECK_EQ(category_of(ReasonCode::Ok), ReasonCategory::Ok);
  NOF_CHECK_EQ(category_of(ReasonCode::HostFallbackApplied), ReasonCategory::Informational);
  NOF_CHECK_EQ(category_of(ReasonCode::MalformedInput), ReasonCategory::Refusal);
  NOF_CHECK_EQ(category_of(ReasonCode::JournalTornTail), ReasonCategory::Recovery);
  NOF_CHECK(is_refusal(ReasonCode::StoreCorrupt));
  NOF_CHECK(is_recovery_classification(ReasonCode::RestartAuthorityReset));
  NOF_CHECK(!is_refusal(ReasonCode::Ok));

  ReasonCode parsed = ReasonCode::Ok;
  NOF_CHECK(parse_reason_code("EXCLUSIVE_CONFLICT", parsed));
  NOF_CHECK_EQ(parsed, ReasonCode::ExclusiveConflict);
  NOF_CHECK(!parse_reason_code("exclusive_conflict", parsed));
  NOF_CHECK(!parse_reason_code("NOT_A_REASON", parsed));
  NOF_CHECK(!parse_reason_code("", parsed));
  NOF_CHECK(std::string(to_string(static_cast<ReasonCode>(0x7FFF))) == "UNKNOWN_REASON");
}

NOF_TEST(core, enum_tokens_round_trip) {
  FunctionClass cls = FunctionClass::RouteLookup;
  for (int index = 1; index <= 16; ++index) {
    NOF_CHECK(parse_function_class(to_string(static_cast<FunctionClass>(index)), cls));
    NOF_CHECK_EQ(static_cast<int>(cls), index);
  }
  NOF_CHECK(!parse_function_class("routing", cls));
  NOF_CHECK(!parse_function_class("", cls));

  Semantic semantic = Semantic::LineRateDeterministic;
  for (std::size_t index = 0; index < kSemanticCount; ++index) {
    NOF_CHECK(parse_semantic(to_string(static_cast<Semantic>(index)), semantic));
    NOF_CHECK_EQ(static_cast<std::size_t>(semantic), index);
  }
  NOF_CHECK(!parse_semantic("nonsense", semantic));

  DeviceKind kind = DeviceKind::Nic;
  for (int index = 1; index <= 4; ++index) {
    NOF_CHECK(parse_device_kind(to_string(static_cast<DeviceKind>(index)), kind));
  }
  NOF_CHECK(!parse_device_kind("fpga", kind));

  AssignmentState state = AssignmentState::Planned;
  for (int index = 1; index <= 11; ++index) {
    NOF_CHECK(parse_assignment_state(to_string(static_cast<AssignmentState>(index)), state));
  }
  NOF_CHECK(!parse_assignment_state("active", state));

  NOF_CHECK(holds_authority(AssignmentState::AppliedVerified));
  NOF_CHECK(holds_authority(AssignmentState::Authorized));
  NOF_CHECK(!holds_authority(AssignmentState::Suspended));
  NOF_CHECK(!holds_authority(AssignmentState::Degraded));
  NOF_CHECK(is_live(AssignmentState::Suspended));
  NOF_CHECK(is_terminal(AssignmentState::Revoked));
  NOF_CHECK(!is_terminal(AssignmentState::AppliedVerified));
  NOF_CHECK_EQ(std::string(to_string(Exclusivity::Exclusive)), std::string("exclusive"));
  NOF_CHECK_EQ(std::string(to_string(ExecutionMode::HostFallback)), std::string("host_fallback"));
  NOF_CHECK_EQ(std::string(to_string(EffectOutcome::Unknown)), std::string("unknown"));
  NOF_CHECK_EQ(std::string(to_string(RecordType::EffectRecorded)), std::string("effect_recorded"));
  NOF_CHECK_EQ(std::string(to_string(CrashBoundary::AfterCommitBeforeAck)),
               std::string("after_commit_before_ack"));
  NOF_CHECK_EQ(std::string(to_string(RecoveryClassification::TornTailTruncated)),
               std::string("torn_tail_truncated"));
}

NOF_TEST(core, bounds_validation_refuses_absurd_configuration) {
  Bounds bounds;
  NOF_CHECK_OK(validate_bounds(bounds));
  Bounds zero_workers = bounds;
  zero_workers.max_workers = 0;
  NOF_CHECK_REFUSED(validate_bounds(zero_workers), ReasonCode::InvalidConfiguration);
  Bounds tiny_record = bounds;
  tiny_record.max_record_bytes = 8;
  NOF_CHECK_REFUSED(validate_bounds(tiny_record), ReasonCode::InvalidConfiguration);
  Bounds inverted = bounds;
  inverted.max_journal_bytes = 16;
  NOF_CHECK_REFUSED(validate_bounds(inverted), ReasonCode::InvalidConfiguration);
  Bounds huge = bounds;
  huge.max_assignments = 1000000000u;
  NOF_CHECK_REFUSED(validate_bounds(huge), ReasonCode::InvalidConfiguration);
  Bounds frame = bounds;
  frame.max_request_bytes = frame.max_frame_bytes + 1;
  NOF_CHECK_REFUSED(validate_bounds(frame), ReasonCode::InvalidConfiguration);
}

NOF_TEST(core, scope_identity_is_derived_canonically) {
  ScopeSpec spec;
  spec.kind = ScopeKind::Flow;
  spec.domain = HostId::from_validated("syn-h0");
  spec.selector = "dir=ingress,proto=tcp";
  auto first = derive_scope_id(spec);
  NOF_CHECK_OK(first);
  auto second = derive_scope_id(spec);
  NOF_CHECK_EQ(first.value(), second.value());
  NOF_CHECK_EQ(first.value().value().substr(0, 3), std::string("sc-"));

  ScopeSpec other = spec;
  other.selector = "dir=egress,proto=tcp";
  auto third = derive_scope_id(other);
  NOF_CHECK_OK(third);
  NOF_CHECK(!(third.value() == first.value()));

  ScopeSpec invalid;
  invalid.kind = ScopeKind::Queue;
  NOF_CHECK_REFUSED(invalid.validate(), ReasonCode::MalformedInput);
  invalid.device = DeviceId::from_validated("syn-h0-nic");
  NOF_CHECK_REFUSED(invalid.validate(), ReasonCode::MalformedInput);
  invalid.selector = "q=0";
  NOF_CHECK_OK(invalid.validate());
  ScopeSpec bad_selector = invalid;
  bad_selector.selector = "Q 0!";
  NOF_CHECK_REFUSED(bad_selector.validate(), ReasonCode::InvalidIdentifier);

  ScopeSpec global;
  global.kind = ScopeKind::Global;
  NOF_CHECK_OK(global.validate());
  ScopeSpec global_with_domain = global;
  global_with_domain.domain = HostId::from_validated("syn-h0");
  NOF_CHECK_REFUSED(global_with_domain.validate(), ReasonCode::MalformedInput);
}
