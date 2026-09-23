#pragma once

#include <compare>
#include <cstdint>

#include "nof/checked.hpp"
#include "nof/error.hpp"

// Typed quantities. Units are part of the type: a packet rate can never be
// added to a byte rate, and a capacity expressed in flows can never be
// compared against one expressed in queues.
namespace nof {

template <class Tag, class Rep>
class Quantity {
 public:
  using rep_type = Rep;

  Quantity() = default;
  explicit constexpr Quantity(Rep value) noexcept : value_(value) {}

  static constexpr Quantity raw(Rep value) noexcept { return Quantity(value); }

  constexpr Rep value() const noexcept { return value_; }

  Result<Quantity> add(const Quantity& other) const {
    Rep out{};
    if (!checked_add(value_, other.value_, out)) {
      return Error(ReasonCode::ArithmeticOverflow, "quantity addition overflow");
    }
    return Quantity(out);
  }

  Result<Quantity> sub(const Quantity& other) const {
    Rep out{};
    if (!checked_sub(value_, other.value_, out)) {
      return Error(ReasonCode::ArithmeticOverflow, "quantity subtraction underflow");
    }
    return Quantity(out);
  }

  Result<Quantity> mul(Rep scalar) const {
    Rep out{};
    if (!checked_mul(value_, scalar, out)) {
      return Error(ReasonCode::ArithmeticOverflow, "quantity multiplication overflow");
    }
    return Quantity(out);
  }

  constexpr Quantity saturating_add(const Quantity& other) const noexcept {
    return Quantity(nof::saturating_add(value_, other.value_));
  }

  constexpr Quantity saturating_mul(Rep scalar) const noexcept {
    return Quantity(nof::saturating_mul(value_, scalar));
  }

  friend bool operator==(const Quantity&, const Quantity&) = default;
  friend std::strong_ordering operator<=>(const Quantity&, const Quantity&) = default;

 private:
  Rep value_{};
};

struct PacketRateTag;
struct ByteRateTag;
struct FlowCountTag;
struct QueueCountTag;
struct ByteSizeTag;
struct MicrosTag;
struct CountTag;

// Packets per second of governed traffic.
using PacketRate = Quantity<PacketRateTag, std::uint64_t>;
// Bytes per second of governed traffic.
using ByteRate = Quantity<ByteRateTag, std::uint64_t>;
// Concurrent tracked flows.
using FlowCount = Quantity<FlowCountTag, std::uint64_t>;
// Hardware queues / descriptor rings.
using QueueCount = Quantity<QueueCountTag, std::uint64_t>;
// Absolute byte size, used for memory-region style requirements.
using ByteSize = Quantity<ByteSizeTag, std::uint64_t>;
// Logical time in microseconds since the Unix epoch, or since an arbitrary
// origin for a manual clock. Never read implicitly by the library: it is always
// supplied by the injected clock or carried inside evidence.
using Micros = Quantity<MicrosTag, std::int64_t>;
// Generic bounded counter for accounting surfaces.
using Count = Quantity<CountTag, std::uint64_t>;

// A demand vector describing what a placement request asks a target to carry.
struct DemandVector {
  PacketRate packets_per_second{};
  ByteRate bytes_per_second{};
  FlowCount flows{};
  QueueCount queues{};
  ByteSize memory{};

  friend bool operator==(const DemandVector&, const DemandVector&) = default;

  bool is_zero() const noexcept {
    return packets_per_second.value() == 0 && bytes_per_second.value() == 0 &&
           flows.value() == 0 && queues.value() == 0 && memory.value() == 0;
  }
};

// A capacity vector advertised by a target.
struct CapacityVector {
  PacketRate packets_per_second{};
  ByteRate bytes_per_second{};
  FlowCount flows{};
  QueueCount queues{};
  ByteSize memory{};

  friend bool operator==(const CapacityVector&, const CapacityVector&) = default;

  bool is_zero() const noexcept {
    return packets_per_second.value() == 0 && bytes_per_second.value() == 0 &&
           flows.value() == 0 && queues.value() == 0 && memory.value() == 0;
  }
};

// Result of committing demand against capacity: explicit rather than
// saturating, so exhaustion is a refusal and not a silent clamp.
inline bool capacity_admits(const CapacityVector& capacity, const DemandVector& committed,
                            const DemandVector& demand, DemandVector& projected) {
  std::uint64_t pps = 0;
  std::uint64_t bps = 0;
  std::uint64_t flows = 0;
  std::uint64_t queues = 0;
  std::uint64_t memory = 0;
  if (!checked_add(committed.packets_per_second.value(), demand.packets_per_second.value(), pps) ||
      !checked_add(committed.bytes_per_second.value(), demand.bytes_per_second.value(), bps) ||
      !checked_add(committed.flows.value(), demand.flows.value(), flows) ||
      !checked_add(committed.queues.value(), demand.queues.value(), queues) ||
      !checked_add(committed.memory.value(), demand.memory.value(), memory)) {
    return false;
  }
  if (pps > capacity.packets_per_second.value() || bps > capacity.bytes_per_second.value() ||
      flows > capacity.flows.value() || queues > capacity.queues.value() ||
      memory > capacity.memory.value()) {
    return false;
  }
  projected = DemandVector{PacketRate{pps}, ByteRate{bps}, FlowCount{flows}, QueueCount{queues},
                           ByteSize{memory}};
  return true;
}

inline bool capacity_exceeds(const DemandVector& used, const CapacityVector& capacity) {
  return used.packets_per_second.value() > capacity.packets_per_second.value() ||
         used.bytes_per_second.value() > capacity.bytes_per_second.value() ||
         used.flows.value() > capacity.flows.value() ||
         used.queues.value() > capacity.queues.value() ||
         used.memory.value() > capacity.memory.value();
}

}  // namespace nof
