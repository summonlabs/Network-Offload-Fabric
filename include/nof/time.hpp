#pragma once

#include <atomic>
#include <cstdint>

#include "nof/error.hpp"
#include "nof/units.hpp"

// Time is always injected. The library never reads the wall clock behind the
// caller's back, which is what allows accepted state to be a deterministic
// function of accepted evidence and policy.
namespace nof {

class Clock {
 public:
  Clock() = default;
  virtual ~Clock() = default;
  Clock(const Clock&) = delete;
  Clock& operator=(const Clock&) = delete;

  virtual Micros now() const = 0;
};

class SystemClock final : public Clock {
 public:
  SystemClock() = default;
  Micros now() const override;
};

// Monotonic logical clock used by deterministic tests and by replay, where the
// recorded timestamps must be reproduced exactly.
class ManualClock final : public Clock {
 public:
  ManualClock() = default;
  explicit ManualClock(Micros start) : now_(start.value()) {}

  Micros now() const override { return Micros::raw(now_.load(std::memory_order_relaxed)); }

  // Advances the clock and returns the new value. Advancing past the
  // representable range is refused rather than wrapping.
  Result<Micros> advance(Micros delta) {
    std::int64_t current = now_.load(std::memory_order_relaxed);
    std::int64_t next = 0;
    if (!checked_add(current, delta.value(), next)) {
      return Error(ReasonCode::ArithmeticOverflow, "clock advance overflow");
    }
    now_.store(next, std::memory_order_relaxed);
    return Micros::raw(next);
  }

  Result<Micros> set(Micros value) {
    if (value.value() < now_.load(std::memory_order_relaxed)) {
      return Error(ReasonCode::OutOfRange, "manual clock cannot move backwards");
    }
    now_.store(value.value(), std::memory_order_relaxed);
    return value;
  }

 private:
  std::atomic<std::int64_t> now_{0};
};

// Freshness interval: evidence is current only while
// observed_at + ttl > now, and only while it has not been superseded.
struct Freshness {
  Micros observed_at{};
  Micros valid_until{};

  bool is_set() const noexcept { return observed_at.value() != 0 && valid_until.value() > 0; }

  bool is_expired(Micros now) const noexcept {
    return !is_set() || now.value() >= valid_until.value();
  }

  friend bool operator==(const Freshness&, const Freshness&) = default;
};

}  // namespace nof
