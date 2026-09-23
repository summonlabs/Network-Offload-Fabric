#pragma once

#include <cstdint>
#include <limits>
#include <type_traits>

#include "nof/error.hpp"

// Overflow-checked arithmetic for all externally derived sizes, counters,
// timestamps, and quantities. Every arithmetic edge that can be driven by
// untrusted input goes through these helpers so that absurd input is refused
// with ArithmeticOverflow instead of silently wrapping.
namespace nof {

template <class T>
constexpr bool add_would_overflow(T a, T b) noexcept {
  static_assert(std::is_integral_v<T>, "integral only");
  if constexpr (std::is_unsigned_v<T>) {
    return a > static_cast<T>(std::numeric_limits<T>::max() - b);
  } else {
    if (b > 0) {
      return a > static_cast<T>(std::numeric_limits<T>::max() - b);
    }
    return a < static_cast<T>(std::numeric_limits<T>::min() - b);
  }
}

template <class T>
constexpr bool sub_would_overflow(T a, T b) noexcept {
  static_assert(std::is_integral_v<T>, "integral only");
  if constexpr (std::is_unsigned_v<T>) {
    return a < b;
  } else {
    if (b > 0) {
      return a < static_cast<T>(std::numeric_limits<T>::min() + b);
    }
    return a > static_cast<T>(std::numeric_limits<T>::max() + b);
  }
}

template <class T>
constexpr bool mul_would_overflow(T a, T b) noexcept {
  static_assert(std::is_integral_v<T>, "integral only");
  if (a == 0 || b == 0) {
    return false;
  }
  if constexpr (std::is_unsigned_v<T>) {
    return a > static_cast<T>(std::numeric_limits<T>::max() / b);
  } else {
    const T max_v = std::numeric_limits<T>::max();
    const T min_v = std::numeric_limits<T>::min();
    if (a > 0) {
      if (b > 0) {
        return a > max_v / b;
      }
      return b < min_v / a;
    }
    if (b > 0) {
      return a < min_v / b;
    }
    return a != 0 && b < max_v / a;
  }
}

// Checked add: returns false and leaves out untouched on overflow.
template <class T>
constexpr bool checked_add(T a, T b, T& out) noexcept {
  if (add_would_overflow(a, b)) {
    return false;
  }
  out = static_cast<T>(a + b);
  return true;
}

// Checked subtract: returns false (never wraps) on underflow.
template <class T>
constexpr bool checked_sub(T a, T b, T& out) noexcept {
  if (sub_would_overflow(a, b)) {
    return false;
  }
  out = static_cast<T>(a - b);
  return true;
}

template <class T>
constexpr bool checked_mul(T a, T b, T& out) noexcept {
  if (mul_would_overflow(a, b)) {
    return false;
  }
  out = static_cast<T>(a * b);
  return true;
}

// Checked narrowing conversions used at every boundary where an untrusted
// 64-bit value becomes a smaller type.
template <class To, class From>
constexpr bool checked_cast(From value, To& out) noexcept {
  static_assert(std::is_integral_v<To> && std::is_integral_v<From>, "integral only");
  if constexpr (std::is_signed_v<From> == std::is_signed_v<To>) {
    if (value < static_cast<From>(std::numeric_limits<To>::min()) ||
        value > static_cast<From>(std::numeric_limits<To>::max())) {
      return false;
    }
  } else if constexpr (std::is_signed_v<From>) {
    if (value < 0) {
      return false;
    }
    using UFrom = std::make_unsigned_t<From>;
    if (static_cast<UFrom>(value) > static_cast<UFrom>(std::numeric_limits<To>::max())) {
      return false;
    }
  } else {
    if (value > static_cast<From>(std::numeric_limits<To>::max())) {
      return false;
    }
  }
  out = static_cast<To>(value);
  return true;
}

template <class T>
constexpr T saturating_add(T a, T b) noexcept {
  T out{};
  if (!checked_add(a, b, out)) {
    return (b > 0) ? std::numeric_limits<T>::max() : std::numeric_limits<T>::min();
  }
  return out;
}

template <class T>
constexpr T saturating_mul(T a, T b) noexcept {
  T out{};
  if (!checked_mul(a, b, out)) {
    return (a < 0) != (b < 0) ? std::numeric_limits<T>::min() : std::numeric_limits<T>::max();
  }
  return out;
}

// Ceiling division that refuses a zero divisor instead of trapping.
template <class T>
constexpr bool checked_ceil_div(T num, T den, T& out) noexcept {
  if (den == 0) {
    return false;
  }
  T q{};
  if (!checked_add(num, static_cast<T>(den - 1), q)) {
    return false;
  }
  out = static_cast<T>(q / den);
  return true;
}

}  // namespace nof
