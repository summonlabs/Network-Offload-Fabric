#include "nof/time.hpp"

#include <chrono>

namespace nof {

Micros SystemClock::now() const {
  const auto since_epoch = std::chrono::system_clock::now().time_since_epoch();
  const auto micros =
      std::chrono::duration_cast<std::chrono::duration<std::int64_t, std::micro>>(since_epoch);
  return Micros::raw(micros.count());
}

}  // namespace nof
