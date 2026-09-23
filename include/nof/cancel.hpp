#pragma once

#include <atomic>

namespace nof {

// Real cancellation. Operations observe the token at defined checkpoints and
// refuse to publish success after cancellation has been observed. Cancellation
// is honoured before the durable commit point; once a commit has been made the
// operation reports the committed outcome instead of pretending nothing
// happened.
class CancelToken {
 public:
  CancelToken() = default;
  CancelToken(const CancelToken&) = delete;
  CancelToken& operator=(const CancelToken&) = delete;

  void cancel() noexcept { flag_.store(true, std::memory_order_release); }
  bool cancelled() const noexcept { return flag_.load(std::memory_order_acquire); }
  void reset() noexcept { flag_.store(false, std::memory_order_release); }

 private:
  std::atomic<bool> flag_{false};
};

}  // namespace nof
