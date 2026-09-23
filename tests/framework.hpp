#pragma once

#include <functional>
#include <string>
#include <vector>

#include "nof/error.hpp"

// Minimal in-house test framework. Deterministic ordering, no timeouts, no
// sleeps: a hang is a defect, not something to paper over with a deadline.
namespace nof::test {

using Body = std::function<void()>;

struct Case {
  std::string suite{};
  std::string name{};
  Body body{};
};

class Registry {
 public:
  static Registry& instance();

  void add(const char* suite, const char* name, Body body);
  const std::vector<Case>& cases() const { return cases_; }

 private:
  std::vector<Case> cases_{};
};

struct Registrar {
  Registrar(const char* suite, const char* name, Body body) {
    Registry::instance().add(suite, name, std::move(body));
  }
};

// Records a failure against the currently running case.
void record_failure(const char* file, int line, const std::string& message);
bool case_failed();

// Comparison helpers. Routing assertions through non-constexpr functions keeps
// the checks honest under /W4 /WX: a comparison of two constants is still a
// real check, it just is not written as a constant conditional expression.
inline bool check_true(bool value) noexcept { return value; }

template <class T, class U>
inline bool check_equal(const T& left, const U& right) {
  return left == right;
}

int run_all(int argc, char** argv);

}  // namespace nof::test

#define NOF_TEST(suite_name, case_name)                                          \
  static void nof_test_##suite_name##_##case_name();                             \
  static const ::nof::test::Registrar nof_test_registrar_##suite_name##_##case_name( \
      #suite_name, #case_name, &nof_test_##suite_name##_##case_name);            \
  static void nof_test_##suite_name##_##case_name()

#define NOF_FAIL(message) ::nof::test::record_failure(__FILE__, __LINE__, (message))

#define NOF_CHECK(condition)                                                        \
  do {                                                                              \
    if (!::nof::test::check_true(static_cast<bool>(condition))) {                    \
      ::nof::test::record_failure(__FILE__, __LINE__, "check failed: " #condition); \
    }                                                                               \
  } while (false)

#define NOF_CHECK_EQ(left, right)                                                      \
  do {                                                                                 \
    const auto nof_left = (left);                                                      \
    const auto nof_right = (right);                                                     \
    if (!::nof::test::check_equal(nof_left, nof_right)) {                              \
      ::nof::test::record_failure(__FILE__, __LINE__,                                   \
                                  std::string("expected equality: " #left " == " #right)); \
    }                                                                                  \
  } while (false)

#define NOF_CHECK_OK(expression)                                                            \
  do {                                                                                      \
    const auto& nof_status = (expression);                                                   \
    if (!nof_status.ok()) {                                                                  \
      ::nof::test::record_failure(__FILE__, __LINE__,                                        \
                                  std::string("expected success: " #expression " -> ") +     \
                                      ::nof::to_string(nof_status.error()));                  \
    }                                                                                        \
  } while (false)

#define NOF_CHECK_REFUSED(expression, expected_code)                                        \
  do {                                                                                      \
    const auto& nof_status = (expression);                                                   \
    if (nof_status.ok()) {                                                                   \
      ::nof::test::record_failure(__FILE__, __LINE__,                                        \
                                  std::string("expected refusal " #expected_code           \
                                              " but the operation succeeded"));             \
    } else if (nof_status.error().code != (expected_code)) {                                 \
      ::nof::test::record_failure(__FILE__, __LINE__,                                        \
                                  std::string("expected refusal " #expected_code " but got ") + \
                                      ::nof::to_string(nof_status.error()));                \
    }                                                                                        \
  } while (false)

#define NOF_CHECK_ERROR(result, expected_code)                                               \
  do {                                                                                      \
    const auto& nof_result = (result);                                                       \
    if (nof_result.ok()) {                                                                   \
      ::nof::test::record_failure(__FILE__, __LINE__,                                        \
                                  std::string("expected error " #expected_code              \
                                              " but the call succeeded"));                  \
    } else if (nof_result.error().code != (expected_code)) {                                 \
      ::nof::test::record_failure(__FILE__, __LINE__,                                        \
                                  std::string("expected error " #expected_code " but got ") + \
                                      ::nof::to_string(nof_result.error()));                \
    }                                                                                        \
  } while (false)
