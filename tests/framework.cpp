#include "framework.hpp"

#include <cstdio>
#include <cstring>
#include <string>

namespace nof::test {

namespace {

bool g_case_failed = false;

}  // namespace

Registry& Registry::instance() {
  static Registry registry;
  return registry;
}

void Registry::add(const char* suite, const char* name, Body body) {
  Case item;
  item.suite = suite;
  item.name = name;
  item.body = std::move(body);
  cases_.push_back(std::move(item));
}

void record_failure(const char* file, int line, const std::string& message) {
  g_case_failed = true;
  std::fprintf(stderr, "    failure at %s:%d: %s\n", file, line, message.c_str());
}

bool case_failed() { return g_case_failed; }

int run_all(int argc, char** argv) {
  std::string filter;
  bool list_only = false;
  for (int index = 1; index < argc; ++index) {
    const std::string argument = argv[index];
    if (argument.rfind("--filter=", 0) == 0) {
      filter = argument.substr(9);
    } else if (argument == "--list") {
      list_only = true;
    }
  }

  const std::vector<Case>& cases = Registry::instance().cases();
  if (list_only) {
    for (const Case& item : cases) {
      std::printf("%s.%s\n", item.suite.c_str(), item.name.c_str());
    }
    return 0;
  }

  std::size_t executed = 0;
  std::size_t failed = 0;
  std::size_t skipped = 0;
  std::string current_suite;
  for (const Case& item : cases) {
    const std::string full = item.suite + "." + item.name;
    if (!filter.empty() && full.find(filter) == std::string::npos) {
      ++skipped;
      continue;
    }
    if (item.suite != current_suite) {
      current_suite = item.suite;
      std::printf("[%s]\n", current_suite.c_str());
    }
    std::printf("  %s ... ", item.name.c_str());
    std::fflush(stdout);
    g_case_failed = false;
    try {
      item.body();
    } catch (const std::exception& error) {
      record_failure(__FILE__, __LINE__,
                     std::string("unhandled exception: ") + error.what());
    } catch (...) {
      record_failure(__FILE__, __LINE__, "unhandled non-standard exception");
    }
    ++executed;
    if (g_case_failed) {
      ++failed;
      std::printf("FAILED\n");
    } else {
      std::printf("ok\n");
    }
    std::fflush(stdout);
  }
  std::printf("\n%d executed, %d failed, %d filtered out\n", static_cast<int>(executed),
              static_cast<int>(failed), static_cast<int>(skipped));
  return failed == 0 ? 0 : 1;
}

}  // namespace nof::test

int main(int argc, char** argv) { return nof::test::run_all(argc, argv); }
