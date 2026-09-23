set(NOF_TEST_SOURCES
  framework.cpp
  support.cpp
  test_core.cpp
  test_evidence.cpp
  test_placement.cpp
  test_lifecycle.cpp
  test_persistence.cpp
  test_process.cpp
  test_concurrency.cpp
  test_property.cpp)

add_executable(nof_tests ${NOF_TEST_SOURCES})
target_link_libraries(nof_tests PRIVATE nof::nof)
# The suites also drive the raw socket layer directly for adversarial framing
# tests, which is an internal header reused only by first-party tests.
target_include_directories(nof_tests PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_SOURCE_DIR}/src)
if(MSVC)
  target_compile_definitions(nof_tests PRIVATE NOMINMAX=1 WIN32_LEAN_AND_MEAN=1)
endif()
nof_apply_warnings(nof_tests)
nof_apply_asan(nof_tests)

# The process-level suites spawn the real tools, so they must exist first.
add_dependencies(nof_tests nofctl nofd)
target_compile_definitions(nof_tests PRIVATE
  NOF_NOFD_PATH="$<TARGET_FILE:nofd>"
  NOF_NOFCTL_PATH="$<TARGET_FILE:nofctl>")

add_test(NAME nof.tests COMMAND nof_tests)
