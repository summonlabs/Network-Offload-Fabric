cmake_minimum_required(VERSION 3.20)

project(NetworkOffloadFabric
  VERSION 1.0.0
  DESCRIPTION "Vendor-neutral C++20 runtime that owns network-wide assignment of forwarding and offload functions"
  HOMEPAGE_URL "https://github.com/summonlabs/Network-Offload-Fabric"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

option(NOF_BUILD_TOOLS "Build the nofctl and nofd command line tools" ON)
option(NOF_BUILD_TESTS "Build the test suite" ON)
option(NOF_BUILD_BENCHMARKS "Build the benchmarks" ON)
option(NOF_WARNINGS_AS_ERRORS "Treat first-party warnings as errors" ON)
option(NOF_ENABLE_ASAN "Build with AddressSanitizer where the toolchain supports it" OFF)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

# Warning configuration lives on each target as PRIVATE compile options so that
# nothing leaks to downstream consumers of the exported package.
function(nof_apply_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus)
    if(NOF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    if(NOF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

function(nof_apply_asan target)
  if(NOF_ENABLE_ASAN)
    if(MSVC)
      target_compile_options(${target} PRIVATE /fsanitize=address)
      target_link_options(${target} PRIVATE /fsanitize=address)
    else()
      target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=address)
    endif()
  endif()
endfunction()

set(NOF_PUBLIC_HEADERS
  include/nof/assignment.hpp
  include/nof/authority.hpp
  include/nof/bounds.hpp
  include/nof/cancel.hpp
  include/nof/canonical.hpp
  include/nof/capability.hpp
  include/nof/checked.hpp
  include/nof/digest.hpp
  include/nof/error.hpp
  include/nof/explanation.hpp
  include/nof/fabric.hpp
  include/nof/function.hpp
  include/nof/ids.hpp
  include/nof/journal.hpp
  include/nof/observation.hpp
  include/nof/policy.hpp
  include/nof/scope.hpp
  include/nof/service.hpp
  include/nof/synthetic.hpp
  include/nof/time.hpp
  include/nof/topology.hpp
  include/nof/units.hpp
  include/nof/version.hpp
  include/nof/wire.hpp)

set(NOF_SOURCES
  src/assignment.cpp
  src/detail/file_io.cpp
  src/authority.cpp
  src/bounds.cpp
  src/canonical.cpp
  src/capability.cpp
  src/digest.cpp
  src/error.cpp
  src/explanation.cpp
  src/export.cpp
  src/fabric.cpp
  src/function.cpp
  src/ids.cpp
  src/journal.cpp
  src/detail/file_io.cpp
  src/detail/net.cpp
  src/observation.cpp
  src/policy.cpp
  src/scope.cpp
  src/service.cpp
  src/synthetic.cpp
  src/time.cpp
  src/topology.cpp
  src/version.cpp
  src/wire.cpp)

add_library(nof ${NOF_SOURCES})
add_library(nof::nof ALIAS nof)
set_target_properties(nof PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  OUTPUT_NAME nof)

target_include_directories(nof
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src)

if(WIN32)
  target_link_libraries(nof PRIVATE ws2_32)
endif()

target_compile_definitions(nof PRIVATE NOF_BUILDING_LIBRARY=1)
if(MSVC)
  target_compile_definitions(nof PRIVATE _CRT_SECURE_NO_WARNINGS=1 NOMINMAX=1 WIN32_LEAN_AND_MEAN=1)
endif()
nof_apply_warnings(nof)
nof_apply_asan(nof)

if(NOF_BUILD_TOOLS)
  add_executable(nofctl tools/nofctl.cpp)
  target_link_libraries(nofctl PRIVATE nof::nof)
  if(MSVC)
    target_compile_definitions(nofctl PRIVATE NOMINMAX=1 WIN32_LEAN_AND_MEAN=1)
  endif()
  nof_apply_warnings(nofctl)
  nof_apply_asan(nofctl)

  add_executable(nofd tools/nofd.cpp)
  target_link_libraries(nofd PRIVATE nof::nof)
  if(MSVC)
    target_compile_definitions(nofd PRIVATE NOMINMAX=1 WIN32_LEAN_AND_MEAN=1)
  endif()
  nof_apply_warnings(nofd)
  nof_apply_asan(nofd)
endif()

if(NOF_BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(NOF_BUILD_BENCHMARKS)
  add_executable(nof_bench bench/bench_fabric.cpp)
  target_link_libraries(nof_bench PRIVATE nof::nof)
  if(MSVC)
    target_compile_definitions(nof_bench PRIVATE NOMINMAX=1 WIN32_LEAN_AND_MEAN=1)
  endif()
  nof_apply_warnings(nof_bench)
  nof_apply_asan(nof_bench)
endif()

# ---------------------------------------------------------------------------
# Install / package
# ---------------------------------------------------------------------------
install(TARGETS nof
  EXPORT nofTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(NOF_BUILD_TOOLS)
  install(TARGETS nofctl nofd
    EXPORT nofTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(DIRECTORY include/nof DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

set(NOF_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/nof)

configure_package_config_file(
  cmake/nof-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/nof-config.cmake
  INSTALL_DESTINATION ${NOF_CMAKE_DIR})

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/nof-config-version.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
  ARCH_INDEPENDENT)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/nof-config.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/nof-config-version.cmake
  DESTINATION ${NOF_CMAKE_DIR})

install(EXPORT nofTargets
  NAMESPACE nof::
  FILE nof-targets.cmake
  DESTINATION ${NOF_CMAKE_DIR})

export(EXPORT nofTargets NAMESPACE nof:: FILE ${CMAKE_CURRENT_BINARY_DIR}/nof-targets.cmake)
