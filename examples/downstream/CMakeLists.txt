cmake_minimum_required(VERSION 3.20)
project(nof_downstream_consumer LANGUAGES CXX)

# Independent consumer of the installed package: only find_package() and the
# exported target are used. No repository paths are referenced, and the
# repository's warning flags are intentionally not inherited.
find_package(nof 1.0 REQUIRED CONFIG)

add_executable(nof_consumer main.cpp)
target_compile_features(nof_consumer PRIVATE cxx_std_20)
target_link_libraries(nof_consumer PRIVATE nof::nof)

# The consumer is built with its own warning settings to prove that nothing the
# package exports leaks into downstream compilation.
if(MSVC)
  target_compile_options(nof_consumer PRIVATE /W4 /WX /permissive-)
else()
  target_compile_options(nof_consumer PRIVATE -Wall -Wextra -Werror)
endif()

install(TARGETS nof_consumer RUNTIME DESTINATION bin)
