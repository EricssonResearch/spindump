cmake_minimum_required(VERSION 3.1)

project(spindump VERSION 1.0.0 LANGUAGES C)

find_program(CLANGTIDY NAMES clang-tidy)
if(CLANGTIDY)
  message(STATUS "Found clang-tidy: ${CLANGTIDY}")
  set(CMAKE_C_CLANG_TIDY ${CLANGTIDY} -system-headers -checks=*)
endif()

find_program(IWYU NAMES include-what-you-use iwyu)
if(IWYU)
  message(STATUS "Found include-what-you-use: ${IWYU}")
  set(CMAKE_C_INCLUDE_WHAT_YOU_USE ${IWYU})
endif()

find_program(CPPCHECK NAMES cppcheck)
if(CPPCHECK)
  message(STATUS "Found cppcheck: ${CPPCHECK}")
  set(CMAKE_C_CPPCHECK ${CPPCHECK} -q --inline-suppr --enable=all)
  set(CMAKE_CXX_CPPCHECK ${CMAKE_C_CPPCHECK})
endif()

include(CheckCCompilerFlag)
foreach(FLAG -pipe -Wextra -Wpedantic -Weverything -Werror
        -fcolor-diagnostics -fdiagnostics-color=always
        -fsanitize=memory -fsanitize-memory-track-origins
        -fsanitize-memory-use-after-dtor -fsanitize=address
        -fsanitize=undefined -fno-omit-frame-pointer
        -fsanitize-address-use-after-scope
        -fno-optimize-sibling-calls -fno-common
        -fsanitize=unsigned-integer-overflow
        -fsanitize=implicit-conversion -fsanitize=nullability
  )
  string(REGEX REPLACE "[-=+]" "_" F ${FLAG})
  check_c_compiler_flag(${FLAG} ${F})
  if(${F})
    add_compile_options(${FLAG})
  endif()
endforeach()

add_subdirectory(src)
