cmake_minimum_required(VERSION 3.22)
project(p4ec CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(USE_MARCH_NATIVE "Add -march=native" ON)
option(USE_LTO "Enable link-time optimization" OFF)

set(CMAKE_CXX_FLAGS_RELEASE "-O3")
add_compile_options(-O3)
if(USE_MARCH_NATIVE)
  add_compile_options(-march=native)
endif()
if(USE_LTO)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
endif()

find_library(GMP_LIB gmp REQUIRED)
find_library(CRYPTO_LIB crypto REQUIRED)

add_executable(p4ec src/main.cpp src/curve_params.cpp)
target_include_directories(p4ec PRIVATE include)
target_link_libraries(p4ec PRIVATE ${GMP_LIB} ${CRYPTO_LIB})
