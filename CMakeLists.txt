cmake_minimum_required(VERSION 3.20)
project(nullsec-bingaze VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Security-hardened compiler flags
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Werror
    -Wconversion
    -Wsign-conversion
    -Wformat=2
    -Wformat-security
    -Wnull-dereference
    -Wstack-protector
    -fstack-protector-strong
    -fPIE
    -D_FORTIFY_SOURCE=2
    -D_GLIBCXX_ASSERTIONS
)

# Release-specific hardening
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2)
    add_link_options(
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,-z,noexecstack
        -pie
    )
endif()

# Debug with sanitizers
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(
        -g
        -O0
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
    )
    add_link_options(-fsanitize=address,undefined)
endif()

add_executable(bingaze bingaze.cpp)

# Install
install(TARGETS bingaze DESTINATION bin)
