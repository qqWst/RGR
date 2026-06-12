cmake_minimum_required(VERSION 3.10)
project(cryptum LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
elseif(MSVC)
    add_compile_options(/W4)
endif()

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

include_directories(include src)

set(MAIN_SOURCES
    src/main.cpp
    src/argParser.cpp
    src/fileIo.cpp
    src/pluginLoader.cpp
    src/algorithmTable.cpp
)

add_executable(cryptum ${MAIN_SOURCES})
if(NOT WIN32)
    target_link_libraries(cryptum dl)
endif()

add_executable(cryptumTest
    tests/cryptumTest.cpp
    src/pluginLoader.cpp
    src/algorithmTable.cpp
)
if(NOT WIN32)
    target_link_libraries(cryptumTest dl)
endif()

add_library(xor    SHARED plugins/xor/xorCipher.cpp)
add_library(rsa    SHARED plugins/rsa/rsaCipher.cpp)
add_library(rabin  SHARED plugins/rabin/rabinCipher.cpp)
add_library(shamir SHARED plugins/shamir/shamirCipher.cpp)

set_target_properties(xor rsa rabin shamir PROPERTIES PREFIX "lib")