cmake_minimum_required(VERSION 3.14)
project(chaskey VERSION 1.0.0)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")
include_directories("${CMAKE_SOURCE_DIR}" "${CMAKE_SOURCE_DIR}/tests")
add_library(chaskey STATIC chaskey.hpp chaskey.cpp)
add_executable(chaskey_test tests/hosted/main.cpp tests/test.cpp)
target_link_libraries(chaskey_test chaskey)

