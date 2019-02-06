cmake_minimum_required(VERSION 3.7)
project(virtnd)

set(CMAKE_CXX_STANDARD 14)

file(GLOB SOURCE_FILES *)

add_executable(virtnd ${SOURCE_FILES})
target_link_libraries(virtnd pthread)