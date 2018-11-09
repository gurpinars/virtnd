cmake_minimum_required(VERSION 3.9)
project(virtnd)

set(CMAKE_CXX_STANDARD 14)

file(GLOB SOURCE_FILES
        "*.h"
        "*.cpp")


add_executable(virtnd ${SOURCE_FILES})
target_link_libraries( virtnd pthread)