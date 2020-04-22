cmake_minimum_required(VERSION 3.7)
project(virtnd)

set(CMAKE_CXX_STANDARD 14)

file(GLOB_RECURSE STACK "stack/*")
file(GLOB_RECURSE UTILITY "utility/*")

set(COMPILATION_UNIT
        netdev.cpp netdev.h
        packet_processor.cpp packet_processor.h
        virtnd.cpp ${STACK} ${UTILITY})

set(DEPS_LIB_POSIX pthread)

add_executable(${PROJECT_NAME} ${COMPILATION_UNIT})
target_link_libraries(${PROJECT_NAME} ${DEPS_LIB_POSIX})