cmake_minimum_required(VERSION 3.7)
project(virtnd)

set(CMAKE_CXX_STANDARD 14)
file(GLOB_RECURSE SOURCES "src/*")
set(COMPILATION_UNIT ${SOURCES})
set(DEPS_LIB_POSIX pthread)

add_executable(${PROJECT_NAME} ${COMPILATION_UNIT})
target_link_libraries(${PROJECT_NAME} ${DEPS_LIB_POSIX})