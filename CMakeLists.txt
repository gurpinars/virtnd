cmake_minimum_required(VERSION 3.9)
project(virtnd)

set(CMAKE_CXX_STANDARD 14)


set(SOURCE_FILES virtnd.cpp
        netdev.cpp netdev.h
        ethernet.h ethernet.cpp
        arp.cpp arp.h
        icmp.cpp icmp.h
        ip.cpp ip.h
        route.cpp route.h
        tap.cpp tap.h
        utils.cpp utils.h)


add_executable(virtnd ${SOURCE_FILES})
target_link_libraries(virtnd pthread)