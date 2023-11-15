cmake_minimum_required(VERSION 3.0.0)
project(libpcap-demo VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
enable_testing()

add_subdirectory(log.c)
add_executable(libpcap-demo main.cpp)
target_link_libraries(libpcap-demo pcap logc systemd)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)