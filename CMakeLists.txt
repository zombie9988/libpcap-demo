cmake_minimum_required(VERSION 3.0.0)
project(libpcap-demo VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
enable_testing()

find_package (Threads)

add_subdirectory(src/log.c)
add_subdirectory(src/detector)
add_subdirectory(src/console_sender)
add_executable(libpcap-demo main.cpp)
target_link_libraries(libpcap-demo pcap logc systemd console_sender detector ${CMAKE_THREAD_LIBS_INIT})
target_include_directories(${PROJECT_NAME} PUBLIC 
$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/include)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)