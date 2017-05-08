cmake_minimum_required (VERSION 2.8.11)
project (lsconnections C)

set (PROGRAM_NAME "lsconnections")
set (VERSION_MAJOR 0)
set (VERSION_MINOR 1)
set (VERSION_PATCH 0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic -Wextra -std=gnu99")

find_path(PCAP_ROOT_DIR    NAMES include/pcap.h)
find_path(PCAP_INCLUDE_DIR NAMES pcap.h HINTS ${PCAP_ROOT_DIR}/include)
find_library(PCAP_LIBRARY  NAMES pcap   HINTS ${PCAP_ROOT_DIR}/lib)

include_directories( "${PROJECT_SOURCE_DIR}/src" )
include_directories( "${PCAP_INCLUDE_DIR}" )

add_executable(lsconnections src/main.c)
target_link_libraries(lsconnections ${PCAP_LIBRARY})

install(TARGETS lsconnections RUNTIME DESTINATION bin)
