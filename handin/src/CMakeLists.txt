cmake_minimum_required(VERSION 3.10)


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -pthread")
include(FindPCAP.cmake)
add_library(router_lib router.cpp)
add_library(server_lib server.cpp)
add_executable(router router.cpp)
add_executable(server server.cpp)
target_link_libraries(router router_lib ${PCAP_LIBRARY})
target_link_libraries(server server_lib ${PCAP_LIBRARY})


add_library(echo_client_lib echo_client.cpp)
add_library(echo_server_lib echo_server.cpp)
add_executable(echo_client echo_client.cpp)
add_executable(echo_server echo_server.cpp)
target_link_libraries(echo_client echo_client_lib ${PCAP_LIBRARY})
target_link_libraries(echo_server echo_server_lib ${PCAP_LIBRARY})


add_library(perf_client_lib perf_client.cpp)
add_library(perf_server_lib perf_server.cpp)
add_executable(perf_client perf_client.cpp)
add_executable(perf_server perf_server.cpp)
target_link_libraries(perf_client perf_client_lib ${PCAP_LIBRARY})
target_link_libraries(perf_server perf_server_lib ${PCAP_LIBRARY})

