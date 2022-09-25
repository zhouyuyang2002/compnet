cmake_minimum_required(VERSION 3.10)

include(FindPCAP.cmake)
add_library(main main.cpp)
add_executable(lab1 main.cpp)
target_link_libraries(lab1 main ${PCAP_LIBRARY})
