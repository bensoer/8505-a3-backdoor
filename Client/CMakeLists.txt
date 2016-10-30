cmake_minimum_required(VERSION 3.3)
project(Client)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -lpcap")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(SOURCE_FILES src/client/main.cpp src/utils/Logger.cpp src/client/CovertSocket.cpp src/client/CovertSocket.h src/client/NetworkMonitor.cpp src/client/NetworkMonitor.h src/client/TrafficAnalyzer.cpp src/client/TrafficAnalyzer.h src/utils/Structures.h)
add_executable(Client ${SOURCE_FILES})