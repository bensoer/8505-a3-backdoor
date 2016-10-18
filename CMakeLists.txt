cmake_minimum_required(VERSION 3.6)
project(8505_a3_backdoor)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
# set the bin folder location
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

set(SOURCE_FILES src/main.cpp)
add_executable(8505_a3_backdoor ${SOURCE_FILES})