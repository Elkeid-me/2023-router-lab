cmake_policy(SET CMP0048 NEW)

project(lab3)
cmake_minimum_required(VERSION 3.11)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

add_compile_options(-Wall)
set(CMAKE_BUILD_TYPE Release)

set(SRC_FILES router.cpp)

add_library(router STATIC ${SRC_FILES})
find_library(LIB_SIMULATOR simulator build/)

add_executable(simulator simulator.cpp)
target_link_libraries(simulator ${LIB_SIMULATOR} router)
