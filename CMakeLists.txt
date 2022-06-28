cmake_minimum_required(VERSION 3.0.0)
project(hw4_atam VERSION 0.1.0)

include(CTest)
enable_testing()

add_executable(hw4_atam debugger.c)
set_property(TARGET hw4_atam PROPERTY C_STANDARD 99)
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
