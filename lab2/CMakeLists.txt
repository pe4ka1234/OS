cmake_minimum_required(VERSION 3.16)
project(lab2_ipc_variant8 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Strict warnings
add_compile_options(-Wall -Wextra -Werror)

# Common sources used by all host_* executables
set(COMMON_SOURCES
    log.cpp
    io_timeout.cpp
    util.cpp
    game.cpp
)

# Find all conn_*.cpp at configure time
file(GLOB CONN_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/conn_*.cpp")

if(CONN_SOURCES STREQUAL "")
    message(FATAL_ERROR "No conn_*.cpp files found.")
endif()

foreach(CONN ${CONN_SOURCES})
    get_filename_component(CONN_NAME "${CONN}" NAME)
    string(REGEX REPLACE "^conn_(.*)\\.cpp$" "\\1" TYPE_CODE "${CONN_NAME}")

    add_executable(host_${TYPE_CODE} host.cpp ${COMMON_SOURCES} ${CONN})
    target_include_directories(host_${TYPE_CODE} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(host_${TYPE_CODE} PRIVATE pthread)
endforeach()
