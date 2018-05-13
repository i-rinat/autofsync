project(autofsync)
cmake_minimum_required(VERSION 3.6)

set(CMAKE_C_STANDARD 99)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror=format")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,--unresolved-symbols=report-all")

add_library(autofsync SHARED
    autofsync.c
)

set_target_properties(autofsync PROPERTIES PREFIX "")
target_link_libraries(autofsync PRIVATE ${CMAKE_DL_LIBS})
