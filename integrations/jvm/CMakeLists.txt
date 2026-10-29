cmake_minimum_required(VERSION 3.10)
project(vandam-jvm CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find JNI for JVMTI headers
find_package(JNI REQUIRED)

# Define shared library target
add_library(vandam-jvm SHARED src/agent.cpp)

# Include JNI directories
target_include_directories(vandam-jvm PRIVATE ${JNI_INCLUDE_DIRS})

# Set output name to libvandam-jvm.so
set_target_properties(vandam-jvm PROPERTIES
    PREFIX ""
    OUTPUT_NAME "vandam-jvm"
)

# Statically link standard libraries for zero runtime dependency
target_link_options(vandam-jvm PRIVATE "-static-libstdc++" "-static-libgcc")

message(STATUS "JNI Include Directories: ${JNI_INCLUDE_DIRS}")
