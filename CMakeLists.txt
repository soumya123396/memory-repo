cmake_minimum_required(VERSION 3.10)
project(danger_project)

# Default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Enable test option
option(ENABLE_TESTS "Enable building and running tests" OFF)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Define paths
set(SOURCE_DIR "${PROJECT_SOURCE_DIR}/Src")
set(INCLUDE_DIR "${PROJECT_SOURCE_DIR}/Inc")

# # Verify that source and header files exist
 file(GLOB SOURCES "${SOURCE_DIR}/danger.c")
 file(GLOB HEADERS "${INCLUDE_DIR}/dangerous_code.h")

# Debug: Print source and header files
message("Source files: ${SOURCES}")
message("Header files: ${HEADERS}")

# Check if the source file exists
if(NOT SOURCES)
    message(FATAL_ERROR "Source file '' not found in ${SOURCE_DIR}")
endif()

# Create the static library
add_library(SPI_LIB STATIC ${SOURCES})
target_include_directories(SPI_LIB PUBLIC ${INCLUDE_DIR})

if(NOT ENABLE_TESTS)
    # Create the main executable only when not testing
    add_executable(danger_project ${SOURCES})
    target_include_directories(danger_project PRIVATE ${INCLUDE_DIR})
else()
    # Add compile definition to disable main in source files
    target_compile_definitions(SPI_LIB PRIVATE ENABLE_TESTS)
    
    # # Add test directory
    # message("Tests are enabled. Adding test directory.")
    # add_subdirectory(tests)
endif()