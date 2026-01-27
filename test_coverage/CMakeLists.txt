cmake_minimum_required(VERSION 3.12)
project(PacketAnalyzer_Tests C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT DEFINED ENABLE_TEST)
    option(ENABLE_TEST "Enable building and running unit tests" ON)
endif()

if(NOT DEFINED ENABLE_COVERAGE)
    option(ENABLE_COVERAGE "Enable code coverage collection" ON)
endif()

message(STATUS "====================================")
message(STATUS "Test Configuration")
message(STATUS "====================================")

find_package(CppUTest REQUIRED)

get_filename_component(PROJECT_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)

set(COMMON_INCLUDE_DIRS
    ${PROJECT_ROOT_DIR}/Inc
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks
)

# Mock files
set(COMMON_MOCK_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks/mock_network.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks/mock_pthread.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks/mock_system.cpp
)

# Function to setup test targets
function(setup_test_target TARGET_NAME TEST_FILE)
    message(STATUS "Configuring: ${TARGET_NAME}")

    add_executable(${TARGET_NAME} 
        ${PROJECT_ROOT_DIR}/Src/packet_analyzer.c
        ${TEST_FILE}
        ${COMMON_MOCK_FILES}
    )

    # Define EXCLUDE_MAIN for the C source file only
    set_source_files_properties(
        ${PROJECT_ROOT_DIR}/Src/packet_analyzer.c
        PROPERTIES COMPILE_DEFINITIONS "EXCLUDE_MAIN=1"
    )

    target_compile_definitions(${TARGET_NAME} PRIVATE
        UNIT_TESTING
        UNIT_TEST
    )

    target_compile_options(${TARGET_NAME} PRIVATE
        -Wall
        -Wextra
        $<$<COMPILE_LANGUAGE:CXX>:-fpermissive>
    )

    target_include_directories(${TARGET_NAME} PRIVATE ${COMMON_INCLUDE_DIRS})

    if(ENABLE_COVERAGE)
        target_compile_options(${TARGET_NAME} PRIVATE 
            -fprofile-arcs 
            -ftest-coverage 
            -g 
            -O0
        )
        target_link_libraries(${TARGET_NAME} PRIVATE gcov)
    endif()

    target_link_libraries(${TARGET_NAME} PRIVATE 
        CppUTest 
        CppUTestExt 
        pthread
    )

    set_target_properties(${TARGET_NAME} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_test(
        NAME ${TARGET_NAME}_Run
        COMMAND ${TARGET_NAME}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endfunction()

set(TEST_TARGETS "")

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/PacketAnalyzerTests.cpp)
    setup_test_target(PacketAnalyzer_TESTS
        ${CMAKE_CURRENT_SOURCE_DIR}/PacketAnalyzerTests.cpp
    )
    list(APPEND TEST_TARGETS PacketAnalyzer_TESTS)
endif()

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/SecurityTests.cpp)
    setup_test_target(Security_TESTS
        ${CMAKE_CURRENT_SOURCE_DIR}/SecurityTests.cpp
    )
    list(APPEND TEST_TARGETS Security_TESTS)
endif()

if(NOT TEST_TARGETS)
    message(FATAL_ERROR "No test files found!")
endif()

message(STATUS "Test targets: ${TEST_TARGETS}")

if(ENABLE_COVERAGE AND TEST_TARGETS)
    find_program(LCOV_EXEC lcov)
    find_program(GENHTML_EXEC genhtml)

    if(LCOV_EXEC AND GENHTML_EXEC)
        set(COVERAGE_DIR "${CMAKE_CURRENT_BINARY_DIR}/coverage")
        set(RUN_TESTS_CMD "")
        foreach(TARGET ${TEST_TARGETS})
            list(APPEND RUN_TESTS_CMD COMMAND ${CMAKE_CURRENT_BINARY_DIR}/${TARGET})
        endforeach()

        add_custom_target(coverage
            COMMAND ${CMAKE_COMMAND} -E remove_directory "${COVERAGE_DIR}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${COVERAGE_DIR}"
            COMMAND ${LCOV_EXEC} --directory ${CMAKE_CURRENT_BINARY_DIR} --zerocounters
            ${RUN_TESTS_CMD}
            COMMAND ${LCOV_EXEC} --rc lcov_branch_coverage=1 
                    --capture 
                    --directory ${CMAKE_CURRENT_BINARY_DIR}
                    --output-file ${COVERAGE_DIR}/coverage_total.info 
                    --ignore-errors inconsistent,unused,empty
            COMMAND ${LCOV_EXEC} --rc lcov_branch_coverage=1
                    --extract ${COVERAGE_DIR}/coverage_total.info
                    "*/Src/packet_analyzer.c" 
                    --output-file ${COVERAGE_DIR}/coverage_filtered.info 
                    --ignore-errors inconsistent,unused,empty
            COMMAND ${GENHTML_EXEC} ${COVERAGE_DIR}/coverage_filtered.info 
                    --output-directory ${COVERAGE_DIR}/html 
                    --legend 
                    --branch-coverage
                    --show-details 
                    --ignore-errors source
            COMMAND ${CMAKE_COMMAND} -E echo "Coverage: ${COVERAGE_DIR}/html/index.html"
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            DEPENDS ${TEST_TARGETS}
        )
        message(STATUS "Coverage target configured")
    endif()
endif()

enable_testing()
message(STATUS "====================================")
