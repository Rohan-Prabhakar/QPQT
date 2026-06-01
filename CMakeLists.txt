cmake_minimum_required(VERSION 3.16)
project(qpqt VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_library(OQS_LIB oqs HINTS /usr/local/lib)
find_path(OQS_INCLUDE oqs/oqs.h HINTS /usr/local/include)

if(NOT OQS_LIB OR NOT OQS_INCLUDE)
    message(FATAL_ERROR
        "liboqs not found. Run: bash scripts/install_deps.sh")
endif()

find_package(OpenMP)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${OQS_INCLUDE}
    ${OPENSSL_INCLUDE_DIR}
)

add_compile_options(-O3 -march=native)
if(OpenMP_CXX_FOUND)
    add_compile_options(${OpenMP_CXX_FLAGS})
endif()

set(QPQT_LIBS ${OQS_LIB} OpenSSL::SSL OpenSSL::Crypto)
if(OpenMP_CXX_FOUND)
    list(APPEND QPQT_LIBS OpenMP::OpenMP_CXX)
endif()

# Core binaries
add_executable(qpqt_writer  src/qpqt_writer.cpp)
target_link_libraries(qpqt_writer  ${QPQT_LIBS})

add_executable(qpqt_reader  src/qpqt_reader.cpp)
target_link_libraries(qpqt_reader  ${QPQT_LIBS})

# CLI tool
add_executable(qpqt         cli/qpqt_cli.cpp)
target_link_libraries(qpqt  ${QPQT_LIBS})

# Arrow integration (optional — requires Arrow C++ library)
find_package(Arrow QUIET)
if(Arrow_FOUND)
    message(STATUS "Arrow found — building qpqt_arrow with IPC support")
    add_executable(qpqt_arrow integrations/arrow/qpqt_arrow.cpp)
    target_compile_definitions(qpqt_arrow PRIVATE QPQT_ARROW_AVAILABLE)
    target_link_libraries(qpqt_arrow ${QPQT_LIBS} Arrow::arrow_shared)
else()
    message(STATUS "Arrow not found — building qpqt_arrow with CSV fallback")
    add_executable(qpqt_arrow integrations/arrow/qpqt_arrow.cpp)
    target_link_libraries(qpqt_arrow ${QPQT_LIBS})
endif()

# Tests
add_executable(qpqt_tests   tests/qpqt_tests.cpp)
target_link_libraries(qpqt_tests   ${QPQT_LIBS})

# Benchmarks
add_executable(qpqt_bench   benchmarks/qpqt_bench.cpp)
target_link_libraries(qpqt_bench   ${QPQT_LIBS})

install(TARGETS qpqt qpqt_arrow DESTINATION bin)
install(FILES
    include/qpqt_types.h
    include/qpqt_utils.h
    include/qpqt_crypto.h
    DESTINATION include/qpqt
)
