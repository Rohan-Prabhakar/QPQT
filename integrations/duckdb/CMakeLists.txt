cmake_minimum_required(VERSION 3.16)

set(EXTENSION_NAME    qpqt)
set(DUCKDB_VERSION    "v1.5.3")

project(${EXTENSION_NAME} CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Fetch DuckDB ─────────────────────────────────────────────────────────────
include(FetchContent)
FetchContent_Declare(
    duckdb
    GIT_REPOSITORY https://github.com/duckdb/duckdb.git
    GIT_TAG        ${DUCKDB_VERSION}
    GIT_SHALLOW    TRUE
)
set(BUILD_UNITTESTS  OFF CACHE BOOL "" FORCE)
set(BUILD_SHELL      OFF CACHE BOOL "" FORCE)
set(ENABLE_SANITIZER OFF CACHE BOOL "" FORCE)
set(BUILD_EXTENSIONS ""  CACHE STRING "" FORCE)
FetchContent_MakeAvailable(duckdb)

# ── liboqs + OpenSSL + OpenMP ─────────────────────────────────────────────────
find_library(OQS_LIB  oqs HINTS /usr/local/lib /usr/local/lib64 REQUIRED)
find_path(OQS_INCLUDE oqs/oqs.h HINTS /usr/local/include REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(OpenMP)

set(QPQT_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)

# ── Build shared library ──────────────────────────────────────────────────────
add_library(${EXTENSION_NAME} SHARED
    qpqt_extension.cpp
    qpqt_scan.cpp
)

target_include_directories(${EXTENSION_NAME} PRIVATE
    ${duckdb_SOURCE_DIR}/src/include
    ${OQS_INCLUDE}
    ${OPENSSL_INCLUDE_DIR}
    ${QPQT_ROOT}/include
)

target_compile_options(${EXTENSION_NAME} PRIVATE
    -O3 -fPIC
    $<$<BOOL:${OpenMP_CXX_FOUND}>:${OpenMP_CXX_FLAGS}>
)

target_compile_definitions(${EXTENSION_NAME} PRIVATE DUCKDB_EXTENSION_MAIN)

target_link_libraries(${EXTENSION_NAME} PRIVATE
    duckdb_static
    ${OQS_LIB}
    OpenSSL::SSL
    OpenSSL::Crypto
    $<$<BOOL:${OpenMP_CXX_FOUND}>:OpenMP::OpenMP_CXX>
)

set_target_properties(${EXTENSION_NAME} PROPERTIES
    PREFIX   ""
    SUFFIX   ".so"
    OUTPUT_NAME "${EXTENSION_NAME}"
)

# ── Post-build: append DuckDB metadata footer ─────────────────────────────────
add_custom_command(TARGET ${EXTENSION_NAME} POST_BUILD
    COMMAND python3
        ${CMAKE_CURRENT_SOURCE_DIR}/append_metadata.py
        $<TARGET_FILE:${EXTENSION_NAME}>
        ${CMAKE_BINARY_DIR}/${EXTENSION_NAME}.duckdb_extension
    COMMENT "Appending DuckDB extension metadata..."
)
