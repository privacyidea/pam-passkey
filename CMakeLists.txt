cmake_minimum_required(VERSION 3.24)

project(pampasskey VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include GNUInstallDirs to determine standard installation paths
include(GNUInstallDirs)

# PAM modules are shared libraries with a specific naming convention
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Single source of truth for the version string. Generates a header that
# substitutes @PROJECT_VERSION@ so source files and the User-Agent never
# drift from the CMake project() declaration above.
configure_file(
    ${CMAKE_SOURCE_DIR}/include/version.h.in
    ${CMAKE_BINARY_DIR}/generated/version.h
    @ONLY
)

# Find dependencies
find_package(PkgConfig REQUIRED)

pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(FIDO2 REQUIRED libfido2)
pkg_check_modules(OPENSSL REQUIRED openssl)
find_package(nlohmann_json REQUIRED)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_library(PAM_LIBRARY pam REQUIRED)

# Add source files
add_library(pam_privacyidea_passkey MODULE
    src/privacyidea_passkey.cpp
    src/privacyidea.cpp
    src/fido_device.cpp
    src/cose_key.cpp
    src/convert.cpp
)

target_include_directories(pam_privacyidea_passkey PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/generated
    ${CURL_INCLUDE_DIRS}
    ${FIDO2_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(pam_privacyidea_passkey
    PRIVATE
    ${CURL_LIBRARIES}
    ${FIDO2_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    nlohmann_json::nlohmann_json
    Threads::Threads
    ${PAM_LIBRARY}
)

# Set properties for the PAM module
set_target_properties(pam_privacyidea_passkey PROPERTIES
    PREFIX ""
    SUFFIX ".so"
)

target_compile_options(pam_privacyidea_passkey PRIVATE
    -Wall -Wextra -Wpedantic
    -fstack-protector-strong
)
# _FORTIFY_SOURCE requires an optimized build to be meaningful (gcc warns
# otherwise). Apply it only when not building plain Debug.
target_compile_definitions(pam_privacyidea_passkey PRIVATE
    $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>
)

# For testing, install the PAM module to the system's security directory.
# This requires administrator privileges (e.g., 'sudo make install').
# GNUInstallDirs typically finds the multi-arch path (e.g., /usr/lib/x86_64-linux-gnu/security)
install(TARGETS pam_privacyidea_passkey
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/security
)

# Unit tests — opt-in with -DBUILD_TESTING=ON. Pulls in GoogleTest via
# FetchContent so the build is self-contained (no system gtest dependency).
option(BUILD_TESTING "Build unit tests" OFF)
if(BUILD_TESTING)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    enable_testing()
    add_subdirectory(tests)
endif()
