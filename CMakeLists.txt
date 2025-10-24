cmake_minimum_required(VERSION 3.10)

project(pampasskey VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include GNUInstallDirs to determine standard installation paths
include(GNUInstallDirs)

# PAM modules are shared libraries with a specific naming convention
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Find dependencies
find_package(PkgConfig REQUIRED)

pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(FIDO2 REQUIRED libfido2)
pkg_check_modules(OPENSSL REQUIRED openssl)

# Include directories
include_directories(
    include
    ${CURL_INCLUDE_DIRS}
    ${FIDO2_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
)

# Add source files
add_library(privacyidea_pam_passkey MODULE
    src/privacyidea_passkey.cpp
    src/privacyidea.cpp
    src/fido_device.cpp
    src/convert.cpp
)

# Link libraries
target_link_libraries(privacyidea_pam_passkey
    PRIVATE
    ${CURL_LIBRARIES}
    ${FIDO2_LIBRARIES}
    ${OPENSSL_LIBRARIES}
)

# Set properties for the PAM module
set_target_properties(privacyidea_pam_passkey PROPERTIES
    PREFIX ""
    SUFFIX ".so"
)

# For testing, install the PAM module to the system's security directory.
# This requires administrator privileges (e.g., 'sudo make install').
# GNUInstallDirs typically finds the multi-arch path (e.g., /usr/lib/x86_64-linux-gnu/security)
install(TARGETS privacyidea_pam_passkey
    DESTINATION /usr/lib/x86_64-linux-gnu/security
)
