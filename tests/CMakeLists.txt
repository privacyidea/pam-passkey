# Unit tests for pam-passkey. Built only when BUILD_TESTING=ON.

include(GoogleTest)

# Helper: create a test executable that links the named project sources plus
# our PAM stub, gtest_main, and any necessary system libs.
function(pam_passkey_add_test name)
    set(sources ${ARGN})
    add_executable(${name} ${sources} pam_stub.cpp)
    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/generated
        ${OPENSSL_INCLUDE_DIRS}
        ${CURL_INCLUDE_DIRS}
        ${FIDO2_INCLUDE_DIRS}
    )
    # Make the fixtures directory discoverable at runtime via a compile-time macro.
    target_compile_definitions(${name} PRIVATE
        FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures"
    )
    target_link_libraries(${name} PRIVATE
        gtest_main
        nlohmann_json::nlohmann_json
        ${OPENSSL_LIBRARIES}
        ${CURL_LIBRARIES}
    )
    gtest_discover_tests(${name})
endfunction()

# Convert helpers — no project deps beyond OpenSSL.
pam_passkey_add_test(test_convert
    test_convert.cpp
    ${CMAKE_SOURCE_DIR}/src/convert.cpp
)

# SecureString — header-only.
pam_passkey_add_test(test_secure_string
    test_secure_string.cpp
)

# parseResponse and offline credential flow — needs PrivacyIDEA + Convert.
pam_passkey_add_test(test_parse_response
    test_parse_response.cpp
    ${CMAKE_SOURCE_DIR}/src/privacyidea.cpp
    ${CMAKE_SOURCE_DIR}/src/convert.cpp
)

# parseOfflineRefillResponse — uses captured /validate/offlinerefill response shapes.
pam_passkey_add_test(test_refill
    test_refill.cpp
    ${CMAKE_SOURCE_DIR}/src/privacyidea.cpp
    ${CMAKE_SOURCE_DIR}/src/convert.cpp
)

# to_json/from_json round-trip for the offline file schema.
pam_passkey_add_test(test_offline_credential_json
    test_offline_credential_json.cpp
    ${CMAKE_SOURCE_DIR}/src/privacyidea.cpp
    ${CMAKE_SOURCE_DIR}/src/convert.cpp
)

# COSE_Key (CBOR) → EVP_PKEY parsing used by the offline FIDO path.
add_executable(test_cose_key
    test_cose_key.cpp
    pam_stub.cpp
    ${CMAKE_SOURCE_DIR}/src/cose_key.cpp
    ${CMAKE_SOURCE_DIR}/src/convert.cpp
)
target_include_directories(test_cose_key PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(test_cose_key PRIVATE
    gtest_main
    ${OPENSSL_LIBRARIES}
    cbor
)
gtest_discover_tests(test_cose_key)
