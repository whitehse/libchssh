cmake_minimum_required(VERSION 3.20)
project(libchssh LANGUAGES C VERSION 0.3.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

add_library(chssh STATIC src/chssh.c src/chssh_crypto.c src/chssh_pubkey.c)

target_include_directories(chssh PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_include_directories(chssh PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
# OpenSSL 3 still uses RSA_set0_key for public key assembly from SSH blobs.
if(NOT MSVC)
    set_source_files_properties(src/chssh_crypto.c PROPERTIES
        COMPILE_FLAGS "-Wno-deprecated-declarations")
endif()

# Production crypto: OpenSSL (host) or mbedTLS (CPE / OpenWrt).
# CHSSH_CRYPTO=auto|openssl|mbedtls  (default auto: OpenSSL preferred)
set(CHSSH_CRYPTO "auto" CACHE STRING "Production crypto: auto|openssl|mbedtls")
set(MBEDTLS_ROOT "" CACHE PATH "Root containing usr/include + usr/lib (extracted debs)")

if(MBEDTLS_ROOT)
    list(APPEND CMAKE_PREFIX_PATH "${MBEDTLS_ROOT}")
endif()

set(_chssh_crypto_backend "none")
find_package(OpenSSL)

if(CHSSH_CRYPTO STREQUAL "openssl" OR
   (CHSSH_CRYPTO STREQUAL "auto" AND OpenSSL_FOUND))
    if(OpenSSL_FOUND)
        target_compile_definitions(chssh PUBLIC HAVE_OPENSSL=1 HAVE_MBEDTLS=0)
        target_link_libraries(chssh PUBLIC OpenSSL::SSL OpenSSL::Crypto)
        set(_chssh_crypto_backend "openssl")
        message(STATUS "OpenSSL found (production KEX enabled)")
    endif()
endif()

if(_chssh_crypto_backend STREQUAL "none" AND
   (CHSSH_CRYPTO STREQUAL "mbedtls" OR CHSSH_CRYPTO STREQUAL "auto"))
    set(_mbed_hints "")
    if(MBEDTLS_ROOT)
        list(APPEND _mbed_hints
            "${MBEDTLS_ROOT}/usr/include"
            "${MBEDTLS_ROOT}/include")
    endif()
    find_path(MBEDTLS_INCLUDE_DIR mbedtls/aes.h HINTS ${_mbed_hints} /usr/include)
    set(_mbed_lib_hints "")
    if(MBEDTLS_ROOT)
        list(APPEND _mbed_lib_hints
            "${MBEDTLS_ROOT}/usr/lib/x86_64-linux-gnu"
            "${MBEDTLS_ROOT}/usr/lib"
            "${MBEDTLS_ROOT}/lib")
    endif()
    find_library(MBEDTLS_CRYPTO_LIB NAMES mbedcrypto HINTS ${_mbed_lib_hints})
    find_library(MBEDTLS_X509_LIB NAMES mbedx509 HINTS ${_mbed_lib_hints})
    find_library(MBEDTLS_TLS_LIB NAMES mbedtls HINTS ${_mbed_lib_hints})
    if(MBEDTLS_INCLUDE_DIR AND MBEDTLS_CRYPTO_LIB)
        target_compile_definitions(chssh PUBLIC HAVE_MBEDTLS=1 HAVE_OPENSSL=0)
        target_include_directories(chssh PRIVATE ${MBEDTLS_INCLUDE_DIR})
        target_link_libraries(chssh PUBLIC ${MBEDTLS_CRYPTO_LIB})
        if(MBEDTLS_X509_LIB)
            target_link_libraries(chssh PUBLIC ${MBEDTLS_X509_LIB})
        endif()
        if(MBEDTLS_TLS_LIB)
            target_link_libraries(chssh PUBLIC ${MBEDTLS_TLS_LIB})
        endif()
        set(_chssh_crypto_backend "mbedtls")
        message(STATUS "mbedTLS found (production KEX) ${MBEDTLS_INCLUDE_DIR}")
    endif()
endif()

if(_chssh_crypto_backend STREQUAL "none")
    target_compile_definitions(chssh PUBLIC HAVE_OPENSSL=0 HAVE_MBEDTLS=0)
    message(STATUS "No production crypto (OpenSSL/mbedTLS); lab_mode dialectic only")
endif()
message(STATUS "chssh crypto backend: ${_chssh_crypto_backend}")

include(GNUInstallDirs)
install(TARGETS chssh EXPORT chssh-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT chssh-targets FILE chssh-config.cmake
    NAMESPACE chssh:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/chssh)

enable_testing()

add_executable(chssh_smoke_test tests/test_chssh_smoke.c)
target_link_libraries(chssh_smoke_test PRIVATE chssh)
add_test(NAME chssh_smoke COMMAND chssh_smoke_test)

add_executable(chssh_dialectic_test tests/test_chssh_dialectic.c)
target_link_libraries(chssh_dialectic_test PRIVATE chssh)
add_test(NAME chssh_dialectic COMMAND chssh_dialectic_test)

add_executable(chssh_multi_channel_test tests/test_chssh_multi_channel.c)
target_link_libraries(chssh_multi_channel_test PRIVATE chssh)
add_test(NAME chssh_multi_channel COMMAND chssh_multi_channel_test)

add_executable(chssh_shell_test tests/test_chssh_shell.c)
target_link_libraries(chssh_shell_test PRIVATE chssh)
add_test(NAME chssh_shell COMMAND chssh_shell_test)

add_executable(chssh_pty_test tests/test_chssh_pty.c)
target_link_libraries(chssh_pty_test PRIVATE chssh)
add_test(NAME chssh_pty COMMAND chssh_pty_test)

add_executable(chssh_forward_test tests/test_chssh_forward.c)
target_link_libraries(chssh_forward_test PRIVATE chssh)
add_test(NAME chssh_forward COMMAND chssh_forward_test)

add_executable(chssh_hold_ident_test tests/test_chssh_hold_ident.c)
target_link_libraries(chssh_hold_ident_test PRIVATE chssh)
add_test(NAME chssh_hold_ident COMMAND chssh_hold_ident_test)

add_executable(chssh_production_test tests/test_chssh_production.c)
target_link_libraries(chssh_production_test PRIVATE chssh)
add_test(NAME chssh_production COMMAND chssh_production_test)

add_executable(chssh_hostkey_pem_test tests/test_chssh_hostkey_pem.c)
target_link_libraries(chssh_hostkey_pem_test PRIVATE chssh)
add_test(NAME chssh_hostkey_pem COMMAND chssh_hostkey_pem_test)

add_executable(chssh_pubkey_test tests/test_chssh_pubkey.c)
target_link_libraries(chssh_pubkey_test PRIVATE chssh)
add_test(NAME chssh_pubkey COMMAND chssh_pubkey_test)

# Optional OpenSSH client interop (TCP host + shell script; skips without sshpass)
add_executable(chssh_openssh_server tests/chssh_openssh_server.c)
target_link_libraries(chssh_openssh_server PRIVATE chssh)
add_test(NAME chssh_openssh_client
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_chssh_openssh_client.sh)
set_tests_properties(chssh_openssh_client PROPERTIES
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    ENVIRONMENT "PATH=${CMAKE_CURRENT_BINARY_DIR}:$ENV{PATH}")

# OpenSSH interactive staff shell (pty-req + shell; password auth)
add_executable(chssh_openssh_staff_server tests/chssh_openssh_staff_server.c)
target_link_libraries(chssh_openssh_staff_server PRIVATE chssh)
add_test(NAME chssh_openssh_staff
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_chssh_openssh_staff.sh)
set_tests_properties(chssh_openssh_staff PROPERTIES
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    ENVIRONMENT "PATH=${CMAKE_CURRENT_BINARY_DIR}:$ENV{PATH}")

option(ENABLE_FUZZ "Build fuzz harness (requires libFuzzer)" OFF)
if(ENABLE_FUZZ)
    add_executable(fuzz_chssh fuzz/fuzz_chssh.c)
    target_link_libraries(fuzz_chssh PRIVATE chssh)
    target_compile_options(fuzz_chssh PRIVATE -fsanitize=fuzzer,address -g -O1)
    target_link_options(fuzz_chssh PRIVATE -fsanitize=fuzzer,address)
endif()
