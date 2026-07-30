cmake_minimum_required(VERSION 3.20)
project(libchssh LANGUAGES C VERSION 0.2.0)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

add_library(chssh STATIC src/chssh.c src/chssh_crypto.c)

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

# Optional OpenSSL for production KEX (v0.2+)
find_package(OpenSSL)
if(OpenSSL_FOUND)
    target_compile_definitions(chssh PUBLIC HAVE_OPENSSL=1)
    target_link_libraries(chssh PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    message(STATUS "OpenSSL found (production KEX enabled)")
else()
    # Explicit 0 so chssh_crypto.c compiles stubs (lab dialectic only).
    target_compile_definitions(chssh PUBLIC HAVE_OPENSSL=0)
    message(STATUS "OpenSSL not found; lab_mode dialectic only")
endif()

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

# Optional OpenSSH client interop (TCP host + shell script; skips without sshpass)
add_executable(chssh_openssh_server tests/chssh_openssh_server.c)
target_link_libraries(chssh_openssh_server PRIVATE chssh)
add_test(NAME chssh_openssh_client
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_chssh_openssh_client.sh)
set_tests_properties(chssh_openssh_client PROPERTIES
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    ENVIRONMENT "PATH=${CMAKE_CURRENT_BINARY_DIR}:$ENV{PATH}")

option(ENABLE_FUZZ "Build fuzz harness (requires libFuzzer)" OFF)
if(ENABLE_FUZZ)
    add_executable(fuzz_chssh fuzz/fuzz_chssh.c)
    target_link_libraries(fuzz_chssh PRIVATE chssh)
    target_compile_options(fuzz_chssh PRIVATE -fsanitize=fuzzer,address -g -O1)
    target_link_options(fuzz_chssh PRIVATE -fsanitize=fuzzer,address)
endif()
