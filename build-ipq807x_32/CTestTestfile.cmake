# CMake generated Testfile for 
# Source directory: /home/dwhite/libchssh
# Build directory: /home/dwhite/libchssh/build-ipq807x_32
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[chssh_smoke]=] "/home/dwhite/libchssh/build-ipq807x_32/chssh_smoke_test")
set_tests_properties([=[chssh_smoke]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/dwhite/libchssh/CMakeLists.txt;53;add_test;/home/dwhite/libchssh/CMakeLists.txt;0;")
add_test([=[chssh_dialectic]=] "/home/dwhite/libchssh/build-ipq807x_32/chssh_dialectic_test")
set_tests_properties([=[chssh_dialectic]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/dwhite/libchssh/CMakeLists.txt;57;add_test;/home/dwhite/libchssh/CMakeLists.txt;0;")
add_test([=[chssh_multi_channel]=] "/home/dwhite/libchssh/build-ipq807x_32/chssh_multi_channel_test")
set_tests_properties([=[chssh_multi_channel]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/dwhite/libchssh/CMakeLists.txt;61;add_test;/home/dwhite/libchssh/CMakeLists.txt;0;")
add_test([=[chssh_shell]=] "/home/dwhite/libchssh/build-ipq807x_32/chssh_shell_test")
set_tests_properties([=[chssh_shell]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/dwhite/libchssh/CMakeLists.txt;65;add_test;/home/dwhite/libchssh/CMakeLists.txt;0;")
add_test([=[chssh_hold_ident]=] "/home/dwhite/libchssh/build-ipq807x_32/chssh_hold_ident_test")
set_tests_properties([=[chssh_hold_ident]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/dwhite/libchssh/CMakeLists.txt;69;add_test;/home/dwhite/libchssh/CMakeLists.txt;0;")
add_test([=[chssh_production]=] "/home/dwhite/libchssh/build-ipq807x_32/chssh_production_test")
set_tests_properties([=[chssh_production]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/dwhite/libchssh/CMakeLists.txt;73;add_test;/home/dwhite/libchssh/CMakeLists.txt;0;")
add_test([=[chssh_hostkey_pem]=] "/home/dwhite/libchssh/build-ipq807x_32/chssh_hostkey_pem_test")
set_tests_properties([=[chssh_hostkey_pem]=] PROPERTIES  _BACKTRACE_TRIPLES "/home/dwhite/libchssh/CMakeLists.txt;77;add_test;/home/dwhite/libchssh/CMakeLists.txt;0;")
add_test([=[chssh_openssh_client]=] "/home/dwhite/libchssh/tests/test_chssh_openssh_client.sh")
set_tests_properties([=[chssh_openssh_client]=] PROPERTIES  ENVIRONMENT "PATH=/home/dwhite/libchssh/build-ipq807x_32:/home/dwhite/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/home/dwhite/.grok/bin" WORKING_DIRECTORY "/home/dwhite/libchssh/build-ipq807x_32" _BACKTRACE_TRIPLES "/home/dwhite/libchssh/CMakeLists.txt;82;add_test;/home/dwhite/libchssh/CMakeLists.txt;0;")
