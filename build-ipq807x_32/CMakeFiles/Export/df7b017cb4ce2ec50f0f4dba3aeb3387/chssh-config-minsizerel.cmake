#----------------------------------------------------------------
# Generated CMake target import file for configuration "MinSizeRel".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "chssh::chssh" for configuration "MinSizeRel"
set_property(TARGET chssh::chssh APPEND PROPERTY IMPORTED_CONFIGURATIONS MINSIZEREL)
set_target_properties(chssh::chssh PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_MINSIZEREL "C"
  IMPORTED_LOCATION_MINSIZEREL "${_IMPORT_PREFIX}/lib/libchssh.a"
  )

list(APPEND _cmake_import_check_targets chssh::chssh )
list(APPEND _cmake_import_check_files_for_chssh::chssh "${_IMPORT_PREFIX}/lib/libchssh.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
