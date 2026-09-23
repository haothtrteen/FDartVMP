# Android FFI plugin build for dartvmp.
#
# Flutter's Gradle plugin builds src/ into libdartvmp.so and packages it into
# the APK's lib/<abi>/ directory.
cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME "dartvmp")
project(${PROJECT_NAME} LANGUAGES C)

# Release builds get the anti-debug layer; debug builds keep it off so
# `flutter run` and `flutter attach` work.
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
  set(DVMP_ANTIDEBUG ON CACHE BOOL "" FORCE)
  set(DVMP_HARDEN_ALLOC ON CACHE BOOL "" FORCE)
endif()

# The core library lives in ../src. The absolute path matters: Flutter adds
# plugins through a symlinked directory, and an absolute subdirectory keeps
# CMake from resolving source paths against the symlink.
set(DVMP_CORE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../src")
get_filename_component(DVMP_CORE_DIR "${DVMP_CORE_DIR}" ABSOLUTE)

add_subdirectory("${DVMP_CORE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/dartvmp_core")

set(dartvmp_bundled_libraries ""
    PARENT_SCOPE)
