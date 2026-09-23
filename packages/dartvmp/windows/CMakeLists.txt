# Windows FFI plugin build for dartvmp.
#
# The core library is built STATIC here and linked into the runner executable,
# so the runtime - and the module image inside it - ends up in
# dartvmp_demo.exe rather than in a separate DLL. Dart reaches it through
# DynamicLibrary.executable(); see `openRuntimeLibrary` in lib/src/bindings.dart.
#
# The link has to be requested explicitly, and that is the whole reason this file
# is longer than two lines. Flutter's generated_plugins.cmake only runs
# `target_link_libraries(${BINARY_NAME} PRIVATE ${plugin}_plugin)` for plugins in
# FLUTTER_PLUGIN_LIST; an FFI plugin lands in FLUTTER_FFI_PLUGIN_LIST, whose loop
# only appends to PLUGIN_BUNDLED_LIBRARIES - a list used for *copying* files next
# to the executable, never for linking. So `add_subdirectory` alone built the
# static library and then dropped it on the floor: the runner was 90 KB with zero
# dartvmp_* symbols in it, and the application started fine and then reported
# "could not open dartvmp.dll" on its first screen. Nothing in the test suite
# could see it, because `flutter test` loads the runtime from DARTVMP_LIBRARY_PATH
# and never touches the runner.
#
# This is safe to do here because the top-level app CMakeLists adds the runner
# target BEFORE including generated_plugins.cmake, so ${BINARY_NAME} already
# exists and is visible in this scope.
cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME "dartvmp")
project(${PROJECT_NAME} LANGUAGES C)

# The core library lives in ../src. The absolute path matters: Flutter adds
# plugins through a symlinked directory, and an absolute subdirectory keeps
# CMake from resolving source paths against the symlink.
set(DVMP_CORE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../src")
get_filename_component(DVMP_CORE_DIR "${DVMP_CORE_DIR}" ABSOLUTE)

add_subdirectory("${DVMP_CORE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/dartvmp_core")

if(TARGET ${BINARY_NAME})
  target_link_libraries(${BINARY_NAME} PRIVATE ${PROJECT_NAME})
  # Linking a static library is not enough on its own: the MSVC linker only pulls
  # in the object files that resolve an *undefined* symbol, and nothing in the
  # runner references dartvmp_* by name - the Dart side resolves them at runtime
  # through GetProcAddress. So without this the link succeeds, the library is
  # discarded in full, and the executable comes out at 90 KB with an empty export
  # table. /WHOLEARCHIVE forces every object in.
  target_link_options(${BINARY_NAME} PRIVATE
    "/WHOLEARCHIVE:$<TARGET_FILE:${PROJECT_NAME}>")
  message(STATUS "dartvmp: linked statically into ${BINARY_NAME} (whole archive)")
else()
  # Loud on purpose. The failure this guards against is silent: the build
  # succeeds, the app launches, and every protected call throws
  # VmpUnavailable("could not open dartvmp.dll") at the user. A configure-time
  # error here costs a minute; the runtime one cost a release build.
  message(FATAL_ERROR
    "dartvmp: no '${BINARY_NAME}' target to link into.\n"
    "        This plugin builds a static library and depends on the application's\n"
    "        runner target, which the top-level CMakeLists must define *before*\n"
    "        including flutter/generated_plugins.cmake.")
endif()

# Nothing to copy next to the executable: the runtime is inside it.
set(dartvmp_bundled_libraries ""
    PARENT_SCOPE)
