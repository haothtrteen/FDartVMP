# CMakeLists.txt - builds the dartvmp runtime as a *standalone shared library*
# for the host platform.
#
# WHY THIS EXISTS
# ---------------
# The Flutter plugin build (packages/dartvmp/{windows,android}/CMakeLists.txt)
# links the runtime statically into the desktop runner, so `flutter test` - which
# builds its own host process - has nothing to dlopen. This project produces the
# same sources as a loadable library so the differential test suite can run the
# interpreter against the Dart oracle.
#
#   cmake -S tool/hostlib -B build/hostlib
#   cmake --build build/hostlib --config Release
#
# then copy the result next to the test host (tool/build_native.ps1 does this).
#
# It reuses packages/dartvmp/src via add_subdirectory, so there is exactly one
# definition of the source list and the compile definitions - the same ones the
# shipping plugin uses.
cmake_minimum_required(VERSION 3.14)
project(dartvmp_hostlib LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# The shared-library target name must be "dartvmp" so the artifact is
# dartvmp.dll / libdartvmp.so, which is what DynamicLibrary.open() looks for.
add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../../packages/dartvmp/src"
                 "${CMAKE_CURRENT_BINARY_DIR}/core")

# The core target is a STATIC library (correct for the plugin, which links it
# into the runner). Re-expose the same objects as a shared library by compiling
# the sources a second time with the same settings; CMake then owns all the
# platform-specific linker quoting, which a hand-rolled cl.exe command line
# cannot get right.
set(DVMP_CORE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../../packages/dartvmp/src")
get_filename_component(DVMP_CORE_SRC "${DVMP_CORE_SRC}" ABSOLUTE)
set(DVMP_IMAGE "${CMAKE_CURRENT_SOURCE_DIR}/../../packages/dartvmp/generated/vmp_module.inc")
get_filename_component(DVMP_IMAGE "${DVMP_IMAGE}" ABSOLUTE)

if(NOT EXISTS "${DVMP_IMAGE}")
  message(FATAL_ERROR
    "packages/dartvmp/generated/vmp_module.inc not found. "
    "Run `dart run tool/build.dart` from the repository root first.")
endif()

# The core source list, duplicated from packages/dartvmp/src/CMakeLists.txt because
# this target needs different compile definitions (diagnostics ON, so the test host can
# reach the interpreter's internals).
#
# Duplication is the problem, so it is checked rather than trusted: the assertion below
# compares this list against every .c file actually present in the core directory and
# fails configuration on any difference. Adding a source to src/ and forgetting it here
# produced exactly the kind of failure this is meant to catch - `dvmp_sha256.c` was
# added, the Android and Windows builds picked it up (they read DVMP_SOURCES), and this
# target alone failed to link with "unresolved external symbol dvmp_mask_keystream".
set(DVMP_CORE_SOURCES
  "dartvmp.c"
  "dvmp_module.c"
  "dvmp_value.c"
  "dvmp_vm.c"
  "dvmp_host.c"
  "dvmp_secure.c"
  "dvmp_sha256.c"
  "dvmp_antidebug.c"
  "dvmp_integrity.c"
)

file(GLOB DVMP_CORE_PRESENT RELATIVE "${DVMP_CORE_SRC}" "${DVMP_CORE_SRC}/*.c")
list(SORT DVMP_CORE_SOURCES)
list(SORT DVMP_CORE_PRESENT)
if(NOT DVMP_CORE_SOURCES STREQUAL DVMP_CORE_PRESENT)
  message(FATAL_ERROR
    "tool/hostlib/CMakeLists.txt and packages/dartvmp/src/CMakeLists.txt disagree "
    "about the core sources.\n"
    "  listed here : ${DVMP_CORE_SOURCES}\n"
    "  present in  : ${DVMP_CORE_PRESENT}\n"
    "Add the missing file to DVMP_CORE_SOURCES (or remove the stale entry); the "
    "release builds read DVMP_SOURCES in the core CMakeLists and will link, so "
    "without this check only the test host breaks.")
endif()

# Built FROM the list above rather than from a second copy of the names.
#
# It was a second copy, and that is how dvmp_integrity.c got added to DVMP_CORE_SOURCES
# (so the assertion below passed) while the build kept linking without it - a link
# error, but only in this target. The assertion compares the list against the directory;
# it cannot see a hand-written add_library that disagrees with both. Deriving the
# sources from the list makes that disagreement unrepresentable.
set(DVMP_CORE_ABS)
foreach(f IN LISTS DVMP_CORE_SOURCES)
  list(APPEND DVMP_CORE_ABS "${DVMP_CORE_SRC}/${f}")
endforeach()

add_library(dartvmp_hostlib SHARED ${DVMP_CORE_ABS})

set_target_properties(dartvmp_hostlib PROPERTIES
  OUTPUT_NAME dartvmp
  PREFIX ""
  C_VISIBILITY_PRESET hidden
  POSITION_INDEPENDENT_CODE ON)

target_include_directories(dartvmp_hostlib PRIVATE "${DVMP_CORE_SRC}")

# Same defines as the plugin build, plus the generated image location.
target_compile_definitions(dartvmp_hostlib PRIVATE
  DVMP_HARDEN_ALLOC=1
  "DVMP_MODULE_INCLUDE=\"${DVMP_IMAGE}\"")

if(WIN32)
  target_compile_definitions(dartvmp_hostlib PRIVATE
    DVMP_PLATFORM_WINDOWS=1 _CRT_SECURE_NO_WARNINGS=1)
else()
  target_compile_definitions(dartvmp_hostlib PRIVATE DVMP_PLATFORM_POSIX=1)
  target_link_libraries(dartvmp_hostlib PRIVATE m)
endif()

# The antidebug layer is opt-in here. Turning it on in the test harness would
# abort the whole test process the moment a profiler or an IDE debugger is
# attached, which is a confusing failure for a library used by tests.
option(DVMP_HOSTLIB_ANTIDEBUG "Enable instrumentation detection in the test library" OFF)
if(DVMP_HOSTLIB_ANTIDEBUG)
  target_compile_definitions(dartvmp_hostlib PRIVATE DVMP_ANTIDEBUG=1)
endif()

# Diagnostic probe exports (dartvmp_code_probe / desc_probe / mask_probe /
# slot_probe / image_probe / session_probe).
#
# ON for the test library, because that is the only way `flutter test` can reach
# the interpreter's internals - the test host does not link the runtime
# statically. A production build turns this OFF so the shipped shared object
# exports only the documented execution ABI; `verify_protection.ps1` asserts
# that.
#
# The define is set explicitly here rather than inherited. The core project
# added above also declares an option named DVMP_DIAGNOSTICS, and `add_subdirectory`
# puts *its* value in the cache, where it silently shadowed this target's
# setting: the probes compiled in even with DVMP_HOSTLIB_DIAGNOSTICS=OFF.
option(DVMP_HOSTLIB_DIAGNOSTICS
       "Export the diagnostic probe symbols (disable for a release build)" ON)
if(DVMP_HOSTLIB_DIAGNOSTICS)
  target_compile_definitions(dartvmp_hostlib PRIVATE DVMP_DIAGNOSTICS=1)
endif()
