# DartVMP native runtime build.
#
# The generated module image (vmp_module.inc) is produced by the Dart compiler
# tool before this CMake project is configured:
#
#     dart run tool/vmpc/bin/vmpc.dart build
#
# It lands in lib/src/generated/ and is force-included into dvmp_module.c via
# DVMP_MODULE_INCLUDE so the image stays a compile-time constant in .rodata.

cmake_minimum_required(VERSION 3.14)
set(PROJECT_NAME "dartvmp")
project(${PROJECT_NAME} LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(DVMP_ANTIDEBUG "Enable ptrace/Frida/debugger detection at runtime" OFF)
option(DVMP_HARDEN_ALLOC "Guard the decrypted bytecode mapping (madvise/VirtualLock)" ON)
option(DVMP_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
# Export the diagnostic probe entry points (dartvmp_code_probe and friends).
# ON by default because the test suite needs them; a release build should set
# -DDVMP_DIAGNOSTICS=OFF so the shipped library exports only the execution ABI.
option(DVMP_DIAGNOSTICS "Export the diagnostic probe symbols" ON)
# Hand the C layer to a post-build virtualizer: give the declared targets global
# symbols so a tool can find them, and keep them out of .dynsym via
# vmp_exports.map. See dvmp_vmpacker.h and tool/apply_vmpacker.ps1. Off by default
# because it requires the external tool to be present and is meaningless without it.
option(DVMP_VMPACKER "Mark the C-layer virtualization targets for VMPacker" OFF)
# Stop the compiler vectorising the byte copies in the *cold* translation units, so
# VMPacker can translate the functions that contain them (`#+wide` in
# tool/vmpacker_targets.txt: dvmp_mask_keystream and code_store_build). VMPacker 1.3
# has no SIMD translation, and the SIMD here is the compiler vectorising a
# little-endian keystream store and an inlined memcpy.
#
# Scoped to dvmp_sha256.c and dvmp_module.c on purpose: those two hold the container's
# front door and are entered once per open, so de-vectorising them costs nothing
# measurable, while leaving dvmp_vm.c - the interpreter loop, the hottest code in the
# system - vectorised.
option(DVMP_VMPACKER_NO_VECTORIZE "Disable auto-vectorisation in the cold translation units so VMPacker can translate the wide target set" OFF)
# The same for dvmp_vm.c, which is only needed for the `#+hot` target (dvmp_vm_run:
# the interpreter itself). Separate because that one *is* the hot path - see
# tool/vmpacker_targets.txt.
option(DVMP_VMPACKER_NO_VECTORIZE_HOT "Also disable auto-vectorisation in the interpreter, so VMPacker can translate dvmp_vm_run" OFF)

# Sources are listed as absolute paths: Flutter adds plugin directories as
# symlinks (windows/flutter/ephemeral/.plugin_symlinks/...), and a relative
# source path in add_library() resolves against the *symlink's* directory in
# some CMake versions, which makes the files appear to be missing.
set(DVMP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")

set(DVMP_SOURCES
  "${DVMP_ROOT}/dartvmp.c"
  "${DVMP_ROOT}/dvmp_module.c"
  "${DVMP_ROOT}/dvmp_value.c"
  "${DVMP_ROOT}/dvmp_vm.c"
  "${DVMP_ROOT}/dvmp_host.c"
  "${DVMP_ROOT}/dvmp_secure.c"
  "${DVMP_ROOT}/dvmp_sha256.c"
  "${DVMP_ROOT}/dvmp_antidebug.c"
  "${DVMP_ROOT}/dvmp_integrity.c"
)

# The list above must match the directory, and that is checked here rather than trusted.
#
# There are two build definitions of this library (this one and tool/hostlib), and the
# failure mode when they drift is nasty: a source added here and not there links fine in
# every shipped configuration and breaks only the test host (dvmp_sha256.c did exactly
# that). tool/hostlib asserts the same thing against its own copy; this half of it was
# missing until dvmp_integrity.c was added and the Android build was the one that would
# have silently shipped without it.
file(GLOB DVMP_PRESENT RELATIVE "${DVMP_ROOT}" "${DVMP_ROOT}/*.c")
set(DVMP_LISTED)
foreach(f IN LISTS DVMP_SOURCES)
  get_filename_component(_name "${f}" NAME)
  list(APPEND DVMP_LISTED "${_name}")
endforeach()
list(SORT DVMP_PRESENT)
list(SORT DVMP_LISTED)
if(NOT DVMP_LISTED STREQUAL DVMP_PRESENT)
  message(FATAL_ERROR
    "packages/dartvmp/src/CMakeLists.txt DVMP_SOURCES does not match the sources on disk.\n"
    "  listed : ${DVMP_LISTED}\n"
    "  on disk: ${DVMP_PRESENT}\n"
    "Add the missing file to DVMP_SOURCES (and to tool/hostlib/CMakeLists.txt, whose own "
    "assertion will tell you if you forget).")
endif()

# ---- generated module image ------------------------------------------------

# WORKAROUND: Flutter adds plugins through a symlink
# (windows/flutter/ephemeral/.plugin_symlinks/dartvmp), and CMake reports
# CMAKE_CURRENT_SOURCE_DIR as the *symlink* path rather than the real one. The
# generated header lives in the real tree, so resolve the symlink explicitly.
# Set -DDVMP_IMAGE_HEADER=... to override (useful for out-of-tree builds).
if(NOT DEFINED DVMP_IMAGE_HEADER)
  file(REAL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/.." DVMP_PLUGIN_ROOT)
  set(DVMP_IMAGE_HEADER "${DVMP_PLUGIN_ROOT}/generated/vmp_module.inc")
endif()

get_filename_component(DVMP_PLUGIN_ROOT "${DVMP_IMAGE_HEADER}" DIRECTORY)
get_filename_component(DVMP_PLUGIN_ROOT "${DVMP_PLUGIN_ROOT}" DIRECTORY)

if(NOT EXISTS "${DVMP_IMAGE_HEADER}")
  # A placeholder keeps configure-time tooling (IDE indexing, `flutter pub get`)
  # working before the first vmpc run. The build then fails with one clear
  # message instead of a wall of C errors.
  file(WRITE "${DVMP_IMAGE_HEADER}"
    "/* PLACEHOLDER - run: dart run tool/build.dart */\n"
    "#error \"vmp_module.inc is a placeholder; run `dart run tool/build.dart` first\"\n")
  message(WARNING
    "dartvmp: ${DVMP_IMAGE_HEADER} not found.\n"
    "        Run `dart run tool/build.dart` from the repository root before "
    "building the app.")
endif()

# ---- platform plumbing -----------------------------------------------------

set(DVMP_LINK_LIBS "")

if(ANDROID)
  find_library(log-lib log)
  list(APPEND DVMP_LINK_LIBS ${log-lib})
  add_compile_definitions(DVMP_PLATFORM_ANDROID=1)
  # Android's linker defaults to --gc-sections; keep it so unused builtins do
  # not bloat the .so.
  add_link_options(-Wl,--gc-sections)
elseif(WIN32)
  add_compile_definitions(DVMP_PLATFORM_WINDOWS=1 _CRT_SECURE_NO_WARNINGS=1)
else()
  add_compile_definitions(DVMP_PLATFORM_POSIX=1)
  list(APPEND DVMP_LINK_LIBS m)
endif()

if(DVMP_DIAGNOSTICS)
  add_compile_definitions(DVMP_DIAGNOSTICS=1)
endif()

if(DVMP_ANTIDEBUG)
  add_compile_definitions(DVMP_ANTIDEBUG=1)
endif()

if(DVMP_HARDEN_ALLOC)
  add_compile_definitions(DVMP_HARDEN_ALLOC=1)
endif()

if(DVMP_VMPACKER)
  add_compile_definitions(DVMP_VMPACKER=1)
endif()

if(DVMP_VMPACKER_NO_VECTORIZE OR DVMP_VMPACKER_NO_VECTORIZE_HOT)
  if(NOT DVMP_VMPACKER)
    message(WARNING
      "dartvmp: DVMP_VMPACKER_NO_VECTORIZE* is ON without DVMP_VMPACKER=ON.\n"
      "        De-vectorising is only useful to make functions translatable by a\n"
      "        C-layer virtualizer, so this build pays the cost for nothing.")
  endif()
  if(MSVC)
    # MSVC has no "vectorize off" switch that leaves the rest of /O2 alone: /O2 only
    # auto-vectorises with /arch:AVX2 or newer, and /Ob0 would disable inlining too.
    # So on MSVC the honest answer is "not expressible" - and MSVC is not a VMPacker
    # target anyway (the tool rewrites ELF; the desktop runtime is a PE image linked
    # into the runner).
    message(WARNING
      "dartvmp: DVMP_VMPACKER_NO_VECTORIZE* has no MSVC equivalent and is ignored.\n"
      "        VMPacker handles ELF only, so this only matters for the Android build.")
  else()
    # Per-source rather than target-wide: see the option definitions above for why the
    # interpreter keeps its vectorised loops unless -Hot is asked for explicitly.
    if(DVMP_VMPACKER_NO_VECTORIZE)
      set_source_files_properties(
        "${DVMP_ROOT}/dvmp_sha256.c" "${DVMP_ROOT}/dvmp_module.c"
        PROPERTIES COMPILE_OPTIONS "-fno-vectorize;-fno-slp-vectorize")
    endif()
    if(DVMP_VMPACKER_NO_VECTORIZE_HOT)
      set_source_files_properties(
        "${DVMP_ROOT}/dvmp_vm.c"
        PROPERTIES COMPILE_OPTIONS "-fno-vectorize;-fno-slp-vectorize")
    endif()
  endif()
endif()

# ---- library ---------------------------------------------------------------

# SHARED on Android/Apple, STATIC on desktop.
#
# The distinction is not cosmetic: the Android Gradle plugin collects
# `lib<name>.so` from the CMake build and packages it into the APK's lib/<abi>/,
# so a STATIC target produces *nothing* to ship and the app fails at runtime with
# "could not open libdartvmp.so". On Windows and Linux desktop, by contrast,
# Flutter links plugin code into the runner executable, and a shared library
# there would be a second copy of the interpreter with its own module state.
if(ANDROID OR IOS OR APPLE)
  add_library(${PROJECT_NAME} SHARED ${DVMP_SOURCES})
else()
  add_library(${PROJECT_NAME} STATIC ${DVMP_SOURCES})
endif()

target_include_directories(${PROJECT_NAME}
  PUBLIC  "${DVMP_ROOT}"
  PRIVATE "${DVMP_ROOT}")

# The generated image is only needed by dvmp_module.c, but forcing the include
# there keeps the image out of every other translation unit's preprocessor pass.
set_source_files_properties("${DVMP_ROOT}/dvmp_module.c"
  PROPERTIES COMPILE_DEFINITIONS "DVMP_MODULE_INCLUDE=\"${DVMP_IMAGE_HEADER}\"")

# The image must be a real dependency, not just a compile definition.
#
# Passing it only as a -D string means CMake has no idea dvmp_module.c reads the
# file, so regenerating the image does not recompile anything: `vmpc build` writes
# a new seed and build id, the stub and oracle change, and the library keeps the
# *previous* image. Nothing fails - the app still runs, the leak probes still
# pass, and the tests exercise bytecode the application does not use. It was
# observed in practice: the deployed test library reported build id 0xd8d9b378
# while the generated header said 0xec73e1a9.
#
# OBJECT_DEPENDS makes the object file depend on the header; CMAKE_CONFIGURE_DEPENDS
# additionally re-runs configure when it changes. Both are needed: the first
# recompiles, the second keeps the generated CMake caches consistent.
set_property(SOURCE "${DVMP_ROOT}/dvmp_module.c" APPEND
  PROPERTY OBJECT_DEPENDS "${DVMP_IMAGE_HEADER}")
set_property(DIRECTORY APPEND
  PROPERTY CMAKE_CONFIGURE_DEPENDS "${DVMP_IMAGE_HEADER}")

if(MSVC)
  target_compile_options(${PROJECT_NAME} PRIVATE /W3)
  if(DVMP_WARNINGS_AS_ERRORS)
    target_compile_options(${PROJECT_NAME} PRIVATE /WX)
  endif()
else()
  target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall -Wextra -Wshadow -Wconversion -Wno-sign-conversion)
  if(DVMP_WARNINGS_AS_ERRORS)
    target_compile_options(${PROJECT_NAME} PRIVATE -Werror)
  endif()
endif()

# Do not export anything except the documented ABI; the interpreter internals
# should not be reachable by name from a debugger or a hooking framework.
set_target_properties(${PROJECT_NAME} PROPERTIES
  C_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON
  POSITION_INDEPENDENT_CODE ON)

# Pin the export surface with a version script, on ELF only.
#
# `C_VISIBILITY_PRESET hidden` above keeps internals out of .dynsym as long as
# every internal stays `static` or undecorated. A C-layer virtualization target
# cannot: DVMP_VMPACKER_TARGET gives it default visibility so a build-time tool
# can find it, which without this script would also export it. The script makes
# "findable at build time" and "callable at runtime" two separate lists instead of
# one, and it turns "only the ABI is exported" from a consequence of a CMake
# preset into a link-time fact.
#
# Generated rather than static, because the export list has to describe the build
# it is linked into. The toolchain passes -Wl,--no-undefined-version, so naming a
# symbol that the current configuration compiles out is a link error - which is
# how this was found.
#
# Not applied on Windows: the desktop runtime is linked into the runner as a PE
# image, MSVC has no version scripts, and VMPacker does not handle PE at all. The
# equivalent guarantee there is the export table check in
# tool/capture_desktop_run.ps1.
if(NOT WIN32 AND NOT MSVC)
  if(DVMP_DIAGNOSTICS)
    set(DVMP_DIAGNOSTIC_EXPORTS
"
    /* Diagnostics; compiled in only when DVMP_DIAGNOSTICS=ON. */
    dartvmp_image_probe;
    dartvmp_mask_probe;
    dartvmp_code_probe;
    dartvmp_desc_probe;
    dartvmp_slot_probe;
    dartvmp_session_probe;
    dartvmp_plaintext_probe;
    dartvmp_body_residue;
    dartvmp_guard_reset;
    dartvmp_code_chunk_probe;
    dartvmp_code_residue;
    dartvmp_sha256_probe;
    dartvmp_instrumented_probe;
    dartvmp_integrity_probe;
    dartvmp_guard_probe;
    dartvmp_antidebug_force;")
  else()
    set(DVMP_DIAGNOSTIC_EXPORTS "")
  endif()
  set(DVMP_EXPORTS_MAP "${CMAKE_CURRENT_BINARY_DIR}/vmp_exports.map")
  configure_file("${DVMP_ROOT}/vmp_exports.map.in" "${DVMP_EXPORTS_MAP}" @ONLY)

  target_link_options(${PROJECT_NAME} PRIVATE
    "-Wl,--version-script=${DVMP_EXPORTS_MAP}")
  set_property(TARGET ${PROJECT_NAME} APPEND PROPERTY
    LINK_DEPENDS "${DVMP_EXPORTS_MAP}")
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC ${DVMP_LINK_LIBS})

# ---- keep an unstripped copy for the VMPacker hand-off ----------------------
#
# The hand-off selects functions **by symbol name**, and Android Gradle Plugin's
# release packaging strips the CMake output in place: `llvm-nm` on the library in
# `intermediates/cxx/.../obj/arm64-v8a/` reports "no symbols" after some builds and
# not others, depending on which task ran last. A pipeline that reads that file is a
# race, and the failure is quiet - VMPacker finds no matching symbol, virtualizes
# nothing, exits 0, and the APK ships unprotected. (tool/apply_vmpacker.ps1 does catch
# it, but only as "no symbol table", and by then the symbols are gone and the only fix
# is a rebuild.)
#
# So the build drops a copy at a path outside Gradle's build directory. It is a copy,
# not a second build: the shipped artifact still comes from the CMake output, and
# nothing reads this file except the hand-off script.
if(DVMP_VMPACKER AND NOT WIN32 AND NOT MSVC)
  if(NOT DEFINED DVMP_UNSTRIPPED_DIR)
    # packages/dartvmp/src -> repository root
    get_filename_component(DVMP_UNSTRIPPED_DIR
      "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
    set(DVMP_UNSTRIPPED_DIR "${DVMP_UNSTRIPPED_DIR}/build/unstripped")
  endif()
  # Per-ABI in the NAME, not just per-directory. Gradle configures this project once
  # per ABI (arm64-v8a and x86_64 - see abiFilters in android/build.gradle), and a
  # single shared filename means the last ABI to finish overwrites the other. The
  # first version of this did exactly that, and the hand-off was then pointed at the
  # *x86_64* library by a file whose name promised arm64; VMPacker refused it with
  # "ARM64 only, got: EM_X86_64". Put the ABI in the name and the mistake is not
  # expressible.
  if(CMAKE_ANDROID_ARCH_ABI)
    set(DVMP_UNSTRIPPED_NAME "libdartvmp.unstripped.${CMAKE_ANDROID_ARCH_ABI}.so")
  else()
    set(DVMP_UNSTRIPPED_NAME "libdartvmp.unstripped.so")
  endif()
  add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${DVMP_UNSTRIPPED_DIR}"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:${PROJECT_NAME}>"
            "${DVMP_UNSTRIPPED_DIR}/${DVMP_UNSTRIPPED_NAME}"
    COMMENT "dartvmp: kept an unstripped copy for the VMPacker hand-off (${DVMP_UNSTRIPPED_NAME})")
endif()
