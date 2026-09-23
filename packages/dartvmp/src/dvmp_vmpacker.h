/*
 * dvmp_vmpacker.h - the hand-off surface for C-layer virtualization.
 *
 * WHAT THIS IS FOR
 * ----------------
 * The DartVMP bytecode is protected; the *interpreter that executes it* is not.
 * `docs/skill-review-lang-vmp-guide.md` records that as the one open gap in this
 * project (L5, "executor protection"): an attacker who reads `dvmp_vm.c` and
 * `dvmp_module.c` as machine code can reimplement the private instruction set and
 * write a disassembler for the bytecode, which is the asset the whole design
 * exists to protect. Virtualizing the C layer means those functions ship as
 * bytecode for a second, unrelated VM instead of as AArch64.
 *
 * VMPacker (github.com/bivex/VMPacker) is the tool that does this. It selects
 * functions **by symbol name** and rewrites an ELF in place:
 *
 *     vmpacker -func "name1,name2" -v -o out.so in.so
 *
 * No source annotation is involved - that is how its own Android test drives it.
 * But it can only virtualize a function it can *find*, and that is what this file
 * is about.
 *
 * THE PROBLEM THIS SOLVES, MEASURED
 * ---------------------------------
 * In the built `libdartvmp.so`, every internal function is a **local** symbol:
 *
 *     $ llvm-nm --defined-only libdartvmp.so
 *     0000000000004120 t apply_keystream
 *     00000000000055b0 t code_store_build
 *     00000000000050c4 t dvmp_body_tag
 *     0000000000003d58 t dvmp_code_ensure
 *     0000000000004304 t module_open_locked
 *     000000000000425c t unpermute_code
 *
 * `t`, not `T`. That is not an accident of `static`: `CMakeLists.txt` sets
 * `C_VISIBILITY_PRESET hidden`, and on this toolchain a hidden-visibility
 * definition is localised in the output even when it is not `static` - measured on
 * a build with no version script at all, where `dvmp_module`, `dvmp_vm_run`,
 * `dvmp_host_call` and `dvmp_crc32` all still come out `t`. Only
 * default-visibility definitions (`dartvmp_init`, `dartvmp_call`) are `T`.
 *
 * The consequence is a silent failure mode, which is the one thing this project
 * does not accept: point VMPacker at the unmodified library and it finds no
 * matching symbol, virtualizes nothing, exits successfully, and ships an
 * unprotected library that everyone believes is protected. A tool that cannot
 * find its targets fails *quietly*, and the artifact looks exactly the same
 * either way.
 *
 * WHY THIS MACRO DOES NOT SET `visibility("default")`
 * ---------------------------------------------------
 * The obvious fix is to give each target default visibility, so it lands in
 * `.symtab` as a global symbol. That was tried, and it does not work here: on this
 * toolchain **a symbol is global if and only if it is exported.** Two measurements
 * settled it.
 *
 *   * With `visibility("default")` and no version script, the targets do come out
 *     `T` - and they also appear in `.dynsym`, i.e. an attacker can call
 *     `unpermute_code` by name through `dlsym`.
 *   * Adding the version script that pins `.dynsym` to the nine ABI entries
 *     (`vmp_exports.map`) puts them back to `t`, because `local: *` localises
 *     unlisted symbols in the whole output symbol table, not just in `.dynsym`.
 *
 * So "findable by a build-time tool but not callable at runtime" is not
 * expressible with visibility plus a version script on this toolchain. Given the
 * choice, this project keeps them **unexported**: an exported `unpermute_code` is
 * a working primitive for an attacker, while a local one is still present in
 * `.symtab` under its own name, which is what a name-based tool reads.
 *
 * `tool/apply_vmpacker.ps1` therefore does not assume the tool can see local
 * symbols - it *checks*, by proving after the run that each declared target
 * actually disappeared. If VMPacker turns out to filter on global binding, that
 * step fails with a message naming the cause instead of shipping an unprotected
 * library, and the alternative (export them for the build that feeds the tool,
 * then demote them again with `llvm-objcopy --localize-symbols`) is a documented
 * next step rather than a guess baked into the default build.
 *
 * WHAT `noinline` IS ACTUALLY FOR
 * -------------------------------
 * At `-O2` most of the secret-bearing helpers do not exist as functions at all:
 * `keystream_seed`, `mask_word`, `sm_next` and `permute_code` are all inlined into
 * their callers. Virtualizing `module_open_locked` while its key derivation sits
 * inline inside it hands the attacker the derivation in plain AArch64 with a
 * protected wrapper around it. A target that has been inlined away is not a
 * target, so each one carries `noinline` in a VMPacker build - and
 * `tool/apply_vmpacker.ps1` refuses to run if a declared name is absent from the
 * symbol table, which is what caught this in the first place.
 *
 * WHAT IS DELIBERATELY NOT A TARGET
 * ---------------------------------
 * `dvmp_vm_run` (the instruction loop) and `dvmp_code_ensure` (called once per
 * instruction) are excluded, and the exclusion is the interesting half of the
 * target list. A VMPacker-protected function runs on a second interpreter, so
 * virtualizing the inner loop would nest one VM inside another on the hottest path
 * in the system - every protected Dart call would pay for it, on every instruction,
 * forever. The residency work in `dvmp_module.c` is what makes the split possible:
 * the per-instruction set is now exactly those two functions, so everything else
 * is cold enough to virtualize for free.
 */
#ifndef DVMP_VMPACKER_H
#define DVMP_VMPACKER_H

/*
 * Applied to a function that a C-layer virtualizer should be able to find.
 *
 * Empty unless DVMP_VMPACKER is defined, so a normal build is unchanged. What it
 * buys is that the function *exists* as a function, under its own name, in
 * `.symtab`; see the notes above for why it deliberately does not also change
 * visibility.
 *
 * `no_stack_protector` is not optional, and finding out why cost a device crash.
 * Android's NDK compiles with `-fstack-protector-strong` by default, so every one of
 * these functions with a local array begins with
 *
 *     mrs  x19, TPIDR_EL0
 *     ldr  x8,  [x19, #0x28]        <- the stack canary
 *
 * VMPacker 1.3 translates both instructions and its VM does not reproduce the TLS
 * read, so `x19` reaches the `ldr` as zero and the function dies on the canary load.
 * Measured on a rooted Xiaomi 12 (Android 13, arm64-v8a): every virtualized function
 * that touches TPIDR_EL0 SIGSEGVs with
 *
 *     signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x0000000000000028
 *
 * and the fault address is *literally* the `#0x28` from the instruction above. The two
 * targets with no canary (keystream_seed, apply_keystream - neither has a local array)
 * ran correctly in the same build, which is what identified it. Per-target device
 * results are in the README.
 *
 * The attribute is on the *targets* rather than a `-fno-stack-protector` flag on the
 * translation unit, so the canary is dropped exactly where a VM executes the code
 * instead of everywhere in the file. The trade is deliberate and small: a canary
 * guards a function's own frame, and a virtualized function's frame is the VM's.
 */
#if defined(DVMP_VMPACKER)
#if defined(_MSC_VER)
/* MSVC is not a VMPacker target - the tool rewrites ELF, and the desktop runtime
 * is a PE image linked into the runner. Defining the macro to something that
 * cannot work would be worse than defining it to nothing. */
#define DVMP_VMPACKER_TARGET
#define DVMP_VMPACKER_LINKAGE static
#else
#define DVMP_VMPACKER_TARGET \
  __attribute__((noinline, used, no_stack_protector))
#define DVMP_VMPACKER_LINKAGE
#endif
#else
#define DVMP_VMPACKER_TARGET
#define DVMP_VMPACKER_LINKAGE static
#endif

/*
 * Applied to a helper that must only ever exist *inside* a VMPacker target.
 *
 * This is the mirror image of DVMP_VMPACKER_TARGET and it is just as load-bearing.
 * A static helper called from two virtualized targets is a candidate for an
 * out-of-line copy, and an out-of-line copy is a plain, readable, callable
 * implementation of exactly the thing the targets were virtualized to hide - the
 * attacker calls the helper and never touches the trampoline.
 *
 * Measured before this was used, on the MSVC build of `dvmp_module.c`:
 *
 *     $ llvm-nm dvmp_module.obj | grep -E 'op_tables|permute'
 *     t op_tables          <- the permutation construction, as its own function
 *     t permute_code
 *     t unpermute_code
 *
 * `inline` (not just `always_inline`) is what guarantees no out-of-line copy is
 * emitted for a static function, on both compilers. The check that this holds in a
 * real build is in tool/apply_vmpacker.ps1, which refuses to pack if a declared
 * *helper* is still findable by name.
 */
#if defined(_MSC_VER)
#define DVMP_ALWAYS_INLINE static __forceinline
#else
#define DVMP_ALWAYS_INLINE static inline __attribute__((always_inline))
#endif

/*
 * Applied to a VMPacker target that contains a `memcpy`/`memset`: it stops the
 * compiler *inlining* those calls, so they stay real calls (`bl memset@plt`) that
 * VMPacker can translate as branches.
 *
 * This is not premature pessimisation, it is the difference between translatable and
 * not. Clang expands a small `memset` inline as `movi v0.16b, #0xff` plus eight
 * `stp q0, q0, [sp]` - nine SIMD instructions. VMPacker 1.3 has no SIMD translation,
 * so `dvmp_mask_keystream` came back as "Translated: 64/70, translation aborted", and
 * neither -fno-vectorize nor -fno-slp-vectorize touched it, because that expansion is
 * the builtin/inline-memset path and not the vectoriser. Measured, not assumed.
 *
 * Only in a VMPacker build. A normal build keeps whatever code generation the
 * compiler prefers.
 */
#if defined(DVMP_VMPACKER) && !defined(_MSC_VER)
#define DVMP_NO_BUILTIN __attribute__((no_builtin("memset", "memcpy")))
#else
#define DVMP_NO_BUILTIN
#endif

#endif /* DVMP_VMPACKER_H */
