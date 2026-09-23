# Licensing

FDartVMP is **dual-licensed**. You may use it under the GNU Affero General Public
License, version 3 or later, or under a separate paid commercial license. You do not
need the commercial license unless the AGPL's obligations do not work for you.

Copyright (C) 2026 haothtrteen.

| | License | Applies to |
|---|---|---|
| Open source | AGPL-3.0-or-later | the default, for everyone who complies with it |
| Commercial | negotiated, per agreement | closed-source and other AGPL-incompatible uses |

The full text of the AGPL is in [`LICENSE`](LICENSE). Nothing in this document
modifies, replaces, or overrides that text; where the two disagree, `LICENSE`
governs.

---

## 1. The default: AGPL-3.0-or-later

Unless you have signed a commercial agreement with the maintainer, FDartVMP is
licensed under the GNU Affero General Public License, version 3, or (at your
option) any later version.

In practical terms, the AGPL gives you the right to run, study, modify, and
redistribute this software, on the condition that:

- if you distribute it, or a work based on it, you pass on the same license and
  make the corresponding source available to your recipients (AGPL sections 4-6);
- if you let users interact with a modified version **over a network**, you must
  offer those users the corresponding source of the version they are interacting
  with (AGPL section 13);
- you keep the copyright notices, the license notices, and the absence-of-warranty
  notice intact (AGPL section 4).

There is no warranty (AGPL sections 15-16). This is a protection component that
ships inside other people's binaries; test it against your own application before
you rely on it.

## 2. Why AGPL and not MIT or Apache-2.0

A permissive license would be the conventional choice for a library. It is
deliberately not the choice here, and the reason is what this component is for.

FDartVMP is an obfuscation and virtual-machine-protection system. Its entire
value proposition is that the logic you put into it is not readable in the binary
you ship. A permissive license would allow a company to take this implementation,
fold it into a proprietary closed-source product or a hosted service, ship it, and
give nothing back. It is the kind of component whose improvements are only ever
written by the people who deploy it in production, which is exactly the situation
copyleft exists to address.

The AGPL closes the specific loophole that matters for a back-end component. Under
plain GPL, a modified version can be run as a network service without ever
publishing its source. AGPL section 13 removes that: if users interact with your
modified version remotely, they are entitled to the corresponding source of the
version actually running.

That obligation is **deliberate, and it is the reason the commercial license
exists**. The intended outcome is:

- if you can live with AGPL's source-disclosure obligations, you use FDartVMP for
  free, and any improvements you make to the protection layers come back to the
  project;
- if you cannot live with them, you buy a commercial license, and the project is
  funded by the people who need the exception.

There is no third path in which you get the exception for free.

## 3. When you need the commercial license

You need a commercial license if you want to do anything that the AGPL does not
permit. The two common cases:

**Shipping FDartVMP inside a closed-source product.** This includes the ordinary
mobile application: a Flutter app whose Dart code, native runtime, or protected
module you do not publish. FDartVMP is statically linked into the desktop runner
and packaged as `libdartvmp.so` into the Android APK, so it is part of the work you
convey, and AGPL sections 5 and 6 apply to the work as a whole. Distributing that
app without offering the corresponding source of the combined work is a use the
AGPL does not grant.

**Any deployment where AGPL section 13 is unacceptable.** If you modify the
runtime or the compiler and expose that modified version to users over a network,
section 13 requires you to offer those users the corresponding source. If your
business cannot do that, you need the commercial license.

A commercial license is a negotiated agreement, not a price list. Scope, term,
support, and whether source-disclosure can be limited are all part of the
negotiation.

**Contact:** haothtrteen — 2557976190@qq.com

## 4. Contributions and the contributor agreement

Because the project is dual-licensed, the maintainer has to hold enough rights in
every part of the codebase to offer it under **both** the AGPL and a commercial
license. That requirement is not a formality: a single outside contribution
accepted without it would make it legally impossible to sell commercial licenses
for any version containing that contribution, because the contributor would still
hold copyright in their part and would not have granted the right to relicense it.

So a contribution is only accepted together with a signed contributor license
agreement, **or** an explicit statement in the pull request that the contributor
assigns or grants the maintainer the rights needed to license the contribution
under both the AGPL-3.0-or-later and the commercial license (including the right to
sublicense and to relicense under other terms).

**Pull requests that do not carry this cannot be merged**, however good the change
is. If you are unsure what is required for your contribution, ask before you spend
time on it.

The full process, including the build and test requirements that apply to any
change, is in [`CONTRIBUTING.md`](CONTRIBUTING.md).

## 5. Third-party components

FDartVMP is not self-contained. The table below records what the repository
actually depends on, and under what license, so that compliance can be checked
rather than assumed.

### 5.1 Dart and Flutter packages

Read from the pubspec manifests in this repository, and each license verified against
the resolved package's own `LICENSE` file in the local pub cache
(`%LOCALAPPDATA%\Pub\Cache\hosted\pub.dev`):

| Component | Declared in | Resolved | License | Verification |
|---|---|---|---|---|
| `crypto` (^3.0.0) | `tool/vmpc/pubspec.yaml` | 3.0.7 | BSD-3-Clause, "Copyright 2015, the Dart project authors" | pub cache `crypto-3.0.7/LICENSE`: source and binary-form clauses, no-endorsement clause, no MIT grant |
| `args` (^2.5.0) | `tool/vmpc/pubspec.yaml` | 2.7.0 | BSD-3-Clause, "Copyright 2013, the Dart project authors" | pub cache `args-2.7.0/LICENSE`, same shape |
| `test` (^1.25.0) | `tool/vmpc/pubspec.yaml` (dev only) | 1.30.0 | BSD-3-Clause, "Copyright 2014, the Dart project authors" | pub cache `test-1.30.0/LICENSE`, same shape. Not shipped. |
| `lints` (^5.0.0) | `tool/vmpc/pubspec.yaml` (dev only) | 5.1.1 | BSD-3-Clause, "Copyright 2021, the Dart project authors" | pub cache `lints-6.1.0/LICENSE` (6.x resolved elsewhere in the cache), same shape. Not shipped. |
| `ffi` (^2.1.0) | `packages/dartvmp/pubspec.yaml`, `app/pubspec.yaml` | 2.1.4 | BSD-3-Clause, "Copyright 2019, the Dart project authors" | pub cache `ffi-2.1.4/LICENSE`, same shape |
| `flutter_lints` (^6.0.0) | `packages/dartvmp/pubspec.yaml`, `app/pubspec.yaml` (dev only) | 6.0.0 | BSD-3-Clause, "Copyright 2013 The Flutter Authors" | pub cache `flutter_lints-6.0.0/LICENSE`, same shape. Not shipped. |
| `cupertino_icons` (^1.0.8) | `app/pubspec.yaml` | 1.0.9 | MIT, "Copyright (c) 2016 Vladimir Kharlampidi" | pub cache `cupertino_icons-1.0.9/LICENSE`, MIT grant text, no BSD clauses. Demo application only. |
| `flutter`, `flutter_test` | `packages/dartvmp/pubspec.yaml`, `app/pubspec.yaml` | Flutter SDK | BSD-3-Clause | Flutter itself, from the SDK rather than pub.dev; the SDK's own `LICENSE` file is the authority |
| `dartvmp` | `app/pubspec.yaml` | in-tree | this project's license (AGPL-3.0-or-later or commercial) | declared as `path: ../packages/dartvmp`, so the demo consumes the in-tree package |

There are no other dependencies in any of the three manifests. Transitive
dependencies of the packages above (`meta`, `collection`, `typed_data`, `path`,
`async`, and so on) are resolved by pub and are likewise BSD-3-Clause Dart-team
packages; they are not declared here and are not shipped by this project.

`crypto` is the only third-party Dart package in the compiler's path: `vmpc` uses it
for the SHA-256 that keys the image mask and the entry-name keystream. The native
runtime includes its own SHA-256 in `packages/dartvmp/src/dvmp_sha256.c` rather than
linking one, and the `dartvmp` package's only non-SDK dependency is `ffi`. The demo
application adds `cupertino_icons`.

None of these packages are vendored into this repository. They are resolved from
pub.dev or the Flutter SDK at build time, and **their own licenses govern them
separately**. Your distribution has to comply with each of them in addition to
FDartVMP's license; the Flutter tooling generates the assembled notices for the
application under `NOTICES` when you build the app, which is the practical
mechanism for that. (That file is a zlib stream inside the built bundle —
`app/build/flutter_assets/NOTICES.Z`, and the same name under
`flutter_assets/` in the release APK and the Windows runner — and it is not
readable as plain text without decompressing it, which is why the table above was
verified against the individual package `LICENSE` files in the pub cache instead.)

### 5.2 VMPacker — a separate tool, not vendored here

[VMPacker](https://github.com/bivex/VMPacker) (github.com/bivex/VMPacker) is an
ARM64 ELF virtualizer used for the optional C-layer hardening step. It is **not
part of this repository and is not distributed with it**:

- it is built from source by `tool/build_vmpacker.ps1` (the VM interpreter stub
  with the Android NDK's clang/ld.lld/objcopy, then the Go packer), or pointed at
  with the `VMPACKER` / `VMPACKER_SRC` environment variables;
- it is applied to an already-built `libdartvmp.so` by `tool/apply_vmpacker.ps1`,
  which refuses to run if the tool is absent unless `-AllowMissing` is passed;
- `build/` is listed in this repository's `.gitignore`, so neither the VMPacker
  source nor its output is tracked in git. A copy on a working machine is a
  downloaded release, not a vendored dependency.

VMPacker is itself licensed under the **GNU Affero General Public License,
version 3** (the license file in the upstream 1.3 release is an unmodified copy of
the standard AGPL-3.0 text). Its license governs it. If you use it, you must
comply with it separately from FDartVMP's license — including its source-offer
obligations for the tool itself — and the presence of FDartVMP's own AGPL grant
neither adds to nor subtracts from that.

### 5.3 Nothing else

The native runtime under `packages/dartvmp/src/` is this project's own C, and
includes its own SHA-256 implementation rather than linking a third-party crypto
library. There is no vendored third-party source in this repository as it stands.

## 6. This is obfuscation, not a security boundary

The AGPL gives you the source of this project, and that is not in tension with what
the project does, because the project has never claimed confidentiality from
someone who reads the source.

Stated plainly, and consistently with the README:

- FDartVMP **raises the cost** of recovering protected logic from a shipped binary.
  It does not make that logic unrecoverable.
- It is **not a cryptographic boundary.** The container's stream cipher is keyed by
  a seed stored in the container's own header, and the mask derivation, the opcode
  permutation's construction, and the interpreter's instruction semantics all ship
  inside `libdartvmp.so`. They have to: the component must work offline, so the
  binary carries its own key material by necessity. Anyone willing to read the
  runtime can re-derive the keystream and reconstruct the instruction set.
- The README documents this at length, including that an attacker who reads
  `unpermute_code` (roughly 100 instructions) or who recognises the SplitMix64
  stream and the Fisher-Yates shuffle reconstructs the opcode mapping directly, and
  that the C-layer virtualization works for only two functions.

The license is not a confidentiality mechanism, and it is not presented as one. If
logic must be genuinely unrecoverable, obfuscation is the wrong tool: keep that
logic on a server and let the shipped binary call it over the network.
