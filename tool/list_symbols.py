#!/usr/bin/env python3
"""Lists the dynamic symbols a shared object exports.

Used to check that libdartvmp.so exposes the documented `dartvmp_*` ABI and
nothing else of interest - the interpreter's internals are all `static` or
hidden-visibility, so an attacker cannot call `dvmp_vm_run` by name.

`llvm-nm`/`nm` are not always on PATH, so this parses the ELF dynamic symbol
table directly. Usage: python tool/list_symbols.py <path.so>
"""
import struct
import sys
from pathlib import Path


def symbols(path: Path):
    data = path.read_bytes()
    if data[:4] != b"\x7fELF":
        raise SystemExit(f"{path}: not an ELF file")
    is64 = data[4] == 2
    little = data[5] == 1
    if not (is64 and little):
        raise SystemExit(f"{path}: only 64-bit little-endian is supported")
    end = "<"

    e_shoff = struct.unpack_from(end + "Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from(end + "H", data, 0x3A)[0]
    e_shnum = struct.unpack_from(end + "H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from(end + "H", data, 0x3E)[0]

    def section(i):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, offset, size, link, info, align, entsize = (
            struct.unpack_from(end + "IIQQQQIIQQ", data, off)
        )
        return dict(
            name=name, type=typ, addr=addr, offset=offset, size=size,
            link=link, entsize=entsize,
        )

    sections = [section(i) for i in range(e_shnum)]

    # Section header string table, to identify .dynsym by name.
    shstr = sections[e_shstrndx]
    shstr_data = data[shstr["offset"]: shstr["offset"] + shstr["size"]]

    def sh_name(off):
        end_i = shstr_data.find(b"\0", off)
        return shstr_data[off:end_i].decode("ascii", "replace")

    out = []
    for s in sections:
        if sh_name(s["name"]) != ".dynsym":
            continue
        strtab = sections[s["link"]]
        strs = data[strtab["offset"]: strtab["offset"] + strtab["size"]]
        assert s["entsize"] == 24, "unexpected ELF64 symbol size"
        for i in range(s["size"] // s["entsize"]):
            off = s["offset"] + i * s["entsize"]
            st_name, st_info, st_other, st_shndx, st_value, st_size = (
                struct.unpack_from(end + "IBBHQQ", data, off)
            )
            if st_name == 0:
                continue
            end_i = strs.find(b"\0", st_name)
            name = strs[st_name:end_i].decode("ascii", "replace")
            out.append((name, st_shndx, st_size))
    return out


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    path = Path(sys.argv[1])
    syms = symbols(path)
    exported = [(n, sz) for n, shndx, sz in syms if shndx != 0 and n]
    exported.sort()

    print(f"{path.name}: {len(exported)} exported dynamic symbols")
    abi = [n for n, _ in exported if n.startswith("dartvmp_")]
    other = [n for n, _ in exported if not n.startswith("dartvmp_")]
    print(f"  dartvmp_* ABI ({len(abi)}):")
    for n in abi:
        print(f"    {n}")
    # C++/compiler runtime symbols are expected; interpreter internals are not.
    suspicious = [
        n for n in other
        if not n.startswith("_") and "GLIBC" not in n and "CXXABI" not in n
    ]
    if suspicious:
        print(f"  other non-underscore exports ({len(suspicious)}):")
        for n in suspicious:
            print(f"    {n}")
    internals = [n for n, _ in exported if n.startswith("dvmp_")]
    print(f"  interpreter internals exported: {len(internals)} "
          f"(expected 0)")
    return 1 if internals else 0


if __name__ == "__main__":
    sys.exit(main())
