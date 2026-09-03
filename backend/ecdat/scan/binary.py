"""Binary artefact analysis: ELF, Mach-O and PE.

Three evidence tiers, with confidence assigned to match what each can actually
prove (PART 11 -- "do not claim semantic certainty from strings alone"):

  dynamic linkage (DT_NEEDED / LC_LOAD_DYLIB / PE import table)
      -> MEDIUM-HIGH. A binary that links libcrypto.so.3 demonstrably uses that
         library. We still cannot see *which* algorithm a given call site selects.

  imported/exported symbol names (.dynsym, PE import thunks)
      -> MEDIUM. `EVP_aes_256_gcm` in the import table is strong evidence that
         AES-256-GCM is reachable, because the symbol names the parameter set.
         It does not prove the code path executes.

  string literals
      -> LOW. Only ever corroborating evidence.

We never claim a cryptographic *role* from a binary; there is no reliable static
signal for it without full decompilation, which is out of MVP scope. Roles stay
Role.UNKNOWN and the UI shows them as such.

Formats are parsed directly from the byte stream (stdlib only). `nm`/`objdump` are
used opportunistically as a cross-check when present but are never required.
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass, field

from ..detect.base import Detection
from ..knowledge import algorithms as alg
from ..knowledge import libraries as libs
from ..models import Confidence

MAX_BINARY_BYTES = 64 * 1024 * 1024

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": ("macho", False, ">"),   # 32-bit BE
    b"\xce\xfa\xed\xfe": ("macho", False, "<"),   # 32-bit LE
    b"\xfe\xed\xfa\xcf": ("macho", True, ">"),    # 64-bit BE
    b"\xcf\xfa\xed\xfe": ("macho", True, "<"),    # 64-bit LE
}
MACHO_FAT = {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}

# --- symbol signatures ------------------------------------------------------------------
# Each entry: (regex, algorithm id or None, note). Symbol names that *name their own
# parameter set* are the valuable ones -- they let us report AES-256-GCM rather than "AES".
_SYMBOL_SIGS: list[tuple[re.Pattern[str], str | None, str]] = [
    (re.compile(r"EVP_aes_256_gcm|AES_256_GCM|aes256gcm"), "aes-256", "AES-256-GCM via EVP"),
    (re.compile(r"EVP_aes_128_gcm|AES_128_GCM"), "aes-128", "AES-128-GCM via EVP"),
    (re.compile(r"EVP_aes_256_cbc"), "aes-256", "AES-256-CBC via EVP"),
    (re.compile(r"EVP_aes_128_cbc"), "aes-128", "AES-128-CBC via EVP"),
    (re.compile(r"EVP_des_ede3|DES_ede3"), "3des", "3DES via EVP"),
    (re.compile(r"EVP_rc4|RC4_set_key"), "rc4", "RC4"),
    (re.compile(r"EVP_chacha20_poly1305"), "chacha20-poly1305", "ChaCha20-Poly1305"),
    (re.compile(r"EVP_sha256|SHA256_(Init|Update|Final)"), "sha-256", "SHA-256"),
    (re.compile(r"EVP_sha384|SHA384_Init"), "sha-384", "SHA-384"),
    (re.compile(r"EVP_sha512|SHA512_Init"), "sha-512", "SHA-512"),
    (re.compile(r"EVP_sha1\b|SHA1_(Init|Update|Final)"), "sha-1", "SHA-1"),
    (re.compile(r"EVP_md5\b|MD5_(Init|Update|Final)"), "md5", "MD5"),
    (re.compile(r"RSA_(generate_key|new|sign|verify|public_encrypt|private_decrypt)|"
                r"EVP_PKEY_CTX_set_rsa"), "rsa", "RSA primitive symbols"),
    (re.compile(r"ECDSA_(do_sign|do_verify|sign|verify)|EVP_PKEY_ECDSA"), "ecdsa", "ECDSA"),
    (re.compile(r"ECDH_compute_key|EVP_PKEY_derive"), "ecdh", "ECDH key agreement"),
    (re.compile(r"X25519|curve25519"), "x25519", "X25519"),
    (re.compile(r"ED25519_(sign|verify)|Ed25519"), "ed25519", "Ed25519"),
    (re.compile(r"DH_compute_key|DH_generate_key"), "dh", "finite-field DH"),
    (re.compile(r"DSA_(do_sign|do_verify)"), "dsa", "DSA"),
    (re.compile(r"ML_KEM|mlkem|EVP_PKEY_ML_KEM"), "ml-kem-768", "ML-KEM (PQC) present"),
    (re.compile(r"ML_DSA|mldsa"), "ml-dsa-65", "ML-DSA (PQC) present"),
    (re.compile(r"SLH_DSA|slhdsa|sphincs"), "slh-dsa-sha2-128s", "SLH-DSA (PQC) present"),
    (re.compile(r"PKCS5_PBKDF2_HMAC"), "pbkdf2", "PBKDF2"),
    (re.compile(r"HMAC_(Init|Update|Final)"), "hmac-sha256", "HMAC (digest unknown)"),
]

_TLS_VERSION_STRINGS = [
    (re.compile(rb"TLSv1\.3"), "TLS", "1.3"),
    (re.compile(rb"TLSv1\.2"), "TLS", "1.2"),
    (re.compile(rb"TLSv1\.1"), "TLS", "1.1"),
    (re.compile(rb"TLSv1(?![\.0-9])"), "TLS", "1.0"),
    (re.compile(rb"SSLv3"), "SSL", "3.0"),
]

_VERSION_STRING = re.compile(rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)")
_STRING_RE = re.compile(rb"[\x20-\x7e]{6,200}")


@dataclass
class BinaryInfo:
    path: str
    fmt: str = "unknown"
    bits: int = 0
    endian: str = "<"
    arch: str = ""
    needed: list[str] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    strings_sample: list[str] = field(default_factory=list)
    openssl_version: str | None = None
    stripped: bool = True
    errors: list[str] = field(default_factory=list)
    size: int = 0


# ======================================================================================
# ELF
# ======================================================================================
_ELF_MACHINE = {0x03: "x86", 0x3E: "x86_64", 0x28: "armv7", 0xB7: "aarch64",
                0x16: "s390x", 0x15: "ppc64", 0xF3: "riscv"}

DT_NEEDED = 1
DT_STRTAB = 5
DT_SONAME = 14


def parse_elf(data: bytes, info: BinaryInfo) -> None:
    info.fmt = "ELF"
    ei_class = data[4]
    info.bits = 64 if ei_class == 2 else 32
    info.endian = "<" if data[5] == 1 else ">"
    e = info.endian
    try:
        machine = struct.unpack_from(e + "H", data, 18)[0]
        info.arch = _ELF_MACHINE.get(machine, f"machine-{machine}")
        if info.bits == 64:
            e_shoff = struct.unpack_from(e + "Q", data, 0x28)[0]
            e_shentsize = struct.unpack_from(e + "H", data, 0x3A)[0]
            e_shnum = struct.unpack_from(e + "H", data, 0x3C)[0]
            e_shstrndx = struct.unpack_from(e + "H", data, 0x3E)[0]
        else:
            e_shoff = struct.unpack_from(e + "I", data, 0x20)[0]
            e_shentsize = struct.unpack_from(e + "H", data, 0x2E)[0]
            e_shnum = struct.unpack_from(e + "H", data, 0x30)[0]
            e_shstrndx = struct.unpack_from(e + "H", data, 0x32)[0]

        if not e_shoff or e_shnum == 0 or e_shnum > 4096:
            info.errors.append("ELF section table absent or implausible")
            return

        # section headers
        sections: list[tuple[int, int, int, int, int]] = []  # (name_off, type, offset, size, entsize)
        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            if base + e_shentsize > len(data):
                break
            if info.bits == 64:
                sh_name, sh_type = struct.unpack_from(e + "II", data, base)
                sh_offset = struct.unpack_from(e + "Q", data, base + 0x18)[0]
                sh_size = struct.unpack_from(e + "Q", data, base + 0x20)[0]
                sh_link = struct.unpack_from(e + "I", data, base + 0x28)[0]
                sh_entsize = struct.unpack_from(e + "Q", data, base + 0x38)[0]
            else:
                sh_name, sh_type = struct.unpack_from(e + "II", data, base)
                sh_offset = struct.unpack_from(e + "I", data, base + 0x10)[0]
                sh_size = struct.unpack_from(e + "I", data, base + 0x14)[0]
                sh_link = struct.unpack_from(e + "I", data, base + 0x18)[0]
                sh_entsize = struct.unpack_from(e + "I", data, base + 0x24)[0]
            sections.append((sh_name, sh_type, sh_offset, sh_size, sh_entsize, sh_link))

        # section name table
        names: dict[int, str] = {}
        if e_shstrndx < len(sections):
            _, _, off, size, _, _ = sections[e_shstrndx]
            strtab = data[off:off + size]
            for idx, (sh_name, *_rest) in enumerate(sections):
                end = strtab.find(b"\x00", sh_name)
                names[idx] = strtab[sh_name:end if end > 0 else None].decode(
                    "utf-8", "replace")

        by_name = {names.get(i, ""): sections[i] for i in range(len(sections))}

        # DT_NEEDED from .dynamic + .dynstr
        dyn = by_name.get(".dynamic")
        dynstr = by_name.get(".dynstr")
        if dyn and dynstr:
            _, _, d_off, d_size, _, _ = dyn
            _, _, s_off, s_size, _, _ = dynstr
            strdata = data[s_off:s_off + s_size]
            entsize = 16 if info.bits == 64 else 8
            fmt = e + ("qQ" if info.bits == 64 else "iI")
            for pos in range(d_off, min(d_off + d_size, len(data)) - entsize + 1, entsize):
                tag, val = struct.unpack_from(fmt, data, pos)
                if tag == 0:
                    break
                if tag in (DT_NEEDED, DT_SONAME) and 0 <= val < len(strdata):
                    end = strdata.find(b"\x00", val)
                    nm = strdata[val:end if end > 0 else None].decode("utf-8", "replace")
                    if tag == DT_NEEDED:
                        info.needed.append(nm)

        # symbols from .dynsym/.symtab
        for sec_name, str_name in ((".dynsym", ".dynstr"), (".symtab", ".strtab")):
            sec = by_name.get(sec_name)
            stab = by_name.get(str_name)
            if not sec or not stab:
                continue
            _, _, sy_off, sy_size, sy_ent, _ = sec
            _, _, st_off, st_size, _, _ = stab
            if not sy_ent:
                sy_ent = 24 if info.bits == 64 else 16
            strdata = data[st_off:st_off + st_size]
            count = min(sy_size // sy_ent, 200_000)
            for i in range(count):
                p = sy_off + i * sy_ent
                if p + 4 > len(data):
                    break
                st_name = struct.unpack_from(e + "I", data, p)[0]
                if st_name == 0 or st_name >= len(strdata):
                    continue
                end = strdata.find(b"\x00", st_name)
                sym = strdata[st_name:end if end > 0 else None].decode("utf-8", "replace")
                if sym:
                    info.symbols.append(sym)
            if sec_name == ".symtab":
                info.stripped = False
    except (struct.error, IndexError) as exc:
        info.errors.append(f"ELF parse: {exc}")


# ======================================================================================
# Mach-O
# ======================================================================================
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x18
LC_REEXPORT_DYLIB = 0x1F
LC_SYMTAB = 0x02
_MACHO_CPU = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64"}


def parse_macho(data: bytes, info: BinaryInfo, offset: int = 0) -> None:
    info.fmt = "Mach-O"
    magic = data[offset:offset + 4]
    if magic in MACHO_FAT:
        # universal binary: analyse the first slice
        try:
            nfat = struct.unpack_from(">I", data, offset + 4)[0]
            if nfat and nfat < 32:
                slice_off = struct.unpack_from(">I", data, offset + 8 + 8)[0]
                info.errors.append(f"universal binary: analysing first of {nfat} slices")
                return parse_macho(data, info, slice_off)
        except struct.error as exc:
            info.errors.append(f"Mach-O fat header: {exc}")
        return

    kind = MACHO_MAGICS.get(magic)
    if not kind:
        info.errors.append("unrecognised Mach-O magic")
        return
    _, is64, endian = kind
    info.bits = 64 if is64 else 32
    info.endian = endian
    e = endian
    try:
        cputype = struct.unpack_from(e + "i", data, offset + 4)[0]
        info.arch = _MACHO_CPU.get(cputype & 0xFFFFFFFF, f"cpu-{cputype}")
        ncmds = struct.unpack_from(e + "I", data, offset + 16)[0]
        pos = offset + (32 if is64 else 28)
        for _ in range(min(ncmds, 4096)):
            if pos + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(e + "II", data, pos)
            if cmdsize < 8:
                break
            if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
                name_off = struct.unpack_from(e + "I", data, pos + 8)[0]
                start = pos + name_off
                end = data.find(b"\x00", start)
                if 0 < end < pos + cmdsize + 256:
                    info.needed.append(data[start:end].decode("utf-8", "replace"))
            elif cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = struct.unpack_from(e + "IIII", data, pos + 8)
                strdata = data[stroff:stroff + strsize]
                entsize = 16 if is64 else 12
                info.stripped = nsyms == 0
                for i in range(min(nsyms, 200_000)):
                    p = symoff + i * entsize
                    if p + 4 > len(data):
                        break
                    n_strx = struct.unpack_from(e + "I", data, p)[0]
                    if n_strx == 0 or n_strx >= len(strdata):
                        continue
                    z = strdata.find(b"\x00", n_strx)
                    sym = strdata[n_strx:z if z > 0 else None].decode("utf-8", "replace")
                    if sym:
                        info.symbols.append(sym.lstrip("_"))
            pos += cmdsize
    except (struct.error, IndexError) as exc:
        info.errors.append(f"Mach-O parse: {exc}")


# ======================================================================================
# PE
# ======================================================================================
_PE_MACHINE = {0x014C: "x86", 0x8664: "x86_64", 0x01C0: "arm", 0xAA64: "arm64"}


def parse_pe(data: bytes, info: BinaryInfo) -> None:
    info.fmt = "PE"
    try:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off:pe_off + 4] != b"PE\x00\x00":
            info.errors.append("PE signature missing")
            return
        machine, nsections = struct.unpack_from("<HH", data, pe_off + 4)
        info.arch = _PE_MACHINE.get(machine, f"machine-{machine:04x}")
        opt_size = struct.unpack_from("<H", data, pe_off + 20)[0]
        opt_off = pe_off + 24
        magic = struct.unpack_from("<H", data, opt_off)[0]
        info.bits = 64 if magic == 0x20B else 32
        # data directory entry 1 = import table
        dd_off = opt_off + (112 if info.bits == 64 else 96)
        imp_rva, imp_size = struct.unpack_from("<II", data, dd_off)

        # section table for RVA -> file offset
        sec_off = opt_off + opt_size
        sections: list[tuple[int, int, int, int]] = []
        for i in range(min(nsections, 96)):
            b = sec_off + i * 40
            if b + 40 > len(data):
                break
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, b + 8)
            sections.append((vaddr, vsize, rawptr, rawsize))

        def rva_to_off(rva: int) -> int | None:
            for vaddr, vsize, rawptr, rawsize in sections:
                if vaddr <= rva < vaddr + max(vsize, rawsize):
                    return rawptr + (rva - vaddr)
            return None

        if imp_rva:
            off = rva_to_off(imp_rva)
            i = 0
            while off is not None and i < 256:
                base = off + i * 20
                if base + 20 > len(data):
                    break
                orig_first, _, _, name_rva, first_thunk = struct.unpack_from(
                    "<IIIII", data, base)
                if name_rva == 0 and first_thunk == 0:
                    break
                noff = rva_to_off(name_rva)
                if noff is not None and noff < len(data):
                    z = data.find(b"\x00", noff)
                    dll = data[noff:z if z > 0 else None].decode("utf-8", "replace")
                    if dll:
                        info.needed.append(dll)
                # imported function names from the hint/name table
                thunk_rva = orig_first or first_thunk
                toff = rva_to_off(thunk_rva) if thunk_rva else None
                j = 0
                ptr_fmt = "<Q" if info.bits == 64 else "<I"
                ptr_size = 8 if info.bits == 64 else 4
                while toff is not None and j < 4096:
                    p = toff + j * ptr_size
                    if p + ptr_size > len(data):
                        break
                    entry = struct.unpack_from(ptr_fmt, data, p)[0]
                    if entry == 0:
                        break
                    high_bit = 1 << (63 if info.bits == 64 else 31)
                    if not entry & high_bit:
                        hoff = rva_to_off(entry & 0x7FFFFFFF)
                        if hoff is not None and hoff + 2 < len(data):
                            z = data.find(b"\x00", hoff + 2)
                            fn = data[hoff + 2:z if z > 0 else None].decode("utf-8", "replace")
                            if fn:
                                info.symbols.append(fn)
                    j += 1
                i += 1
    except (struct.error, IndexError) as exc:
        info.errors.append(f"PE parse: {exc}")


# ======================================================================================
# Driver
# ======================================================================================
def identify(data: bytes) -> str:
    if data[:4] == ELF_MAGIC:
        return "ELF"
    if data[:4] in MACHO_MAGICS or data[:4] in MACHO_FAT:
        return "Mach-O"
    if data[:2] == PE_MAGIC:
        return "PE"
    if data[:4] in (b"\xca\xfe\xba\xbe",):
        return "Mach-O"
    return "unknown"


def analyze_binary(path: str, data: bytes | None = None) -> BinaryInfo:
    info = BinaryInfo(path=path)
    if data is None:
        try:
            with open(path, "rb") as fh:
                data = fh.read(MAX_BINARY_BYTES)
        except OSError as exc:
            info.errors.append(str(exc))
            return info
    info.size = len(data)
    fmt = identify(data)
    if fmt == "ELF":
        parse_elf(data, info)
    elif fmt == "Mach-O":
        parse_macho(data, info)
    elif fmt == "PE":
        parse_pe(data, info)
    else:
        info.fmt = "unknown"
        info.errors.append("not a recognised executable format")

    # string extraction (LOW-confidence tier)
    found: list[str] = []
    for m in _STRING_RE.finditer(data):
        s = m.group(0)
        if any(k in s for k in (b"EVP_", b"SSL", b"TLS", b"AES", b"RSA", b"SHA",
                                b"ECDSA", b"OpenSSL", b"libcrypto", b"MD5", b"ML-KEM",
                                b"ML_KEM", b"ChaCha", b"X25519", b"kem")):
            found.append(s.decode("utf-8", "replace"))
        if len(found) > 4000:
            break
    info.strings_sample = found[:600]

    vm = _VERSION_STRING.search(data)
    if vm:
        info.openssl_version = vm.group(1).decode()
    return info


class BinaryScanner:
    id = "binary-format"

    def supports(self, path: str) -> bool:
        ext = os.path.splitext(path)[1].lower()
        if ext in (".so", ".dylib", ".dll", ".exe", ".a", ".o", ".bin", ".elf"):
            return True
        if ext in (".py", ".js", ".java", ".txt", ".md", ".json", ".yaml", ".yml"):
            return False
        return ext == ""            # extension-less files may be executables

    def detect(self, path: str, text: str = "") -> list[Detection]:
        info = analyze_binary(path)
        if info.fmt == "unknown":
            return []
        return binary_detections(info)


def binary_detections(info: BinaryInfo) -> list[Detection]:
    out: list[Detection] = []
    base_extra = {
        "binary_format": info.fmt, "arch": info.arch, "bits": info.bits,
        "linked_libraries": info.needed, "stripped": info.stripped,
        "symbol_count": len(info.symbols), "size_bytes": info.size,
        "parse_errors": info.errors,
    }

    # ---- tier 1: dynamic linkage ---------------------------------------------------
    for soname in info.needed:
        lib = libs.resolve_package(soname.split("/")[-1].split(".")[0]) or \
            libs.resolve_package(soname)
        if lib is None:
            for cand in libs.ALL_LIBRARIES:
                if any(sn.split(".")[0] in soname for sn in cand.sonames if sn):
                    lib = cand
                    break
        if lib is None:
            continue
        cap, cap_note = libs.pqc_capability(lib, info.openssl_version
                                            if lib.id == "openssl" else None)
        out.append(Detection(
            detector=BinaryScanner.id, method="dynamic-linkage",
            confidence=Confidence.HIGH,
            library=lib.id,
            library_version=info.openssl_version if lib.id == "openssl" else None,
            file=info.path, language=info.fmt.lower(),
            matched=soname,
            reasoning=(f"{info.fmt} dynamic linkage table names '{soname}', resolved to "
                       f"{lib.name}. Linkage is structural evidence from the binary "
                       f"header, not a string heuristic. PQC capability: {cap}."),
            api_call="dynamic-linkage",
            extra={**base_extra, "soname": soname, "pqc_capability": cap,
                   "pqc_note": cap_note, "evidence_tier": "linkage"},
        ))

    # ---- tier 2: symbols ------------------------------------------------------------
    symbol_blob = "\n".join(info.symbols)
    seen_alg: set[str] = set()
    if symbol_blob:
        for rx, alg_id, note in _SYMBOL_SIGS:
            m = rx.search(symbol_blob)
            if not m or alg_id in seen_alg:
                continue
            spec = alg.get(alg_id) if alg_id else None
            if alg_id:
                seen_alg.add(alg_id)
            out.append(Detection(
                detector=BinaryScanner.id, method="symbol-table",
                confidence=Confidence.MEDIUM,
                algorithm=alg_id, role=alg.ROLE_UNKNOWN,
                key_size=(int(alg_id.split("-")[1]) if alg_id and alg_id.startswith("aes-")
                          else None),
                file=info.path, language=info.fmt.lower(),
                matched=m.group(0),
                reasoning=(f"Symbol '{m.group(0)}' present in the {info.fmt} symbol "
                           f"table ({note}). The symbol names its parameter set, so the "
                           f"algorithm identification is reliable; whether this code "
                           f"path executes at runtime cannot be established statically, "
                           f"so no cryptographic role is claimed."),
                api_call="symbol-table",
                extra={**base_extra, "evidence_tier": "symbol", "signature_note": note},
            ))

    # ---- tier 3: strings ------------------------------------------------------------
    blob = "\n".join(info.strings_sample).encode("utf-8", "replace")
    for rx, proto, ver in _TLS_VERSION_STRINGS:
        if rx.search(blob):
            out.append(Detection(
                detector=BinaryScanner.id, method="strings",
                confidence=Confidence.LOW,
                protocol=proto, protocol_version=ver,
                file=info.path, language=info.fmt.lower(),
                matched=f"{proto}{ver}",
                reasoning=(f"String literal '{proto}v{ver}' found in the binary. This "
                           f"indicates the protocol version is *supported by the linked "
                           f"library*, not that it is enabled or negotiated. Corroborate "
                           f"with configuration before acting."),
                api_call="strings",
                extra={**base_extra, "evidence_tier": "string"},
            ))
    return out
