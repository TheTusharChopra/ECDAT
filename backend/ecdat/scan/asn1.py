"""Minimal DER (ASN.1 Distinguished Encoding Rules) reader.

Written from scratch because ECDAT's analysis core must run with zero third-party
dependencies in an air-gapped environment. Scope is deliberately narrow: enough
DER to parse X.509 certificate *metadata*. It is a strict reader -- malformed
input raises rather than guessing -- and it enforces a nesting depth and a length
ceiling so a hostile certificate cannot exhaust memory in the scanner (PART 30:
safe parsing, resource limits).

It never decrypts anything and has no code path that can emit private key bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MAX_DEPTH = 40
MAX_LENGTH = 8 * 1024 * 1024  # 8 MiB ceiling on any single DER value


class Asn1Error(ValueError):
    pass


# --- universal tags ---------------------------------------------------------------------
BOOLEAN = 0x01
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OID = 0x06
UTF8_STRING = 0x0C
SEQUENCE = 0x10
SET = 0x11
PRINTABLE_STRING = 0x13
T61_STRING = 0x14
IA5_STRING = 0x16
UTC_TIME = 0x17
GENERALIZED_TIME = 0x18
BMP_STRING = 0x1E

_STRING_TAGS = {UTF8_STRING, PRINTABLE_STRING, T61_STRING, IA5_STRING, BMP_STRING,
                0x15, 0x1A}

CLASS_UNIVERSAL = 0x00
CLASS_APPLICATION = 0x40
CLASS_CONTEXT = 0x80
CLASS_PRIVATE = 0xC0


@dataclass
class Node:
    """One TLV. `children` is populated for constructed values."""

    tag: int              # raw first identifier octet
    tag_number: int       # low 5 bits
    tag_class: int        # high 2 bits
    constructed: bool
    value: bytes          # raw content octets
    children: list["Node"] = field(default_factory=list)
    offset: int = 0

    # -- convenience accessors ---------------------------------------------------------
    def child(self, *path: int) -> "Node":
        node = self
        for i in path:
            if i >= len(node.children):
                raise Asn1Error(f"no child at index {i} (have {len(node.children)})")
            node = node.children[i]
        return node

    def find(self, tag_number: int, tag_class: int = CLASS_UNIVERSAL) -> "Node | None":
        for c in self.children:
            if c.tag_number == tag_number and c.tag_class == tag_class:
                return c
        return None

    @property
    def is_seq(self) -> bool:
        return self.tag_class == CLASS_UNIVERSAL and self.tag_number in (SEQUENCE, SET)

    def as_int(self) -> int:
        if not self.value:
            return 0
        return int.from_bytes(self.value, "big", signed=True)

    def as_uint(self) -> int:
        return int.from_bytes(self.value.lstrip(b"\x00") or b"\x00", "big")

    def as_bool(self) -> bool:
        return bool(self.value and self.value[0] != 0)

    def as_oid(self) -> str:
        return decode_oid(self.value)

    def as_text(self) -> str:
        if self.tag_number == BMP_STRING:
            try:
                return self.value.decode("utf-16-be", "replace")
            except Exception:
                return self.value.decode("latin-1", "replace")
        for enc in ("utf-8", "latin-1"):
            try:
                return self.value.decode(enc)
            except UnicodeDecodeError:
                continue
        return self.value.decode("utf-8", "replace")

    def bitstring_bytes(self) -> bytes:
        """Content of a BIT STRING minus the unused-bits prefix octet."""
        if not self.value:
            return b""
        unused = self.value[0]
        if unused > 7:
            raise Asn1Error(f"invalid BIT STRING unused-bit count {unused}")
        return self.value[1:]


def decode_oid(data: bytes) -> str:
    """Decode a DER OID content octet string to dotted notation."""
    if not data:
        raise Asn1Error("empty OID")
    first = data[0]
    parts = [str(first // 40), str(first % 40)]
    if first >= 80:
        parts = ["2", str(first - 80)]
    val = 0
    started = False
    for b in data[1:]:
        val = (val << 7) | (b & 0x7F)
        started = True
        if not b & 0x80:
            parts.append(str(val))
            val = 0
            started = False
    if started:
        raise Asn1Error("truncated OID: final subidentifier has continuation bit set")
    return ".".join(parts)


def _read_length(buf: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(buf):
        raise Asn1Error("truncated length")
    b = buf[pos]
    pos += 1
    if b < 0x80:
        return b, pos
    n = b & 0x7F
    if n == 0:
        raise Asn1Error("indefinite length not permitted in DER")
    if n > 4:
        raise Asn1Error("length field too large")
    if pos + n > len(buf):
        raise Asn1Error("truncated long-form length")
    length = int.from_bytes(buf[pos:pos + n], "big")
    if length > MAX_LENGTH:
        raise Asn1Error(f"value length {length} exceeds ECDAT parse ceiling")
    return length, pos + n


def parse(buf: bytes, pos: int = 0, depth: int = 0) -> tuple[Node, int]:
    """Parse one TLV at `pos`; return (node, next_position)."""
    if depth > MAX_DEPTH:
        raise Asn1Error("maximum nesting depth exceeded")
    if pos >= len(buf):
        raise Asn1Error("truncated: expected tag")
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise Asn1Error("multi-octet tags not supported")
    pos += 1
    length, pos = _read_length(buf, pos)
    end = pos + length
    if end > len(buf):
        raise Asn1Error(f"truncated value: need {length} bytes, have {len(buf) - pos}")

    node = Node(
        tag=tag,
        tag_number=tag & 0x1F,
        tag_class=tag & 0xC0,
        constructed=bool(tag & 0x20),
        value=buf[pos:end],
        offset=pos,
    )

    if node.constructed:
        inner = pos
        while inner < end:
            child, inner = parse(buf, inner, depth + 1)
            node.children.append(child)
        if inner != end:
            raise Asn1Error("constructed value overran its declared length")

    return node, end


def parse_one(buf: bytes) -> Node:
    node, consumed = parse(buf, 0, 0)
    return node


def parse_explicit(node: Node, depth: int = 0) -> Node | None:
    """Unwrap an EXPLICIT context-tagged wrapper to its single inner value."""
    if node.constructed and node.children:
        return node.children[0]
    try:
        inner, _ = parse(node.value, 0, depth + 1)
        return inner
    except Asn1Error:
        return None
