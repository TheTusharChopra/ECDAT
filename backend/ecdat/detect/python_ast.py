"""Layer 2 -- true semantic analysis of Python via the stdlib `ast` module.

This is where ECDAT stops guessing. For Python we build a real syntax tree and:

  1. resolve import aliases, so `from cryptography...asymmetric import rsa as r`
     still resolves `r.generate_private_key` to the canonical API path;
  2. propagate module- and function-level integer constants, so
     `KEY_BITS = 1024` ... `generate_private_key(key_size=KEY_BITS)` is caught;
  3. infer AES key length from `os.urandom(32)` / `token_bytes(16)` bindings;
  4. **refine cryptographic role by dataflow** -- a private key object is tracked
     from its constructor to its use, so `k = rsa.generate_private_key(...)`
     followed by `k.sign(...)` yields DIGITAL_SIGNATURE, `k.verify(...)` yields
     SIGNATURE_VERIFICATION, and `k.decrypt(...)` yields DECRYPTION. This is the
     honest answer to "how do you know RSA is signing rather than doing key
     establishment?": we claim only the role we observed a call for, and fall back
     to Role.UNKNOWN otherwise.

Tree-sitter would extend the same design to Java/Go/JS; it is not installed in
this environment, so those languages are served by the context-scored detector in
`lexical.py` and are reported at correspondingly lower confidence. That gap is
recorded honestly rather than papered over.
"""

from __future__ import annotations

import ast
import os

from ..knowledge import algorithms as alg
from ..models import Confidence
from .base import Detection

# ======================================================================================
# API table. Keys are canonical dotted paths (or suffixes matched right-to-left).
# ======================================================================================


class ApiSpec:
    __slots__ = ("algorithm", "role", "library", "argmap", "note", "primitive_hint")

    def __init__(self, algorithm=None, role=None, library=None, argmap=None,
                 note="", primitive_hint=None):
        self.algorithm = algorithm
        self.role = role
        self.library = library
        self.argmap = argmap or {}
        self.note = note
        self.primitive_hint = primitive_hint


R_KEY = alg.ROLE_KEY_ESTABLISHMENT
R_KT = alg.ROLE_KEY_TRANSPORT
R_SIG = alg.ROLE_SIGNATURE
R_VER = alg.ROLE_SIGNATURE_VERIFICATION
R_ENC = alg.ROLE_ENCRYPTION
R_DEC = alg.ROLE_DECRYPTION
R_HASH = alg.ROLE_HASH
R_MAC = alg.ROLE_MAC
R_KDF = alg.ROLE_KDF
R_UNK = alg.ROLE_UNKNOWN

PYCA = "python-cryptography"

# argmap values: ("key_size", kwarg_name_or_positional_index)
_APIS: dict[str, ApiSpec] = {
    # ---- pyca/cryptography asymmetric --------------------------------------------
    "asymmetric.rsa.generate_private_key": ApiSpec(
        "rsa", R_UNK, PYCA, {"key_size": "key_size"},
        "RSA key generation; role determined by later use, not by generation."),
    "asymmetric.dsa.generate_private_key": ApiSpec("dsa", R_SIG, PYCA, {"key_size": "key_size"}),
    "asymmetric.ec.generate_private_key": ApiSpec("ecdsa", R_UNK, PYCA, {"curve": 0}),
    "asymmetric.ed25519.Ed25519PrivateKey.generate": ApiSpec("ed25519", R_SIG, PYCA),
    "asymmetric.ed448.Ed448PrivateKey.generate": ApiSpec("ed448", R_SIG, PYCA),
    "asymmetric.x25519.X25519PrivateKey.generate": ApiSpec("x25519", R_KEY, PYCA),
    "asymmetric.x448.X448PrivateKey.generate": ApiSpec("x448", R_KEY, PYCA),
    "asymmetric.dh.generate_parameters": ApiSpec("dh", R_KEY, PYCA, {"key_size": "key_size"}),
    "asymmetric.padding.OAEP": ApiSpec("rsa", R_KT, PYCA,
                                       note="OAEP padding => RSA key transport; migrating "
                                            "this needs a KEM, not a cipher swap."),
    "asymmetric.padding.PKCS1v15": ApiSpec("rsa", R_UNK, PYCA,
                                           note="PKCS#1 v1.5 is used for both signing and encryption."),
    "asymmetric.padding.PSS": ApiSpec("rsa", R_SIG, PYCA, note="PSS padding => RSA signature."),
    # ---- pyca ciphers -------------------------------------------------------------
    "ciphers.algorithms.AES": ApiSpec("aes-128", R_ENC, PYCA, {"key_var": 0}),
    "ciphers.algorithms.TripleDES": ApiSpec("3des", R_ENC, PYCA),
    "ciphers.algorithms.ChaCha20": ApiSpec("chacha20", R_ENC, PYCA),
    "ciphers.algorithms.Blowfish": ApiSpec("blowfish", R_ENC, PYCA),
    "ciphers.algorithms.ARC4": ApiSpec("rc4", R_ENC, PYCA),
    "ciphers.aead.AESGCM": ApiSpec("aes-128", R_ENC, PYCA, {"key_var": 0}),
    "ciphers.aead.AESCCM": ApiSpec("aes-128", R_ENC, PYCA, {"key_var": 0}),
    "ciphers.aead.ChaCha20Poly1305": ApiSpec("chacha20-poly1305", R_ENC, PYCA),
    # ---- pyca hashes / kdf / mac ---------------------------------------------------
    "hashes.MD5": ApiSpec("md5", R_HASH, PYCA),
    "hashes.SHA1": ApiSpec("sha-1", R_HASH, PYCA),
    "hashes.SHA224": ApiSpec("sha-224", R_HASH, PYCA),
    "hashes.SHA256": ApiSpec("sha-256", R_HASH, PYCA),
    "hashes.SHA384": ApiSpec("sha-384", R_HASH, PYCA),
    "hashes.SHA512": ApiSpec("sha-512", R_HASH, PYCA),
    "hashes.SHA3_256": ApiSpec("sha3-256", R_HASH, PYCA),
    "kdf.pbkdf2.PBKDF2HMAC": ApiSpec("pbkdf2", R_KDF, PYCA),
    "kdf.hkdf.HKDF": ApiSpec("hkdf", R_KDF, PYCA),
    "hmac.HMAC": ApiSpec("hmac-sha256", R_MAC, PYCA),
    # ---- stdlib hashlib / hmac ------------------------------------------------------
    "hashlib.md5": ApiSpec("md5", R_HASH, None),
    "hashlib.sha1": ApiSpec("sha-1", R_HASH, None),
    "hashlib.sha224": ApiSpec("sha-224", R_HASH, None),
    "hashlib.sha256": ApiSpec("sha-256", R_HASH, None),
    "hashlib.sha384": ApiSpec("sha-384", R_HASH, None),
    "hashlib.sha512": ApiSpec("sha-512", R_HASH, None),
    "hashlib.sha3_256": ApiSpec("sha3-256", R_HASH, None),
    "hashlib.pbkdf2_hmac": ApiSpec("pbkdf2", R_KDF, None),
    "hashlib.new": ApiSpec(None, R_HASH, None, {"alg_literal": 0}),
    "hmac.new": ApiSpec("hmac-sha256", R_MAC, None, {"hmac_digest": "digestmod"}),
    # ---- PyCryptodome ---------------------------------------------------------------
    "Cipher.AES.new": ApiSpec("aes-128", R_ENC, "pycryptodome", {"key_var": 0, "mode_attr": 1}),
    "Cipher.DES3.new": ApiSpec("3des", R_ENC, "pycryptodome"),
    "Cipher.DES.new": ApiSpec("des", R_ENC, "pycryptodome"),
    "Cipher.ARC4.new": ApiSpec("rc4", R_ENC, "pycryptodome"),
    "PublicKey.RSA.generate": ApiSpec("rsa", R_UNK, "pycryptodome", {"key_size": 0}),
    "PublicKey.ECC.generate": ApiSpec("ecdsa", R_UNK, "pycryptodome", {"curve": "curve"}),
    "Hash.MD5.new": ApiSpec("md5", R_HASH, "pycryptodome"),
    "Hash.SHA1.new": ApiSpec("sha-1", R_HASH, "pycryptodome"),
    "Hash.SHA256.new": ApiSpec("sha-256", R_HASH, "pycryptodome"),
    "Signature.pkcs1_15.new": ApiSpec("rsa", R_SIG, "pycryptodome"),
    "Signature.pss.new": ApiSpec("rsa", R_SIG, "pycryptodome"),
    "Cipher.PKCS1_OAEP.new": ApiSpec("rsa", R_KT, "pycryptodome"),
    # ---- ssl / paramiko / jwt -------------------------------------------------------
    "ssl.SSLContext": ApiSpec(None, None, "openssl", {"tls_version": 0}),
    "ssl.wrap_socket": ApiSpec(None, None, "openssl"),
    "paramiko.SSHClient": ApiSpec(None, None, "paramiko"),
    "paramiko.RSAKey.from_private_key_file": ApiSpec("rsa", R_SIG, "paramiko",
                                                     note="SSH host/user authentication key."),
    "paramiko.Ed25519Key": ApiSpec("ed25519", R_SIG, "paramiko"),
    "jwt.encode": ApiSpec(None, R_SIG, None, {"jwt_alg": "algorithm"}),
    "jwt.decode": ApiSpec(None, R_SIG, None, {"jwt_algs": "algorithms"}),
}

# Method calls used for role refinement on tracked key objects.
_ROLE_BY_METHOD = {
    "sign": R_SIG,
    "verify": R_VER,
    "decrypt": R_DEC,
    "encrypt": R_ENC,
    "exchange": R_KEY,
    "derive": R_KDF,
    "encapsulate": R_KEY,
    "decapsulate": R_KEY,
}

_JWT_ALG = {
    "HS256": "hmac-sha256", "HS384": "hmac-sha256", "HS512": "hmac-sha256",
    "RS256": "rsa", "RS384": "rsa", "RS512": "rsa",
    "PS256": "rsa", "PS384": "rsa", "PS512": "rsa",
    "ES256": "ecdsa", "ES384": "ecdsa", "ES512": "ecdsa",
    "EdDSA": "ed25519", "none": None,
}

_TLS_CONST = {
    "PROTOCOL_TLSv1": ("TLS", "1.0"), "PROTOCOL_TLSv1_1": ("TLS", "1.1"),
    "PROTOCOL_TLSv1_2": ("TLS", "1.2"), "PROTOCOL_SSLv3": ("SSL", "3.0"),
    "PROTOCOL_SSLv23": ("TLS", "negotiated"), "PROTOCOL_TLS": ("TLS", "negotiated"),
    "PROTOCOL_TLS_CLIENT": ("TLS", "negotiated"), "PROTOCOL_TLS_SERVER": ("TLS", "negotiated"),
}

_CURVE_CLASSES = {
    "SECP192R1": "secp192r1", "SECP224R1": "secp224r1", "SECP256R1": "secp256r1",
    "SECP256K1": "secp256k1", "SECP384R1": "secp384r1", "SECP521R1": "secp521r1",
    "BrainpoolP256R1": "brainpoolp256r1", "BrainpoolP384R1": "brainpoolp384r1",
}


def _dotted(node: ast.AST) -> str | None:
    """Render an attribute/name chain as a dotted string."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    elif isinstance(cur, ast.Call):
        inner = _dotted(cur.func)
        if inner:
            parts.append(inner)
    else:
        return None
    return ".".join(reversed(parts))


class PythonAstDetector:
    """Genuine AST-based detection for Python sources."""

    id = "python-ast"

    def supports(self, path: str) -> bool:
        return os.path.splitext(path)[1].lower() in (".py", ".pyi")

    # ---------------------------------------------------------------------------------
    def detect(self, path: str, text: str) -> list[Detection]:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            # A file we cannot parse is not silently dropped -- the source scanner
            # records it so coverage stays honest.
            return []

        lines = text.splitlines()
        ctx = _FileContext(path, lines)
        ctx.collect_imports(tree)
        ctx.collect_constants(tree)
        ctx.collect_calls(tree)
        return ctx.finalize()


class _FileContext:
    def __init__(self, path: str, lines: list[str]):
        self.path = path
        self.lines = lines
        self.alias: dict[str, str] = {}     # local name -> canonical dotted path
        self.consts: dict[str, int] = {}    # NAME -> int literal
        self.byte_lens: dict[str, int] = {} # var -> byte length (os.urandom(32))
        self.detections: list[Detection] = []
        # tracked key objects: var -> (algorithm, line, key_size, curve, det_index)
        self.keys: dict[str, dict] = {}
        self.role_uses: dict[str, list[tuple[str, int]]] = {}

    def line_at(self, n: int) -> str:
        return self.lines[n - 1] if 0 < n <= len(self.lines) else ""

    # -- imports -----------------------------------------------------------------------
    def collect_imports(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.alias[a.asname or a.name.split(".")[0]] = a.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for a in node.names:
                    self.alias[a.asname or a.name] = f"{mod}.{a.name}"

    def canonical(self, dotted: str) -> str:
        """Rewrite a local dotted call through the alias table."""
        head, _, rest = dotted.partition(".")
        base = self.alias.get(head, head)
        return f"{base}.{rest}" if rest else base

    # -- constants ---------------------------------------------------------------------
    def collect_constants(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                tgt = node.targets[0]
                if not isinstance(tgt, ast.Name):
                    continue
                val = node.value
                if isinstance(val, ast.Constant) and isinstance(val.value, int):
                    self.consts[tgt.id] = val.value
                elif isinstance(val, ast.Call):
                    fn = _dotted(val.func) or ""
                    canon = self.canonical(fn)
                    if canon.endswith(("os.urandom", "secrets.token_bytes", "urandom",
                                       "token_bytes", "get_random_bytes")) and val.args:
                        a0 = val.args[0]
                        n = None
                        if isinstance(a0, ast.Constant) and isinstance(a0.value, int):
                            n = a0.value
                        elif isinstance(a0, ast.Name):
                            n = self.consts.get(a0.id)
                        if n:
                            self.byte_lens[tgt.id] = n

    def _int_arg(self, node: ast.AST | None) -> int | None:
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Name):
            return self.consts.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.LShift)):
            l = self._int_arg(node.left)
            r = self._int_arg(node.right)
            if l is not None and r is not None:
                return l * r if isinstance(node.op, ast.Mult) else l << r
        return None

    def _str_arg(self, node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    # -- calls -------------------------------------------------------------------------
    def collect_calls(self, tree: ast.AST) -> None:
        # First pass: record method-call role evidence on any variable.
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                base = node.func.value
                meth = node.func.attr
                if isinstance(base, ast.Name) and meth in _ROLE_BY_METHOD:
                    self.role_uses.setdefault(base.id, []).append((meth, node.lineno))

        # Second pass: the actual API matches.
        parents: dict[int, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[id(child)] = parent

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            dotted = _dotted(node.func)
            if not dotted:
                continue
            canon = self.canonical(dotted)
            spec, matched_key = self._lookup(canon, dotted)
            if spec is None:
                # protocol constants passed as ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                continue
            self._emit(node, spec, matched_key, canon, parents)

    def _lookup(self, canon: str, dotted: str) -> tuple[ApiSpec | None, str | None]:
        for key in (canon, dotted):
            if key in _APIS:
                return _APIS[key], key
        # suffix match, longest first -- handles deep pyca module paths
        for api_key in sorted(_APIS, key=len, reverse=True):
            if canon.endswith("." + api_key) or dotted.endswith("." + api_key):
                return _APIS[api_key], api_key
            # bare trailing segment match for 2-part keys like "hashlib.md5"
            if api_key.count(".") == 1 and dotted == api_key:
                return _APIS[api_key], api_key
        return None, None

    # -- emit --------------------------------------------------------------------------
    def _emit(self, node: ast.Call, spec: ApiSpec, api_key: str, canon: str,
              parents: dict[int, ast.AST]) -> None:
        line = node.lineno
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        algorithm = spec.algorithm
        role = spec.role
        key_size = None
        curve = None
        mode = None
        protocol = None
        protocol_version = None
        notes: list[str] = []
        if spec.note:
            notes.append(spec.note)

        # ---- argument extraction ----------------------------------------------------
        for target, src in spec.argmap.items():
            val: ast.AST | None
            if isinstance(src, int):
                val = node.args[src] if len(node.args) > src else None
            else:
                val = kwargs.get(src)

            if target == "key_size":
                key_size = self._int_arg(val)
                if key_size and isinstance(val, ast.Name):
                    notes.append(f"key_size resolved from constant {val.id}={key_size} "
                                 f"by module-level constant propagation.")
            elif target == "curve":
                if val is not None:
                    cname = _dotted(val.func) if isinstance(val, ast.Call) else _dotted(val)
                    if cname:
                        leaf = cname.split(".")[-1]
                        curve = _CURVE_CLASSES.get(leaf, leaf.lower())
                    sval = self._str_arg(val)
                    if sval:
                        curve = sval.lower()
            elif target == "key_var":
                if isinstance(val, ast.Name) and val.id in self.byte_lens:
                    nbytes = self.byte_lens[val.id]
                    algorithm = {16: "aes-128", 24: "aes-192", 32: "aes-256"}.get(
                        nbytes, algorithm)
                    key_size = nbytes * 8
                    notes.append(f"AES key length inferred from {val.id} = "
                                 f"{nbytes}-byte random buffer.")
                elif isinstance(val, ast.Call):
                    fn = self.canonical(_dotted(val.func) or "")
                    if fn.endswith(("urandom", "token_bytes", "get_random_bytes")) and val.args:
                        n = self._int_arg(val.args[0])
                        if n:
                            algorithm = {16: "aes-128", 24: "aes-192",
                                         32: "aes-256"}.get(n, algorithm)
                            key_size = n * 8
                            notes.append(f"AES key length inferred from inline "
                                         f"{n}-byte random buffer.")
            elif target == "alg_literal":
                s = self._str_arg(val)
                if s:
                    resolved = alg.resolve(s)
                    if resolved:
                        algorithm = resolved.id
                        notes.append(f"Algorithm from string literal '{s}'.")
            elif target == "hmac_digest":
                if val is not None:
                    dn = _dotted(val) or self._str_arg(val) or ""
                    leaf = dn.split(".")[-1]
                    resolved = alg.resolve(leaf)
                    if resolved and resolved.primitive == "hash":
                        algorithm = f"hmac-{resolved.id.replace('-', '')}"
                        if algorithm not in ("hmac-sha256", "hmac-sha1", "hmac-md5"):
                            algorithm = "hmac-sha256" if "256" in leaf else algorithm
                        if "md5" in leaf.lower():
                            algorithm = "hmac-md5"
                        elif "sha1" in leaf.lower():
                            algorithm = "hmac-sha1"
                        notes.append(f"HMAC digest = {leaf}.")
            elif target == "mode_attr":
                if val is not None:
                    dn = _dotted(val) or ""
                    leaf = dn.split(".")[-1].lower()
                    for m in ("gcm", "cbc", "ctr", "ccm", "ecb", "ofb", "cfb"):
                        if m in leaf:
                            mode = m
                            break
            elif target == "jwt_alg":
                s = self._str_arg(val)
                if s:
                    algorithm = _JWT_ALG.get(s)
                    notes.append(f"JWT signing algorithm '{s}'.")
                    if s == "none":
                        notes.append("JWT alg 'none' disables signature verification.")
            elif target == "jwt_algs":
                if isinstance(val, (ast.List, ast.Tuple)):
                    for el in val.elts:
                        s = self._str_arg(el)
                        if s and _JWT_ALG.get(s):
                            algorithm = _JWT_ALG[s]
                            notes.append(f"JWT accepted algorithm '{s}'.")
                            break
            elif target == "tls_version":
                dn = _dotted(val) if val is not None else None
                leaf = (dn or "").split(".")[-1]
                if leaf in _TLS_CONST:
                    protocol, protocol_version = _TLS_CONST[leaf]
                    notes.append(f"TLS protocol constant {leaf}.")

        # ssl.SSLContext with no explicit protocol still evidences TLS usage
        if api_key and api_key.startswith("ssl.") and protocol is None:
            protocol, protocol_version = "TLS", "negotiated"

        # ---- mode from surrounding Cipher(...) construction --------------------------
        if algorithm and (alg.get(algorithm) or _Dummy()).primitive in (
                "block-cipher", "stream-cipher", "ae") and mode is None:
            mode = self._mode_from_sibling(node, parents)

        # ---- role refinement by dataflow --------------------------------------------
        assigned_to = self._assignment_target(node, parents)
        refined_from: tuple[str, int] | None = None
        if assigned_to and role in (None, R_UNK):
            for meth, uline in self.role_uses.get(assigned_to, []):
                cand = _ROLE_BY_METHOD.get(meth)
                if cand:
                    role = cand
                    refined_from = (meth, uline)
                    break
        if assigned_to:
            self.keys[assigned_to] = {"algorithm": algorithm, "line": line}

        if refined_from:
            meth, uline = refined_from
            notes.append(
                f"Cryptographic role refined to '{role}' by dataflow: the key object "
                f"bound to '{assigned_to}' at line {line} is used in "
                f"`.{meth}()` at line {uline}."
            )
        elif role in (None, R_UNK):
            spec_obj = alg.get(algorithm)
            derived = alg.default_role(spec_obj)
            if derived != R_UNK:
                role = derived
            else:
                role = R_UNK
                notes.append("Role not claimed: no usage of the generated key object was "
                             "observed in this file. Reported as UNKNOWN rather "
                             "than assumed.")

        if algorithm is None and protocol is None:
            return

        # ---- confidence -------------------------------------------------------------
        # A resolved AST call to a known cryptographic API is the strongest evidence a
        # static analyser can produce short of executing the code.
        confidence = Confidence.HIGH
        reasoning = (f"AST call to {canon} resolved through the import table"
                     + (f"; {' '.join(notes)}" if notes else "."))

        self.detections.append(Detection(
            detector=PythonAstDetector.id,
            method="ast-call",
            confidence=confidence,
            algorithm=algorithm,
            role=role,
            key_size=key_size,
            curve=curve,
            mode=mode,
            protocol=protocol,
            protocol_version=protocol_version,
            library=spec.library,
            file=self.path,
            line=line,
            language="python",
            snippet=self.line_at(line),
            matched=canon,
            reasoning=reasoning,
            api_call=canon,
            extra={"ast_notes": notes} if notes else {},
        ))

    def _assignment_target(self, node: ast.Call, parents: dict[int, ast.AST]) -> str | None:
        p = parents.get(id(node))
        while isinstance(p, ast.Call):        # unwrap e.g. wrapper(gen(...))
            p = parents.get(id(p))
        if isinstance(p, ast.Assign) and len(p.targets) == 1 and isinstance(p.targets[0], ast.Name):
            return p.targets[0].id
        if isinstance(p, ast.AnnAssign) and isinstance(p.target, ast.Name):
            return p.target.id
        return None

    def _mode_from_sibling(self, node: ast.Call, parents: dict[int, ast.AST]) -> str | None:
        """`Cipher(algorithms.AES(k), modes.GCM(iv))` -- mode is a sibling argument."""
        p = parents.get(id(node))
        if not isinstance(p, ast.Call):
            return None
        for arg in p.args:
            if isinstance(arg, ast.Call):
                dn = _dotted(arg.func) or ""
                leaf = dn.split(".")[-1].lower()
                for m in ("gcm", "cbc", "ctr", "ccm", "ecb", "ofb", "cfb"):
                    if leaf == m:
                        return m
        return None

    def finalize(self) -> list[Detection]:
        return self.detections


class _Dummy:
    primitive = None
