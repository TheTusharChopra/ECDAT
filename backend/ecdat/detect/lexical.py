"""Layer 1 -- lexical pattern detection, and Layer 2b -- context-scored semantics.

Layer 1 alone would be a toy. What makes it defensible is the second stage in this
module: every lexical hit is scored against the *surrounding evidence* before a
confidence level is assigned.

    "AES" in a comment                          -> LOW,  no role claimed
    "AES" next to Cipher.getInstance("AES/GCM") -> HIGH, role=encryption, mode=gcm
    "MD5" next to a docstring saying 'checksum' -> LOW + non-security-use flag

That last case matters: hashing a file for cache invalidation with MD5 is not a
cryptographic vulnerability, and a tool that reports it as one destroys its own
credibility with the security team reading the output.
"""

from __future__ import annotations

import re

from ..knowledge import algorithms as alg
from ..knowledge import libraries as libs
from ..models import Confidence
from .base import Detection, language_for

# ======================================================================================
# Algorithm token patterns. Word-boundary anchored; ordered longest-first at match time
# so that "AES-256-GCM" is not shredded into "AES".
# ======================================================================================
_ALG_PATTERNS: list[tuple[str, str]] = [
    # symmetric with explicit size
    (r"\bAES[-_ ]?256[-_ ]?(GCM|CBC|CTR|CCM|ECB|OFB|CFB|XTS)\b", "aes-256"),
    (r"\bAES[-_ ]?192[-_ ]?(GCM|CBC|CTR|CCM|ECB)\b", "aes-192"),
    (r"\bAES[-_ ]?128[-_ ]?(GCM|CBC|CTR|CCM|ECB|OFB|CFB)\b", "aes-128"),
    (r"\bAES[-_ ]?256\b", "aes-256"),
    (r"\bAES[-_ ]?192\b", "aes-192"),
    (r"\bAES[-_ ]?128\b", "aes-128"),
    (r"\bAES\b", "aes-128"),          # unqualified AES: size unknown, flagged below
    (r"\bCHACHA20[-_ ]?POLY1305\b", "chacha20-poly1305"),
    (r"\bXCHACHA20[-_ ]?POLY1305\b", "chacha20-poly1305"),
    (r"\bCHACHA20\b", "chacha20"),
    (r"\b(3DES|TRIPLEDES|DES[-_ ]?EDE3|DESede)\b", "3des"),
    (r"\bDES\b", "des"),
    (r"\bRC4\b|\bARCFOUR\b", "rc4"),
    (r"\bBLOWFISH\b", "blowfish"),
    # hashes
    (r"\bSHA3[-_ ]?512\b", "sha3-512"),
    (r"\bSHA3[-_ ]?256\b", "sha3-256"),
    (r"\bSHAKE256\b", "shake256"),
    (r"\bSHA[-_ ]?512\b", "sha-512"),
    (r"\bSHA[-_ ]?384\b", "sha-384"),
    (r"\bSHA[-_ ]?256\b", "sha-256"),
    (r"\bSHA[-_ ]?224\b", "sha-224"),
    (r"\bSHA[-_ ]?1\b|\bSHA1\b", "sha-1"),
    (r"\bMD5\b", "md5"),
    # MAC / KDF
    (r"\bHMAC[-_ ]?SHA[-_ ]?256\b", "hmac-sha256"),
    (r"\bHMAC[-_ ]?SHA[-_ ]?1\b", "hmac-sha1"),
    (r"\bHMAC[-_ ]?MD5\b", "hmac-md5"),
    (r"\bPBKDF2\b", "pbkdf2"),
    (r"\bHKDF\b", "hkdf"),
    # public key
    (r"\bRSA[-_ ]?(4096|3072|2048|1024)\b", "rsa"),
    (r"\bRSA\b", "rsa"),
    (r"\bECDSA\b", "ecdsa"),
    (r"\bED25519\b", "ed25519"),
    (r"\bED448\b", "ed448"),
    (r"\bX25519\b", "x25519"),
    (r"\bX448\b", "x448"),
    (r"\bECDHE?\b", "ecdh"),
    (r"\bDSA\b", "dsa"),
    (r"\bDIFFIE[-_ ]?HELLMAN\b|\bDHE?\b", "dh"),
    (r"\bELGAMAL\b", "elgamal"),
    # PQC + hybrid
    (r"\bML[-_ ]?KEM[-_ ]?1024\b", "ml-kem-1024"),
    (r"\bML[-_ ]?KEM[-_ ]?768\b", "ml-kem-768"),
    (r"\bML[-_ ]?KEM[-_ ]?512\b", "ml-kem-512"),
    (r"\bML[-_ ]?DSA[-_ ]?87\b", "ml-dsa-87"),
    (r"\bML[-_ ]?DSA[-_ ]?65\b", "ml-dsa-65"),
    (r"\bML[-_ ]?DSA[-_ ]?44\b", "ml-dsa-44"),
    (r"\bSLH[-_ ]?DSA[-_A-Z0-9]*\b", "slh-dsa-sha2-128s"),
    (r"\bKYBER[-_ ]?768\b", "ml-kem-768"),
    (r"\bKYBER\b", "ml-kem-768"),
    (r"\bDILITHIUM\b", "ml-dsa-65"),
    (r"\bSPHINCS\+?\b", "slh-dsa-sha2-128s"),
    (r"\bHQC\b", "hqc"),
    (r"\bX25519MLKEM768\b", "x25519mlkem768"),
    (r"\bSecP256r1MLKEM768\b", "secp256r1mlkem768"),
    (r"\bSecP384r1MLKEM1024\b", "secp384r1mlkem1024"),
    (r"\bX25519Kyber768Draft00\b", "x25519kyber768draft00"),
]

_COMPILED_ALG = [(re.compile(p, re.IGNORECASE), a) for p, a in _ALG_PATTERNS]

# ======================================================================================
# Strong crypto-API markers. Presence on the same line upgrades confidence and, for a
# subset, licenses a *role* claim.
# ======================================================================================
_API_MARKERS: list[tuple[re.Pattern[str], str, str | None]] = [
    # (pattern, api label, role it licenses)
    (re.compile(r"Cipher\.getInstance\s*\(", re.I), "javax.crypto.Cipher.getInstance", alg.ROLE_ENCRYPTION),
    (re.compile(r"MessageDigest\.getInstance\s*\(", re.I), "java.security.MessageDigest", alg.ROLE_HASH),
    (re.compile(r"Signature\.getInstance\s*\(", re.I), "java.security.Signature", alg.ROLE_SIGNATURE),
    (re.compile(r"KeyPairGenerator\.getInstance\s*\(", re.I), "java.security.KeyPairGenerator", None),
    (re.compile(r"KeyAgreement\.getInstance\s*\(", re.I), "javax.crypto.KeyAgreement", alg.ROLE_KEY_ESTABLISHMENT),
    (re.compile(r"Mac\.getInstance\s*\(", re.I), "javax.crypto.Mac", alg.ROLE_MAC),
    (re.compile(r"SecretKeyFactory\.getInstance\s*\(", re.I), "javax.crypto.SecretKeyFactory", alg.ROLE_KDF),
    (re.compile(r"\bcrypto\.create(Cipher|Decipher)iv?\s*\(", re.I), "node:crypto.createCipheriv", alg.ROLE_ENCRYPTION),
    (re.compile(r"\bcrypto\.createHash\s*\(", re.I), "node:crypto.createHash", alg.ROLE_HASH),
    (re.compile(r"\bcrypto\.createHmac\s*\(", re.I), "node:crypto.createHmac", alg.ROLE_MAC),
    (re.compile(r"\bcrypto\.createSign\s*\(|\bcrypto\.sign\s*\(", re.I), "node:crypto.createSign", alg.ROLE_SIGNATURE),
    (re.compile(r"\bcrypto\.generateKeyPair(Sync)?\s*\(", re.I), "node:crypto.generateKeyPair", None),
    (re.compile(r"\bcrypto\.createDiffieHellman\s*\(|createECDH\s*\(", re.I), "node:crypto.createECDH", alg.ROLE_KEY_ESTABLISHMENT),
    (re.compile(r"EVP_(Encrypt|Decrypt)Init(_ex2?)?\s*\(", re.I), "OpenSSL EVP_EncryptInit", alg.ROLE_ENCRYPTION),
    (re.compile(r"EVP_Digest(Init|Sign|Verify)[A-Za-z_]*\s*\(", re.I), "OpenSSL EVP_Digest*", None),
    (re.compile(r"EVP_PKEY_(keygen|encrypt|decrypt|sign|verify|derive)[a-z_]*\s*\(", re.I), "OpenSSL EVP_PKEY", None),
    (re.compile(r"\bRSA_(generate_key|public_encrypt|private_decrypt|sign|verify)[a-z_]*\s*\(", re.I), "OpenSSL RSA_*", None),
    (re.compile(r"SSL_CTX_set[a-z0-9_]*\s*\(", re.I), "OpenSSL SSL_CTX_set*", None),
    (re.compile(r"\b(ecdsa|rsa|ed25519)\.(Sign|Verify|SignPKCS1v15|GenerateKey)\s*\(", re.I), "Go crypto sign/verify", alg.ROLE_SIGNATURE),
    (re.compile(r"\b(aes|cipher)\.(NewCipher|NewGCM|NewCBCEncrypter)\s*\(", re.I), "Go crypto/aes", alg.ROLE_ENCRYPTION),
    (re.compile(r"\bcurve25519\.|\becdh\.", re.I), "Go ECDH", alg.ROLE_KEY_ESTABLISHMENT),
    (re.compile(r"\bhashlib\.(md5|sha1|sha256|sha384|sha512|sha3_256)\s*\(", re.I), "python hashlib", alg.ROLE_HASH),
    (re.compile(r"\bhmac\.new\s*\(", re.I), "python hmac.new", alg.ROLE_MAC),
    (re.compile(r"\.verify\s*\(", re.I), "verify call", alg.ROLE_SIGNATURE_VERIFICATION),
    (re.compile(r"\.sign\s*\(", re.I), "sign call", alg.ROLE_SIGNATURE),
    (re.compile(r"\bgenerate_private_key\s*\(", re.I), "pyca generate_private_key", None),
    (re.compile(r"\bexchange\s*\(", re.I), "key exchange call", alg.ROLE_KEY_ESTABLISHMENT),
    (re.compile(r"\bencapsulate\s*\(|\bdecapsulate\s*\(", re.I), "KEM encapsulate", alg.ROLE_KEY_ESTABLISHMENT),
]

# ======================================================================================
# Non-security usage markers -- suppress false positives (PART 21/42).
# ======================================================================================
_NON_SECURITY = re.compile(
    r"\b(checksum\w*|etag|cache[-_ ]?key\w*|cachekey|dedup\w*|fingerprint\w*|bucket|"
    r"shard|hash[-_ ]?ring|content[-_ ]?address\w*|integrity[-_ ]?only|non[-_ ]?crypto|"
    r"not[-_ ]?for[-_ ]?security|test[-_ ]?vector\w*|sample|placeholder|example\w*|"
    r"dummy|lorem|mock\w*|fixture\w*|legacy[-_ ]?id)\b",
    re.IGNORECASE,
)
# How many preceding lines to read when looking for a stated non-security
# intent. Three covers "comment above the def" plus the def line itself.
_NON_SECURITY_LOOKBACK = 3
_COMMENT_LINE = re.compile(r"^\s*(#|//|\*|/\*|<!--|--|;)")
_DOC_CONTEXT = re.compile(r"\b(TODO|FIXME|deprecated|see also|reference|docs?|README)\b", re.I)

# key size / curve extraction
_KEYSIZE = re.compile(
    r"(?:key[-_ ]?(?:size|length|bits)|modulus|bits|public_exponent\s*=\s*\d+\s*,\s*key_size)"
    r"\s*[=:]\s*(\d{3,5})\b", re.IGNORECASE)
_KEYSIZE_CALL = re.compile(r"\b(?:generate|newkey|genrsa|generate_private_key|"
                           r"GenerateKey|generateKeyPair|initialize)\w*\s*\([^)]*?\b(\d{3,5})\b",
                           re.IGNORECASE)
_CURVE = re.compile(r"\b(secp(?:192r1|224r1|256r1|256k1|384r1|521r1)|prime256v1|"
                    r"P-?(?:192|224|256|384|521)|brainpoolP\d+r1|curve25519|curve448)\b",
                    re.IGNORECASE)
_MODE = re.compile(r"\b(GCM|CBC|CTR|CCM|ECB|OFB|CFB|XTS|SIV)\b")
_PADDING = re.compile(r"\b(OAEP|PKCS1v15|PKCS1|PKCS5Padding|PKCS7Padding|NoPadding|PSS)\b", re.I)

_MODE_CDX = {"gcm": "gcm", "cbc": "cbc", "ctr": "ctr", "ccm": "ccm", "ecb": "ecb",
             "ofb": "ofb", "cfb": "cfb"}
_PADDING_CDX = {"oaep": "oaep", "pkcs1v15": "pkcs1v15", "pkcs1": "pkcs1v15",
                "pkcs5padding": "pkcs5", "pkcs7padding": "pkcs7", "nopadding": "raw"}


class LexicalDetector:
    """Layer 1 + Layer 2b. Works on any text file, in any language."""

    id = "lexical-context"

    def supports(self, path: str) -> bool:
        return True

    def detect(self, path: str, text: str) -> list[Detection]:
        lang = language_for(path)
        out: list[Detection] = []
        lines = text.splitlines()
        is_test = bool(re.search(r"(^|/)(tests?|spec|fixtures?|examples?)/|_test\.|test_|\.spec\.",
                                 path, re.I))

        for idx, raw_line in enumerate(lines, start=1):
            if len(raw_line) > 4000:      # minified bundles: skip, they generate noise
                continue
            line = raw_line
            claimed: set[str] = set()
            consumed_spans: list[tuple[int, int]] = []

            for pattern, alg_id in _COMPILED_ALG:
                m = pattern.search(line)
                if not m:
                    continue
                # longest-first: skip if this span sits inside an already-matched span
                if any(s <= m.start() and m.end() <= e for s, e in consumed_spans):
                    continue
                if alg_id in claimed:
                    continue
                spec = alg.get(alg_id)
                if spec is None:
                    continue
                claimed.add(alg_id)
                consumed_spans.append((m.start(), m.end()))

                det = self._build(path, lang, idx, line, m, spec, is_test, lines)
                if det:
                    out.append(det)
        return out

    # ---------------------------------------------------------------------------------
    def _build(self, path, lang, line_no, line, match, spec, is_test,
               lines: list[str] | None = None) -> Detection | None:
        matched_text = match.group(0)
        context = line

        # Non-security intent is almost never stated on the same line as the call.
        # It lives in the enclosing function name or the comment above it, so the
        # suppression check reads a small window while the API-marker check below
        # stays strictly line-local (an API call on another line proves nothing
        # about this one).
        window = context
        if lines:
            start = max(0, line_no - 1 - _NON_SECURITY_LOOKBACK)
            window = "\n".join(lines[start:line_no])

        api_label: str | None = None
        licensed_role: str | None = None
        for pat, label, role in _API_MARKERS:
            if pat.search(context):
                api_label = label
                licensed_role = role
                break

        in_comment = bool(_COMMENT_LINE.match(line))
        non_security = bool(_NON_SECURITY.search(window))
        doc_context = bool(_DOC_CONTEXT.search(context))

        # ---- confidence scoring -----------------------------------------------------
        if api_label and not in_comment:
            confidence = Confidence.HIGH
            reasoning = (f"Algorithm token '{matched_text}' appears on the same line as "
                         f"cryptographic API '{api_label}'.")
        elif not in_comment and re.search(r"[=(\[\"']", context):
            confidence = Confidence.MEDIUM
            reasoning = (f"Algorithm token '{matched_text}' used in an expression or "
                         f"string literal, but no recognised crypto API on this line.")
        else:
            confidence = Confidence.LOW
            reasoning = (f"Lexical match on '{matched_text}'"
                         + (" inside a comment." if in_comment else " with no surrounding context."))

        if in_comment or doc_context:
            confidence = Confidence.LOW
        if non_security and confidence != Confidence.HIGH:
            confidence = Confidence.LOW
            reasoning += (" Context suggests a non-security use (checksum/cache/fixture); "
                          "downgraded and flagged for triage.")

        # ---- parameter extraction ---------------------------------------------------
        key_size = None
        for rx in (_KEYSIZE, _KEYSIZE_CALL):
            km = rx.search(context)
            if km:
                val = int(km.group(1))
                if 128 <= val <= 16384:
                    key_size = val
                    break
        if key_size is None and spec.family == "RSA":
            km = re.search(r"\bRSA[-_ ]?(4096|3072|2048|1024)\b", matched_text, re.I)
            if km:
                key_size = int(km.group(1))
        if spec.family == "AES" and spec.id.startswith("aes-"):
            key_size = int(spec.id.split("-")[1])

        curve = None
        cm = _CURVE.search(context)
        if cm:
            curve = cm.group(1)

        mode = None
        mm = _MODE.search(matched_text) or _MODE.search(context)
        if mm and spec.primitive in ("block-cipher", "stream-cipher", "ae"):
            mode = _MODE_CDX.get(mm.group(1).lower(), "other")

        padding = None
        pm = _PADDING.search(context)
        if pm and spec.family in ("RSA",):
            padding = _PADDING_CDX.get(pm.group(1).lower().replace("-", ""), "other")

        # ---- role: only claim what evidence supports (PART 8/16) --------------------
        role = licensed_role
        if role is None:
            # only default where the capability set is unambiguous at decision level
            derived = alg.default_role(spec)
            if derived != alg.ROLE_UNKNOWN:
                role = derived
        if role is None:
            role = alg.ROLE_UNKNOWN

        lib = self._library_hint(context)

        extra: dict[str, object] = {}
        if is_test:
            extra["in_test_path"] = True
        if non_security:
            extra["suspected_non_security_use"] = True
        if spec.id == "aes-128" and re.search(r"\bAES\b", matched_text, re.I) and \
                not re.search(r"128", matched_text):
            extra["key_size_assumed"] = True
            extra["assumption"] = ("Unqualified 'AES' token; key size not determinable "
                                   "from source. Recorded as AES-128 (the weakest legal "
                                   "variant) so the risk score is conservative rather "
                                   "than optimistic.")

        return Detection(
            detector=self.id,
            method="regex+context" if api_label else "regex",
            confidence=confidence,
            algorithm=spec.id,
            role=role,
            key_size=key_size,
            curve=curve,
            mode=mode,
            padding=padding,
            library=lib,
            file=path,
            line=line_no,
            language=lang,
            snippet=line,
            matched=matched_text,
            reasoning=reasoning,
            api_call=api_label,
            extra=extra,
        )

    @staticmethod
    def _library_hint(context: str) -> str | None:
        low = context.lower()
        for lib in libs.ALL_LIBRARIES:
            for token in (lib.id, *lib.package_names):
                t = token.lower()
                if len(t) >= 5 and t in low:
                    return lib.id
        if "openssl" in low or "evp_" in low or "ssl_ctx" in low:
            return "openssl"
        if "javax.crypto" in low or "java.security" in low:
            return "jca"
        if "hashlib" in low or "hmac" in low:
            return None
        return None
