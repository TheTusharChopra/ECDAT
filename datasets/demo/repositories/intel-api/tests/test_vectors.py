"""Known-answer tests. These reference weak algorithms deliberately as test
vectors -- ECDAT should flag them LOW confidence / test-path, not as findings."""
import hashlib

MD5_TEST_VECTOR = "d41d8cd98f00b204e9800998ecf8427e"
SHA1_TEST_VECTOR = "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def test_md5_empty():
    assert hashlib.md5(b"").hexdigest() == MD5_TEST_VECTOR


def test_sha1_empty():
    assert hashlib.sha1(b"").hexdigest() == SHA1_TEST_VECTOR
