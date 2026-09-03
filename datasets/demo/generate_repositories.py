#!/usr/bin/env python3
"""Generate the ECDAT demo enterprise estate.

Deliberately a GENERATOR rather than committed files: it keeps the demo dataset
auditable in one place and makes the seeded cryptography explicit. Every finding a
judge sees in the UI traces back to a line written here.

The estate is synthetic but the code is real and really parsed -- the Python files
are valid ASTs, the configs are valid directives, the manifests are valid.

Seeded deliberately:
  * quantum-vulnerable key establishment on long-retention internet-facing systems
  * quantum-vulnerable signatures with and without evidenced roles
  * classically broken primitives (MD5, SHA-1, 3DES, RC4, RSA-1024)
  * already-migrated PQC/hybrid assets (so RETAIN is demonstrable)
  * false-positive candidates (MD5 for cache keys, crypto words in comments/tests)
  * an RSA key generated but never used -> role UNKNOWN by design
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent / "repositories"

FILES: dict[str, str] = {}


def add(path: str, body: str) -> None:
    FILES[path] = body.lstrip("\n")


# ======================================================================================
# 1. Government Citizen Portal -- Python, internet-facing, 10-year retention
# ======================================================================================
add("citizen-portal/app/auth.py", '''
"""Citizen authentication: session tokens and document signing."""
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SESSION_KEY_BITS = 2048


def load_signing_key(path: str):
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def issue_document_signature(key, document: bytes) -> bytes:
    """Sign a citizen document. Signature must remain verifiable for 10 years."""
    return key.sign(
        document,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


def rotate_signing_key():
    # Role is evidenced by the .sign() call below -> DIGITAL_SIGNATURE
    key = rsa.generate_private_key(public_exponent=65537, key_size=SESSION_KEY_BITS)
    key.sign(b"self-test", padding.PKCS1v15(), hashes.SHA256())
    return key


def session_tag(session_id: str, secret: bytes) -> str:
    return hmac.new(secret, session_id.encode(), digestmod=hashlib.sha256).hexdigest()


def document_cache_key(blob: bytes) -> str:
    # Non-security use: cache key only, not an integrity control.
    return hashlib.md5(blob).hexdigest()
''')

add("citizen-portal/app/storage.py", '''
"""Encrypted document storage for citizen records."""
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RECORD_KEY = os.urandom(32)  # 256-bit


def seal_record(plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, AESGCM(RECORD_KEY).encrypt(nonce, plaintext, aad)


def open_record(nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(RECORD_KEY).decrypt(nonce, ciphertext, aad)
''')

add("citizen-portal/deploy/nginx.conf", '''
server {
    listen 443 ssl;
    server_name portal.gov.example.in;

    ssl_certificate     /etc/ssl/certs/citizen-portal.crt;
    ssl_certificate_key /etc/ssl/private/citizen-portal.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:AES256-SHA;
    ssl_ecdh_curve secp384r1:prime256v1;
    ssl_prefer_server_ciphers on;
}
''')

add("citizen-portal/requirements.txt", '''
cryptography==41.0.7
pyopenssl==23.2.0
requests==2.31.0
gunicorn==21.2.0
''')

add("citizen-portal/Dockerfile", '''
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \\
        openssl=3.0.11-1 libssl3 ca-certificates \\
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ /srv/app/
COPY certs/citizen-portal.crt /etc/ssl/certs/
CMD ["gunicorn", "--bind", "0.0.0.0:8443", "app.main:app"]
''')

# ======================================================================================
# 2. National Identity Service -- Java, mission critical, 20-year retention
# ======================================================================================
add("identity-service/src/main/java/gov/id/TokenSigner.java", '''
package gov.id;

import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

/** Signs identity assertions. Assertions are archived for 20 years. */
public class TokenSigner {

    private static final int KEY_BITS = 4096;

    public byte[] signAssertion(byte[] assertion, java.security.PrivateKey key)
            throws Exception {
        Signature signer = Signature.getInstance("SHA384withRSA");
        signer.initSign(key);
        signer.update(assertion);
        return signer.sign();
    }

    public java.security.KeyPair generateIdentityKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(KEY_BITS);
        return gen.generateKeyPair();
    }

    public byte[] digest(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-384").digest(data);
    }

    public Cipher recordCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    public KeyAgreement peerAgreement() throws Exception {
        return KeyAgreement.getInstance("ECDH");
    }
}
''')

add("identity-service/src/main/resources/application.properties", '''
server.port=8443
server.ssl.enabled=true
server.ssl.key-store=classpath:identity.p12
server.ssl.key-store-type=PKCS12
server.ssl.protocol=TLS
server.ssl.enabled-protocols=TLSv1.2,TLSv1.3
server.ssl.ciphers=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
identity.retention.years=20
''')

add("identity-service/pom.xml", '''
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>gov.id</groupId>
  <artifactId>identity-service</artifactId>
  <version>3.4.1</version>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.77</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
      <version>3.2.0</version>
    </dependency>
  </dependencies>
</project>
''')

# ======================================================================================
# 3. Payment API -- Python, RSA key transport (the KEM restructuring case)
# ======================================================================================
add("payment-api/src/tls_config.py", '''
"""TLS and card-data protection for the payment authorisation service."""
import os
import ssl

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PAN_KEY = os.urandom(16)  # 128-bit -- below the 256-bit policy floor


def build_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ctx.load_cert_chain("certs/payment-gateway.crt", "certs/payment-gateway.key")
    return ctx


def wrap_data_key(recipient_public_key, data_key: bytes) -> bytes:
    """RSA-OAEP key transport -> requires a KEM to migrate, not a cipher swap."""
    return recipient_public_key.encrypt(
        data_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_data_key(private_key, wrapped: bytes) -> bytes:
    return private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def encrypt_pan(pan: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, AESGCM(PAN_KEY).encrypt(nonce, pan, b"pan-v1")
''')

add("payment-api/src/keys.py", '''
"""Key custody helpers."""
from cryptography.hazmat.primitives.asymmetric import rsa


def provision_escrow_key():
    """Generated and handed to the HSM operator.

    ECDAT observes no sign/verify/encrypt/decrypt call on this object, so the
    cryptographic role is reported as UNKNOWN rather than guessed.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key
''')

add("payment-api/requirements.txt", '''
cryptography==3.4.8
pycryptodome==3.19.0
flask==3.0.0
''')

# ======================================================================================
# 4. Secure File Exchange -- Go, ECDH + ECDSA, already on TLS 1.3
# ======================================================================================
add("file-exchange/transfer.go", '''
package transfer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
)

// NegotiateSession performs ECDH key agreement with the peer.
func NegotiateSession(peer []byte) ([]byte, error) {
	curve := ecdh.P256()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	remote, err := curve.NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(remote)
}

// SealChunk encrypts one file chunk with AES-256-GCM.
func SealChunk(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

// SignManifest signs the transfer manifest with ECDSA P-256.
func SignManifest(priv *ecdsa.PrivateKey, manifest []byte) ([]byte, error) {
	sum := sha256.Sum256(manifest)
	return ecdsa.SignASN1(rand.Reader, priv, sum[:])
}

func TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768,
			tls.CurveP256,
		},
	}
}

var _ = elliptic.P256
''')

add("file-exchange/go.mod", '''
module gov.example.in/file-exchange

go 1.24

require (
	golang.org/x/crypto v0.31.0
	github.com/rs/zerolog v1.32.0
)
''')

# ======================================================================================
# 5. Legacy Java Enterprise Portal -- the classical-weakness showcase
# ======================================================================================
add("legacy-portal/src/com/legacy/CryptoUtil.java", '''
package com.legacy;

import java.security.MessageDigest;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import javax.crypto.Mac;

/**
 * Legacy crypto helper. Written in 2009, still deployed.
 * TODO: migrate away from DESede and SHA-1.
 */
public class CryptoUtil {

    public static byte[] legacyEncrypt(byte[] data, javax.crypto.SecretKey k)
            throws Exception {
        Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(data);
    }

    public static String passwordHash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(password.getBytes()));
    }

    public static byte[] documentDigest(byte[] doc) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(doc);
    }

    public static java.security.KeyPair weakKeyPair() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(1024);
        return g.generateKeyPair();
    }

    public static Mac legacyMac() throws Exception {
        return Mac.getInstance("HmacSHA1");
    }
}
''')

add("legacy-portal/conf/server.xml", '''
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true"
               sslProtocol="TLS"
               sslEnabledProtocols="TLSv1,TLSv1.1,TLSv1.2"
               ciphers="SSL_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,SSL_RSA_WITH_RC4_128_MD5"
               keystoreFile="conf/legacy.jks"
               keystorePass="changeit" />
  </Service>
</Server>
''')

add("legacy-portal/build.gradle", '''
dependencies {
    implementation 'org.bouncycastle:bcprov-jdk15on:1.58'
    implementation 'commons-codec:commons-codec:1.11'
    implementation 'org.apache.httpcomponents:httpclient:4.5.13'
}
''')

# ======================================================================================
# 6. Python Intelligence API -- modern primitives, high sensitivity
# ======================================================================================
add("intel-api/service/channel.py", '''
"""Analyst channel: modern primitives, 25-year classification lifetime."""
import os

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def establish_channel(peer_public):
    """X25519 key agreement -- classically strong, Shor-vulnerable."""
    private = x25519.X25519PrivateKey.generate()
    shared = private.exchange(peer_public)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"analyst-channel-v2").derive(shared)


def sign_report(report: bytes):
    key = ed25519.Ed25519PrivateKey.generate()
    return key.sign(report)


def verify_report(public_key, signature: bytes, report: bytes) -> bool:
    public_key.verify(signature, report)
    return True


def seal(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
''')

add("intel-api/tests/test_vectors.py", '''
"""Known-answer tests. These reference weak algorithms deliberately as test
vectors -- ECDAT should flag them LOW confidence / test-path, not as findings."""
import hashlib

MD5_TEST_VECTOR = "d41d8cd98f00b204e9800998ecf8427e"
SHA1_TEST_VECTOR = "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def test_md5_empty():
    assert hashlib.md5(b"").hexdigest() == MD5_TEST_VECTOR


def test_sha1_empty():
    assert hashlib.sha1(b"").hexdigest() == SHA1_TEST_VECTOR
''')

add("intel-api/requirements.txt", '''
cryptography==42.0.5
fastapi==0.109.0
uvicorn==0.27.0
''')

# ======================================================================================
# 7. Node.js Microservice -- notification fan-out
# ======================================================================================
add("notify-service/src/crypto.js", '''
'use strict';
const crypto = require('crypto');

// AES-256-GCM for payload confidentiality.
function sealPayload(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, enc, tag: cipher.getAuthTag() };
}

// Webhook authentication tag.
function webhookSignature(secret, body) {
  return crypto.createHmac('sha256', secret).update(body).digest('hex');
}

// Deduplication only -- NOT a security control.
function dedupeKey(message) {
  return crypto.createHash('md5').update(message).digest('hex');
}

// RSA-2048 signing for partner callbacks.
function signCallback(privateKey, payload) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(payload);
  return signer.sign(privateKey, 'base64');
}

module.exports = { sealPayload, webhookSignature, dedupeKey, signCallback };
''')

add("notify-service/package.json", '''
{
  "name": "notify-service",
  "version": "2.7.0",
  "dependencies": {
    "express": "4.18.2",
    "node-forge": "1.3.1",
    "jsonwebtoken": "9.0.2"
  },
  "devDependencies": {
    "jest": "29.7.0"
  }
}
''')

# ======================================================================================
# 8. Kubernetes platform -- already migrated to a PQ/T hybrid (RETAIN demo)
# ======================================================================================
add("k8s-platform/manifests/ingress.yaml", '''
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: apps-ingress
  namespace: platform
spec:
  tls:
    - hosts:
        - "*.apps.k8s.example.in"
      secretName: kube-ingress-tls
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: edge-proxy
spec:
  template:
    spec:
      containers:
        - name: edge-proxy
          image: envoyproxy/envoy:v1.29.1
''')

add("k8s-platform/config/envoy-tls.yaml", '''
tls_context:
  common_tls_context:
    tls_params:
      tls_minimum_protocol_version: TLSv1_3
      cipher_suites: ECDHE-ECDSA-AES256-GCM-SHA384
    supported_groups: X25519MLKEM768:X25519:secp384r1
''')

add("k8s-platform/Dockerfile", '''
FROM envoyproxy/envoy:v1.29.1
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 \\
    && rm -rf /var/lib/apt/lists/*
COPY config/envoy-tls.yaml /etc/envoy/
''')

# ======================================================================================
# 9. VPN Gateway -- config + the compiled binary in datasets/demo/binaries
# ======================================================================================
add("vpn-gateway/etc/sshd_config", '''
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,diffie-hellman-group14-sha1
Ciphers aes256-gcm@openssh.com,aes128-ctr
MACs hmac-sha2-256,hmac-sha1
PubkeyAuthentication yes
PasswordAuthentication no
''')

add("vpn-gateway/etc/ipsec.conf", '''
config setup
    charondebug="ike 1, knl 1"

conn site-to-site
    ikeVersion=2
    ike=aes256-sha256-modp2048
    esp=aes256gcm16-modp2048
    keyexchange=ikev2
    left=203.0.113.7
    leftcert=vpn-gateway-p384.crt
    right=198.51.100.20
    auth=pubkey
''')

# ======================================================================================
# 10. Internal HR -- low criticality, weak-but-internal
# ======================================================================================
add("internal-hr/hr/payroll.py", '''
"""Payroll export. Internal only, 7-year statutory retention."""
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

EXPORT_KEY = os.urandom(16)


def encrypt_export(data: bytes, iv: bytes) -> bytes:
    """AES-128-CBC -- below policy floor and an unauthenticated mode."""
    cipher = Cipher(algorithms.AES(EXPORT_KEY), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def employee_ref(employee_id: str) -> str:
    # SHA-1 used as an identifier, not a security control.
    return hashlib.sha1(employee_id.encode()).hexdigest()[:12]
''')

add("internal-hr/requirements.txt", '''
cryptography==38.0.4
pandas==2.1.4
''')

# ======================================================================================
# 11. Certificate Authority tooling
# ======================================================================================
add("pki-authority/openssl.cnf", '''
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = /srv/pki
certificate       = $dir/root-ca.crt
private_key       = $dir/private/root-ca.key
default_md        = sha384
default_days      = 730
policy            = policy_strict

[ policy_strict ]
countryName             = match
organizationName        = match
commonName              = supplied

[ req ]
default_bits        = 4096
default_md          = sha384
distinguished_name  = req_distinguished_name

[ req_distinguished_name ]
countryName = Country Name
organizationName = Organization Name
commonName = Common Name
''')

add("pki-authority/issue.sh", '''
#!/bin/sh
# Issue a server certificate from the intermediate CA.
set -eu
openssl req -new -newkey rsa:3072 -nodes -keyout "$1.key" -out "$1.csr" -subj "$2"
openssl x509 -req -in "$1.csr" -CA intermediate-ca.crt -CAkey intermediate-ca.key \\
    -sha384 -days 730 -out "$1.crt"
''')

# ======================================================================================
# 12. A deliberate false-positive minefield
# ======================================================================================
add("docs-site/content/security-overview.md", '''
# Security Overview

Our platform historically used MD5 and SHA-1 for checksums. We have since moved to
SHA-256. Older RSA-1024 certificates were retired in 2019. The DES and 3DES
ciphers referenced in appendix B are documentation of legacy peers only.

Planned work references Kyber and Dilithium (now standardised as ML-KEM and
ML-DSA respectively).
''')

add("docs-site/examples/sample-config.txt", '''
# EXAMPLE ONLY -- placeholder values, not a deployed configuration
ssl_protocols TLSv1.0;
ssl_ciphers RC4-MD5:DES-CBC3-SHA;
''')


def main() -> int:
    written = 0
    for rel, body in FILES.items():
        target = ROOT / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
        written += 1
    # Make the shell script look like a real executable to the scanner.
    sh = ROOT / "pki-authority" / "issue.sh"
    if sh.exists():
        sh.chmod(0o755)
    repos = sorted({p.split("/")[0] for p in FILES})
    print(f"wrote {written} files across {len(repos)} repositories:")
    for r in repos:
        n = sum(1 for p in FILES if p.startswith(r + "/"))
        print(f"  {r:20} {n} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
