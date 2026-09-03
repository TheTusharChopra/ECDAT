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
