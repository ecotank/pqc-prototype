package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

type RSAKeyPairResult struct {
	Algorithm       string  `json:"algorithm"`
	KeyBits         int     `json:"key_bits"`
	PublicKeyHex    string  `json:"public_key_hex"`
	PublicKeyBase64 string  `json:"public_key_base64"`
	PrivateKeyHex   string  `json:"private_key_hex"`
	PrivateKeyBase64 string `json:"private_key_base64"`
	PublicKeyBytes  int     `json:"public_key_bytes"`
	PrivateKeyBytes int     `json:"private_key_bytes"`
	GenDurationMs   float64 `json:"gen_duration_ms"`
}

func GenerateRSAKeyPair(bits int) (*RSAKeyPairResult, error) {
	if bits != 2048 && bits != 3072 && bits != 4096 {
		bits = 2048
	}

	start := time.Now()
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	duration := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("gagal membangkitkan kunci RSA-%d: %w", bits, err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)

	algName := fmt.Sprintf("RSA-%d", bits)
	return &RSAKeyPairResult{
		Algorithm:       algName,
		KeyBits:         bits,
		PublicKeyHex:    hex.EncodeToString(pubKeyBytes),
		PublicKeyBase64: base64.StdEncoding.EncodeToString(pubKeyBytes),
		PrivateKeyHex:   hex.EncodeToString(privKeyBytes),
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(privKeyBytes),
		PublicKeyBytes:  len(pubKeyBytes),
		PrivateKeyBytes: len(privKeyBytes),
		GenDurationMs:   float64(duration.Microseconds()) / 1000.0,
	}, nil
}

type RSASignResult struct {
	Algorithm       string  `json:"algorithm"`
	SignatureHex    string  `json:"signature_hex"`
	SignatureBase64 string  `json:"signature_base64"`
	SignatureBytes  int     `json:"signature_bytes"`
	SignDurationMs  float64 `json:"sign_duration_ms"`
	TargetCompliant bool    `json:"target_compliant"` // =< 2000 ms
	DigestAlgorithm string  `json:"digest_algorithm"`
	DigestHex       string  `json:"digest_hex"`
}

func SignRSA(privKeyBytes []byte, message []byte, hashType string) (*RSASignResult, error) {
	privKey, err := x509.ParsePKCS1PrivateKey(privKeyBytes)
	if err != nil {
		// coba parse PKCS8 jika bukan PKCS1
		keyInterface, err2 := x509.ParsePKCS8PrivateKey(privKeyBytes)
		if err2 != nil {
			return nil, fmt.Errorf("gagal parse RSA private key: %v / %v", err, err2)
		}
		var ok bool
		privKey, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("kunci bukan RSA private key")
		}
	}

	var h crypto.Hash
	var digest []byte
	hashUpper := strings.ToUpper(strings.TrimSpace(hashType))
	if hashUpper == "SHA-512" || hashUpper == "SHA512" {
		h = crypto.SHA512
		d := sha512.Sum512(message)
		digest = d[:]
	} else {
		h = crypto.SHA256
		d := sha256.Sum256(message)
		digest = d[:]
	}

	start := time.Now()
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, h, digest)
	duration := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("gagal menandatangani RSA: %w", err)
	}

	durMs := float64(duration.Microseconds()) / 1000.0
	bits := privKey.N.BitLen()

	return &RSASignResult{
		Algorithm:       fmt.Sprintf("RSA-%d", bits),
		SignatureHex:    hex.EncodeToString(sig),
		SignatureBase64: base64.StdEncoding.EncodeToString(sig),
		SignatureBytes:  len(sig),
		SignDurationMs:  durMs,
		TargetCompliant: durMs <= 2000.0,
		DigestAlgorithm: h.String(),
		DigestHex:       hex.EncodeToString(digest),
	}, nil
}

func VerifyRSA(pubKeyBytes []byte, message []byte, sigBytes []byte, hashType string) (*VerifyResult, error) {
	pubInterface, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return &VerifyResult{
			Valid:     false,
			Algorithm: "RSA",
			Reason:    fmt.Sprintf("Format Public Key RSA tidak valid: %v", err),
		}, nil
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return &VerifyResult{
			Valid:     false,
			Algorithm: "RSA",
			Reason:    "Kunci publik bukan bertipe RSA",
		}, nil
	}

	var h crypto.Hash
	var digest []byte
	hashUpper := strings.ToUpper(strings.TrimSpace(hashType))
	if hashUpper == "SHA-512" || hashUpper == "SHA512" {
		h = crypto.SHA512
		d := sha512.Sum512(message)
		digest = d[:]
	} else {
		h = crypto.SHA256
		d := sha256.Sum256(message)
		digest = d[:]
	}

	start := time.Now()
	err = rsa.VerifyPKCS1v15(pubKey, h, digest, sigBytes)
	duration := time.Since(start)

	durMs := float64(duration.Microseconds()) / 1000.0
	bits := pubKey.N.BitLen()
	algName := fmt.Sprintf("RSA-%d", bits)

	if err != nil {
		return &VerifyResult{
			Valid:            false,
			Algorithm:        algName,
			VerifyDurationMs: durMs,
			Reason:           "Tanda tangan RSA TIDAK SAH: data telah dimodifikasi atau tanda tangan rusak",
			FIPS204Compliant: false,
		}, nil
	}

	return &VerifyResult{
		Valid:            true,
		Algorithm:        algName,
		VerifyDurationMs: durMs,
		Reason:           "Tanda tangan RSA sah dan terverifikasi",
		FIPS204Compliant: false,
	}, nil
}
