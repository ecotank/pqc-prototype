// Package crypto menyediakan primitif tanda tangan digital pascakuantum (Post-Quantum Cryptography)
// berbasis Module-Lattice-Based Digital Signature Algorithm (ML-DSA) sesuai standar resmi NIST FIPS 204
// serta algoritma pembanding klasik RSA (PKCS #1 v1.5) untuk kebutuhan purwarupa TTE BSrE BSSN.
package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// AlgorithmParams mendefinisikan parameter matematis skema ML-DSA sesuai FIPS 204.
type AlgorithmParams struct {
	Name             string `json:"name"`              // Nama resmi varian ML-DSA (44, 65, 87)
	SecurityCategory int    `json:"security_category"` // Kategori keamanan NIST (Level 2, 3, 5)
	NistStandard     string `json:"nist_standard"`     // Rujukan dokumen standar (NIST FIPS 204)
	MatrixK          int    `json:"matrix_k"`          // Dimensi baris matriks lattice k
	MatrixL          int    `json:"matrix_l"`          // Dimensi kolom matriks lattice l
	ModulusQ         int    `json:"modulus_q"`         // Modulus bilangan prima q = 8.380.417
	PublicKeyBytes   int    `json:"public_key_bytes"`  // Ukuran kunci publik baku dalam byte
	PrivateKeyBytes  int    `json:"private_key_bytes"` // Ukuran kunci privat baku dalam byte
	SignatureBytes   int    `json:"signature_bytes"`   // Ukuran tanda tangan baku dalam byte
	Description      string `json:"description"`       // Rekomendasi penggunaan pada ekosistem BSrE
}

// MLDSASpecs memetakan parameter resmi FIPS 204 untuk seluruh varian parameter set.
var MLDSASpecs = map[string]AlgorithmParams{
	"ML-DSA-44": {
		Name:             "ML-DSA-44",
		SecurityCategory: 2,
		NistStandard:     "NIST FIPS 204",
		MatrixK:          4,
		MatrixL:          4,
		ModulusQ:         8380417,
		PublicKeyBytes:   1312,
		PrivateKeyBytes:  2560,
		SignatureBytes:   2420,
		Description:      "NIST Kategori 2 (Setara SHA-256 / AES-128)",
	},
	"ML-DSA-65": {
		Name:             "ML-DSA-65",
		SecurityCategory: 3,
		NistStandard:     "NIST FIPS 204",
		MatrixK:          6,
		MatrixL:          5,
		ModulusQ:         8380417,
		PublicKeyBytes:   1952,
		PrivateKeyBytes:  4032,
		SignatureBytes:   3309,
		Description:      "NIST Kategori 3 (Setara AES-192, Direkomendasikan BSrE untuk End-Entity)",
	},
	"ML-DSA-87": {
		Name:             "ML-DSA-87",
		SecurityCategory: 5,
		NistStandard:     "NIST FIPS 204",
		MatrixK:          8,
		MatrixL:          7,
		ModulusQ:         8380417,
		PublicKeyBytes:   2592,
		PrivateKeyBytes:  4896,
		SignatureBytes:   4627,
		Description:      "NIST Kategori 5 (Setara AES-256, Direkomendasikan untuk Root CA)",
	},
}

// GetScheme mengembalikan interface Scheme CIRCL berdasarkan string algoritma.
func GetScheme(alg string) (sign.Scheme, error) {
	switch strings.ToUpper(strings.TrimSpace(alg)) {
	case "ML-DSA-44", "MLDSA44", "44":
		return mldsa44.Scheme(), nil
	case "ML-DSA-65", "MLDSA65", "65":
		return mldsa65.Scheme(), nil
	case "ML-DSA-87", "MLDSA87", "87":
		return mldsa87.Scheme(), nil
	default:
		return nil, fmt.Errorf("algoritma ML-DSA tidak dikenal: %s (pilihan: ML-DSA-44, ML-DSA-65, ML-DSA-87)", alg)
	}
}

// KeyPairResult merepresentasikan pasangan kunci publik dan privat hasil pembangkitan.
type KeyPairResult struct {
	Algorithm        string          `json:"algorithm"`
	PublicKeyHex     string          `json:"public_key_hex"`
	PublicKeyBase64  string          `json:"public_key_base64"`
	PrivateKeyHex    string          `json:"private_key_hex"`
	PrivateKeyBase64 string          `json:"private_key_base64"`
	PublicKeyBytes   int             `json:"public_key_bytes"`
	PrivateKeyBytes  int             `json:"private_key_bytes"`
	GenDurationMs    float64         `json:"gen_duration_ms"`
	Params           AlgorithmParams `json:"params"`
}

// GenerateMLDSAKeyPair membangkitkan pasangan kunci ML-DSA sesuai algoritma yang diminta.
func GenerateMLDSAKeyPair(alg string) (*KeyPairResult, error) {
	scheme, err := GetScheme(alg)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	pk, sk, err := scheme.GenerateKey()
	duration := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("gagal membangkitkan kunci %s: %w", alg, err)
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, err
	}

	stdAlg := scheme.Name()
	return &KeyPairResult{
		Algorithm:        stdAlg,
		PublicKeyHex:     hex.EncodeToString(pkBytes),
		PublicKeyBase64:  base64.StdEncoding.EncodeToString(pkBytes),
		PrivateKeyHex:    hex.EncodeToString(skBytes),
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(skBytes),
		PublicKeyBytes:   len(pkBytes),
		PrivateKeyBytes:  len(skBytes),
		GenDurationMs:    float64(duration.Microseconds()) / 1000.0,
		Params:           MLDSASpecs[stdAlg],
	}, nil
}

// SignResult merepresentasikan keluaran hasil penandatanganan ML-DSA.
type SignResult struct {
	Algorithm        string  `json:"algorithm"`
	SignatureHex     string  `json:"signature_hex"`
	SignatureBase64  string  `json:"signature_base64"`
	SignatureBytes   int     `json:"signature_bytes"`
	SignDurationMs   float64 `json:"sign_duration_ms"`
	TargetCompliant  bool    `json:"target_compliant"`  // Memenuhi target =< 2.000 ms (2 detik)
	FIPS204Compliant bool    `json:"fips204_compliant"` // Memenuhi spesifikasi NIST FIPS 204
	MessageHash      string  `json:"message_hash"`
}

// SignMLDSA menandatangani pesan atau nilai digest hash menggunakan kunci privat ML-DSA.
func SignMLDSA(alg string, privKeyBytes []byte, message []byte) (*SignResult, error) {
	scheme, err := GetScheme(alg)
	if err != nil {
		return nil, err
	}

	sk, err := scheme.UnmarshalBinaryPrivateKey(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("gagal unmarshal private key %s: %w", alg, err)
	}

	start := time.Now()
	sig := scheme.Sign(sk, message, nil)
	duration := time.Since(start)

	durMs := float64(duration.Microseconds()) / 1000.0
	isCompliant := durMs <= 2000.0 // target =< 2 detik

	return &SignResult{
		Algorithm:        scheme.Name(),
		SignatureHex:     hex.EncodeToString(sig),
		SignatureBase64:  base64.StdEncoding.EncodeToString(sig),
		SignatureBytes:   len(sig),
		SignDurationMs:   durMs,
		TargetCompliant:  isCompliant,
		FIPS204Compliant: true,
		MessageHash:      hex.EncodeToString(message),
	}, nil
}

// VerifyResult merepresentasikan status keabsahan dan rincian verifikasi tanda tangan.
type VerifyResult struct {
	Valid            bool    `json:"valid"`
	Algorithm        string  `json:"algorithm"`
	VerifyDurationMs float64 `json:"verify_duration_ms"`
	Reason           string  `json:"reason"`
	FIPS204Compliant bool    `json:"fips204_compliant"`
}

// VerifyMLDSA memverifikasi integritas pesan dan keabsahan tanda tangan terhadap kunci publik ML-DSA.
func VerifyMLDSA(alg string, pubKeyBytes []byte, message []byte, sigBytes []byte) (*VerifyResult, error) {
	scheme, err := GetScheme(alg)
	if err != nil {
		return nil, err
	}

	pk, err := scheme.UnmarshalBinaryPublicKey(pubKeyBytes)
	if err != nil {
		return &VerifyResult{
			Valid:            false,
			Algorithm:        alg,
			Reason:           fmt.Sprintf("Format Public Key tidak valid: %v", err),
			FIPS204Compliant: false,
		}, nil
	}

	expectedSigLen := scheme.SignatureSize()
	if len(sigBytes) != expectedSigLen {
		return &VerifyResult{
			Valid:            false,
			Algorithm:        scheme.Name(),
			Reason:           fmt.Sprintf("Ukuran tanda tangan (%d byte) tidak sesuai spesifikasi FIPS 204 (%d byte)", len(sigBytes), expectedSigLen),
			FIPS204Compliant: false,
		}, nil
	}

	start := time.Now()
	valid := scheme.Verify(pk, message, sigBytes, nil)
	duration := time.Since(start)

	durMs := float64(duration.Microseconds()) / 1000.0
	reason := "Tanda tangan sah dan terverifikasi sesuai spesifikasi FIPS 204"
	if !valid {
		reason = "Tanda tangan TIDAK SAH: data telah diubah, kunci publik tidak cocok, atau tanda tangan rusak"
	}

	return &VerifyResult{
		Valid:            valid,
		Algorithm:        scheme.Name(),
		VerifyDurationMs: durMs,
		Reason:           reason,
		FIPS204Compliant: true,
	}, nil
}

// DecodeHexOrBase64 mengurai string yang dikodekan dalam format Hexadecimal atau Base64 menjadi byte slice.
func DecodeHexOrBase64(input string) ([]byte, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return nil, errors.New("data kosong")
	}
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("format tidak valid, harus hex atau base64")
}
