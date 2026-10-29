package crypto

import (
	"fmt"
	"time"
)

type DualSignResult struct {
	Mode             string      `json:"mode"`
	MLDSAResult      *SignResult `json:"mldsa"`
	RSAResult        *RSASignResult `json:"rsa"`
	TotalDurationMs  float64     `json:"total_duration_ms"`
	TargetCompliant  bool        `json:"target_compliant"` // =< 2000 ms
	TotalSizeBytes   int         `json:"total_size_bytes"`
}

type DualVerifyResult struct {
	Mode             string        `json:"mode"`
	BothValid        bool          `json:"both_valid"`
	MLDSAVerification *VerifyResult `json:"mldsa_verification"`
	RSAVerification   *VerifyResult `json:"rsa_verification"`
	TotalDurationMs  float64       `json:"total_duration_ms"`
	Summary          string        `json:"summary"`
}

func SignDual(mldsaAlg string, mldsaSK []byte, rsaSK []byte, message []byte, hashType string) (*DualSignResult, error) {
	start := time.Now()

	mldsaRes, err := SignMLDSA(mldsaAlg, mldsaSK, message)
	if err != nil {
		return nil, fmt.Errorf("gagal menandatangani ML-DSA dalam skema dual: %w", err)
	}

	rsaRes, err := SignRSA(rsaSK, message, hashType)
	if err != nil {
		return nil, fmt.Errorf("gagal menandatangani RSA dalam skema dual: %w", err)
	}

	totalDur := time.Since(start)
	totalDurMs := float64(totalDur.Microseconds()) / 1000.0

	return &DualSignResult{
		Mode:            fmt.Sprintf("Dual Sign (%s + %s)", mldsaRes.Algorithm, rsaRes.Algorithm),
		MLDSAResult:     mldsaRes,
		RSAResult:       rsaRes,
		TotalDurationMs: totalDurMs,
		TargetCompliant: totalDurMs <= 2000.0,
		TotalSizeBytes:  mldsaRes.SignatureBytes + rsaRes.SignatureBytes,
	}, nil
}

func VerifyDual(mldsaAlg string, mldsaPK []byte, mldsaSig []byte, rsaPK []byte, rsaSig []byte, message []byte, hashType string) (*DualVerifyResult, error) {
	start := time.Now()

	mldsaVer, err := VerifyMLDSA(mldsaAlg, mldsaPK, message, mldsaSig)
	if err != nil {
		return nil, err
	}

	rsaVer, err := VerifyRSA(rsaPK, message, rsaSig, hashType)
	if err != nil {
		return nil, err
	}

	totalDur := time.Since(start)
	totalDurMs := float64(totalDur.Microseconds()) / 1000.0
	bothValid := mldsaVer.Valid && rsaVer.Valid

	var summary string
	if bothValid {
		summary = "Dual Verifikasi Berhasil: Tanda tangan klasik (RSA) dan pascakuantum (ML-DSA) keduanya SAH."
	} else if mldsaVer.Valid && !rsaVer.Valid {
		summary = "Dual Verifikasi Parsial: ML-DSA valid, tetapi RSA tidak valid."
	} else if !mldsaVer.Valid && rsaVer.Valid {
		summary = "Dual Verifikasi Parsial: RSA valid, tetapi ML-DSA tidak valid."
	} else {
		summary = "Dual Verifikasi Gagal: Baik RSA maupun ML-DSA tidak valid (data diubah atau tanda tangan rusak)."
	}

	return &DualVerifyResult{
		Mode:              "Dual Verification (RSA + ML-DSA)",
		BothValid:         bothValid,
		MLDSAVerification: mldsaVer,
		RSAVerification:   rsaVer,
		TotalDurationMs:   totalDurMs,
		Summary:           summary,
	}, nil
}
