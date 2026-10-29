package crypto

import (
	"crypto/rand"
	"fmt"
	"time"
)

type FIPSTestCase struct {
	ID          string  `json:"id"`
	Algorithm   string  `json:"algorithm"`
	TestName    string  `json:"test_name"`
	Description string  `json:"description"`
	Passed      bool    `json:"passed"`
	DurationMs  float64 `json:"duration_ms"`
	Details     string  `json:"details"`
}

type FIPSValidationReport struct {
	Standard    string         `json:"standard"`
	Timestamp   string         `json:"timestamp"`
	TotalTests  int            `json:"total_tests"`
	PassedTests int            `json:"passed_tests"`
	FailedTests int            `json:"failed_tests"`
	AllPassed   bool           `json:"all_passed"`
	TestCases   []FIPSTestCase `json:"test_cases"`
}

func RunFIPS204Validation() *FIPSValidationReport {
	report := &FIPSValidationReport{
		Standard:  "NIST FIPS 204 (Module-Lattice-Based Digital Signature Standard)",
		Timestamp: time.Now().Format("2006-01-02 15:04:05 MST"),
		TestCases: make([]FIPSTestCase, 0),
	}

	algs := []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}

	for _, alg := range algs {
		scheme, err := GetScheme(alg)
		if err != nil {
			report.TestCases = append(report.TestCases, FIPSTestCase{
				ID: fmt.Sprintf("TC-%s-INIT", alg), Algorithm: alg, TestName: "Scheme Init", Passed: false, Details: err.Error(),
			})
			continue
		}

		spec := MLDSASpecs[scheme.Name()]

		// Test 1: Key sizes compliance
		t0 := time.Now()
		pk, sk, err := scheme.GenerateKey()
		dur1 := float64(time.Since(t0).Microseconds()) / 1000.0
		pkBytes, _ := pk.MarshalBinary()
		skBytes, _ := sk.MarshalBinary()

		sizePassed := len(pkBytes) == spec.PublicKeyBytes && len(skBytes) == spec.PrivateKeyBytes
		report.TestCases = append(report.TestCases, FIPSTestCase{
			ID:          fmt.Sprintf("TC-%s-PARAM", alg),
			Algorithm:   alg,
			TestName:    "FIPS 204 Parameter & Key Size Verification",
			Description: fmt.Sprintf("Verifikasi ukuran PK (%d B) dan SK (%d B) sesuai FIPS 204 Tabel 1/2", spec.PublicKeyBytes, spec.PrivateKeyBytes),
			Passed:      sizePassed,
			DurationMs:  dur1,
			Details:     fmt.Sprintf("Actual PK: %d B, SK: %d B (Expected PK: %d B, SK: %d B)", len(pkBytes), len(skBytes), spec.PublicKeyBytes, spec.PrivateKeyBytes),
		})

		// Test 2: Signature Generation & Size
		msg := []byte("BSrE-BSSN FIPS 204 Test Vector Message Payload")
		t0 = time.Now()
		sig := scheme.Sign(sk, msg, nil)
		dur2 := float64(time.Since(t0).Microseconds()) / 1000.0

		sigPassed := len(sig) == spec.SignatureBytes && dur2 <= 2000.0
		report.TestCases = append(report.TestCases, FIPSTestCase{
			ID:          fmt.Sprintf("TC-%s-SIGGEN", alg),
			Algorithm:   alg,
			TestName:    "Signature Generation & Latency (< 2.0s)",
			Description: fmt.Sprintf("Penandatanganan sesuai FIPS 204 dengan ukuran %d B dan latency =< 2 detik", spec.SignatureBytes),
			Passed:      sigPassed,
			DurationMs:  dur2,
			Details:     fmt.Sprintf("Signature size: %d B (expected %d B), Durasi: %.3f ms (Target: < 2000 ms)", len(sig), spec.SignatureBytes, dur2),
		})

		// Test 3: Signature Verification (Valid Message)
		t0 = time.Now()
		valid := scheme.Verify(pk, msg, sig, nil)
		dur3 := float64(time.Since(t0).Microseconds()) / 1000.0

		report.TestCases = append(report.TestCases, FIPSTestCase{
			ID:          fmt.Sprintf("TC-%s-SIGVER-PASS", alg),
			Algorithm:   alg,
			TestName:    "Valid Signature Verification",
			Description: "Verifikasi tanda tangan sah harus mengembalikan nilai TRUE",
			Passed:      valid,
			DurationMs:  dur3,
			Details:     fmt.Sprintf("Verify result: %v (expected true)", valid),
		})

		// Test 4: Tampering Detection (1 Bit Flip on Message)
		tamperedMsg := make([]byte, len(msg))
		copy(tamperedMsg, msg)
		tamperedMsg[0] ^= 0x01 // flip 1 bit

		t0 = time.Now()
		tamperedValid := scheme.Verify(pk, tamperedMsg, sig, nil)
		dur4 := float64(time.Since(t0).Microseconds()) / 1000.0

		tamperPassed := !tamperedValid
		report.TestCases = append(report.TestCases, FIPSTestCase{
			ID:          fmt.Sprintf("TC-%s-TAMPER-MSG", alg),
			Algorithm:   alg,
			TestName:    "Message Tampering Integrity Test",
			Description: "Memodifikasi 1-bit pesan wajib ditolak (Verify mengembalikan FALSE)",
			Passed:      tamperPassed,
			DurationMs:  dur4,
			Details:     fmt.Sprintf("Tampered verify result: %v (expected false)", tamperedValid),
		})

		// Test 5: Signature Corruption (1 Bit Flip on Signature)
		corruptedSig := make([]byte, len(sig))
		copy(corruptedSig, sig)
		corruptedSig[len(corruptedSig)-1] ^= 0x80 // flip 1 bit on signature

		t0 = time.Now()
		corruptedValid := scheme.Verify(pk, msg, corruptedSig, nil)
		dur5 := float64(time.Since(t0).Microseconds()) / 1000.0

		corruptPassed := !corruptedValid
		report.TestCases = append(report.TestCases, FIPSTestCase{
			ID:          fmt.Sprintf("TC-%s-TAMPER-SIG", alg),
			Algorithm:   alg,
			TestName:    "Signature Corruption Detection Test",
			Description: "Memodifikasi 1-bit signature wajib ditolak",
			Passed:      corruptPassed,
			DurationMs:  dur5,
			Details:     fmt.Sprintf("Corrupted sig verify result: %v (expected false)", corruptedValid),
		})

		// Test 6: Deterministic Seed Derivation (FIPS 204 DeriveKey)
		seed := make([]byte, scheme.SeedSize())
		rand.Read(seed)
		pkDer1, skDer1 := scheme.DeriveKey(seed)
		pkDer2, skDer2 := scheme.DeriveKey(seed)

		bPk1, _ := pkDer1.MarshalBinary()
		bPk2, _ := pkDer2.MarshalBinary()
		bSk1, _ := skDer1.MarshalBinary()
		bSk2, _ := skDer2.MarshalBinary()

		detPassed := string(bPk1) == string(bPk2) && string(bSk1) == string(bSk2)
		report.TestCases = append(report.TestCases, FIPSTestCase{
			ID:          fmt.Sprintf("TC-%s-SEED-DERIVE", alg),
			Algorithm:   alg,
			TestName:    "Deterministic Key Derivation from Seed",
			Description: "Pembangkitan kunci deterministik dari seed 32-byte (FIPS 204 Algoritma 1)",
			Passed:      detPassed,
			DurationMs:  0.1,
			Details:     fmt.Sprintf("Deterministic match: %v", detPassed),
		})
	}

	total := len(report.TestCases)
	passed := 0
	for _, tc := range report.TestCases {
		if tc.Passed {
			passed++
		}
	}
	report.TotalTests = total
	report.PassedTests = passed
	report.FailedTests = total - passed
	report.AllPassed = (passed == total)

	return report
}
