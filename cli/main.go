package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"pqc-prototype/crypto"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "test-fips", "fips":
		runFIPSTest()
	case "benchmark", "bench":
		runBenchmark(os.Args[2:])
	case "keygen":
		runKeygen(os.Args[2:])
	case "sign":
		runSign(os.Args[2:])
	case "verify":
		runVerify(os.Args[2:])
	case "dual-sign":
		runDualSign(os.Args[2:])
	default:
		fmt.Printf("Perintah tidak dikenal: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("=====================================================================")
	fmt.Println(" CLI PURWARUPA PENANDATANGANAN PASCALATTICE ML-DSA (BSrE - BSSN)")
	fmt.Println(" Standar: NIST FIPS 204 | Target: Penandatanganan =< 2.0 Detik")
	fmt.Println("=====================================================================")
	fmt.Println("Penggunaan: pqc-cli <perintah> [opsi]")
	fmt.Println()
	fmt.Println("Perintah tersedia:")
	fmt.Println("  test-fips              : Jalankan pengujian kepatuhan spesifikasi NIST FIPS 204")
	fmt.Println("  benchmark [-n iter]    : Jalankan benchmark perbandingan ML-DSA vs RSA")
	fmt.Println("  keygen -alg <alg>      : Bangkitkan pasangan kunci baru (ML-DSA-44/65/87, RSA)")
	fmt.Println("  sign -alg <alg> ...    : Tandatangani pesan atau nilai hash")
	fmt.Println("  verify -alg <alg> ...  : Verifikasi keabsahan tanda tangan")
	fmt.Println("  dual-sign -msg <msg>   : Simulasi skema transisi dual sign (ML-DSA + RSA)")
	fmt.Println("=====================================================================")
}

func runFIPSTest() {
	fmt.Println("\n[+] Menjalankan Validasi Kepatuhan NIST FIPS 204...")
	report := crypto.RunFIPS204Validation()
	fmt.Printf("Standar   : %s\n", report.Standard)
	fmt.Printf("Waktu     : %s\n", report.Timestamp)
	fmt.Printf("Total Uji : %d | Lulus: %d | Gagal: %d\n", report.TotalTests, report.PassedTests, report.FailedTests)
	fmt.Println("---------------------------------------------------------------------")

	for _, tc := range report.TestCases {
		status := "[ PASS ]"
		if !tc.Passed {
			status = "[ FAIL ]"
		}
		fmt.Printf("%s %-18s (%-9s) : %s (%.3f ms)\n", status, tc.ID, tc.Algorithm, tc.TestName, tc.DurationMs)
		fmt.Printf("       Detail: %s\n", tc.Details)
	}

	fmt.Println("---------------------------------------------------------------------")
	if report.AllPassed {
		fmt.Println("[KESIMPULAN] 100% LULUS: Implementasi sepenuhnya mematuhi standar NIST FIPS 204.")
	} else {
		fmt.Println("[KESIMPULAN] GAGAL: Ditemukan ketidaksesuaian terhadap spesifikasi FIPS 204.")
	}
}

func runBenchmark(args []string) {
	fs := flag.NewFlagSet("benchmark", flag.ExitOnError)
	n := fs.Int("n", 50, "Jumlah iterasi benchmark")
	_ = fs.Parse(args)

	fmt.Printf("\n[+] Menjalankan Benchmark Kinerja (%d iterasi)... Target: =< 2.0s\n", *n)
	rep, err := crypto.RunFullBenchmark(*n)
	if err != nil {
		fmt.Printf("Galat benchmark: %v\n", err)
		return
	}

	fmt.Println("----------------------------------------------------------------------------------------------------------")
	fmt.Printf("%-11s | %-14s | %-8s | %-8s | %-12s | %-12s | %-10s\n",
		"Algoritma", "Public Key", "Sign (B)", "Sign Mean", "Sign P95", "Verify Mean", "Target =<2s")
	fmt.Println("----------------------------------------------------------------------------------------------------------")

	for _, item := range rep.Items {
		targetStr := "MEMENUHI"
		if !item.TargetCompliant {
			targetStr = "GAGAL"
		}
		fmt.Printf("%-11s | %10d B | %6d B | %8.3f ms | %8.3f ms | %9.3f ms | %s\n",
			item.Algorithm, item.PublicKeyBytes, item.SignatureBytes, item.SignMeanMs, item.SignP95Ms, item.VerifyMeanMs, targetStr)
	}
	fmt.Println("----------------------------------------------------------------------------------------------------------")
	fmt.Println("[CATATAN]:", rep.SummaryInsight)
}

func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	alg := fs.String("alg", "ML-DSA-65", "Algoritma: ML-DSA-44, ML-DSA-65, ML-DSA-87, RSA-2048, RSA-3072")
	_ = fs.Parse(args)

	algUpper := strings.ToUpper(*alg)
	if strings.HasPrefix(algUpper, "RSA") {
		bits := 2048
		if algUpper == "RSA-3072" {
			bits = 3072
		}
		res, err := crypto.GenerateRSAKeyPair(bits)
		if err != nil {
			fmt.Printf("Galat: %v\n", err)
			return
		}
		fmt.Printf("\n[+] Pembangkitan Kunci %s Berhasil (%.3f ms)\n", res.Algorithm, res.GenDurationMs)
		fmt.Printf("Public Key (%d Bytes):\n%s\n", res.PublicKeyBytes, res.PublicKeyHex)
		fmt.Printf("Private Key (%d Bytes):\n%s\n", res.PrivateKeyBytes, res.PrivateKeyHex)
		return
	}

	res, err := crypto.GenerateMLDSAKeyPair(*alg)
	if err != nil {
		fmt.Printf("Galat: %v\n", err)
		return
	}

	fmt.Printf("\n[+] Pembangkitan Kunci %s Berhasil (%.3f ms)\n", res.Algorithm, res.GenDurationMs)
	fmt.Printf("Standar      : %s (%s)\n", res.Params.NistStandard, res.Params.Description)
	fmt.Printf("Public Key (%d Bytes):\n%s\n", res.PublicKeyBytes, res.PublicKeyHex)
	fmt.Printf("Private Key (%d Bytes):\n%s\n", res.PrivateKeyBytes, res.PrivateKeyHex)
}

func runSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	alg := fs.String("alg", "ML-DSA-65", "Algoritma")
	msg := fs.String("msg", "Surat Keputusan Elektronik BSrE 2026", "Pesan atau data yang ditandatangani")
	privKeyHex := fs.String("key", "", "Kunci privat dalam format Hex (jika kosong akan dibuat otomatis)")
	_ = fs.Parse(args)

	var privBytes []byte
	var pubHex string
	var err error

	if *privKeyHex == "" {
		fmt.Println("[*] Kunci privat tidak disediakan, membangkitkan pasangan kunci sementara...")
		if strings.HasPrefix(strings.ToUpper(*alg), "RSA") {
			k, _ := crypto.GenerateRSAKeyPair(2048)
			privBytes, _ = hex.DecodeString(k.PrivateKeyHex)
			pubHex = k.PublicKeyHex
		} else {
			k, _ := crypto.GenerateMLDSAKeyPair(*alg)
			privBytes, _ = hex.DecodeString(k.PrivateKeyHex)
			pubHex = k.PublicKeyHex
		}
	} else {
		privBytes, err = crypto.DecodeHexOrBase64(*privKeyHex)
		if err != nil {
			fmt.Printf("Kunci privat tidak valid: %v\n", err)
			return
		}
	}

	h := sha256.Sum256([]byte(*msg))
	digest := h[:]

	if strings.HasPrefix(strings.ToUpper(*alg), "RSA") {
		res, err := crypto.SignRSA(privBytes, digest, "SHA-256")
		if err != nil {
			fmt.Printf("Galat sign: %v\n", err)
			return
		}
		fmt.Printf("\n[+] Penandatanganan RSA Berhasil\n")
		fmt.Printf("Algoritma  : %s\n", res.Algorithm)
		fmt.Printf("Durasi     : %.3f ms (Target =< 2000 ms: %v)\n", res.SignDurationMs, res.TargetCompliant)
		fmt.Printf("Ukuran Sig : %d Bytes\n", res.SignatureBytes)
		fmt.Printf("Signature  : %s\n", res.SignatureHex)
		if pubHex != "" {
			fmt.Printf("Public Key : %s\n", pubHex)
		}
		return
	}

	res, err := crypto.SignMLDSA(*alg, privBytes, digest)
	if err != nil {
		fmt.Printf("Galat sign: %v\n", err)
		return
	}

	fmt.Printf("\n[+] Penandatanganan ML-DSA Berhasil\n")
	fmt.Printf("Algoritma  : %s (NIST FIPS 204)\n", res.Algorithm)
	fmt.Printf("Durasi     : %.3f ms (Target =< 2000 ms: %v)\n", res.SignDurationMs, res.TargetCompliant)
	fmt.Printf("Ukuran Sig : %d Bytes\n", res.SignatureBytes)
	fmt.Printf("Signature  : %s\n", res.SignatureHex)
	if pubHex != "" {
		fmt.Printf("Public Key : %s\n", pubHex)
	}
}

func runVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	alg := fs.String("alg", "ML-DSA-65", "Algoritma")
	msg := fs.String("msg", "Surat Keputusan Elektronik BSrE 2026", "Pesan atau data yang diverifikasi")
	pubHex := fs.String("pub", "", "Kunci publik dalam format Hex")
	sigHex := fs.String("sig", "", "Tanda tangan dalam format Hex")
	_ = fs.Parse(args)

	if *pubHex == "" || *sigHex == "" {
		fmt.Println("Parameter -pub dan -sig wajib diisi.")
		return
	}

	pubBytes, err := crypto.DecodeHexOrBase64(*pubHex)
	if err != nil {
		fmt.Printf("Kunci publik tidak valid: %v\n", err)
		return
	}

	sigBytes, err := crypto.DecodeHexOrBase64(*sigHex)
	if err != nil {
		fmt.Printf("Signature tidak valid: %v\n", err)
		return
	}

	h := sha256.Sum256([]byte(*msg))
	digest := h[:]

	if strings.HasPrefix(strings.ToUpper(*alg), "RSA") {
		res, err := crypto.VerifyRSA(pubBytes, digest, sigBytes, "SHA-256")
		if err != nil {
			fmt.Printf("Galat verify: %v\n", err)
			return
		}
		fmt.Printf("\n[Hasil Verifikasi RSA]\nStatus  : %v\nDurasi  : %.3f ms\nCatatan : %s\n", res.Valid, res.VerifyDurationMs, res.Reason)
		return
	}

	res, err := crypto.VerifyMLDSA(*alg, pubBytes, digest, sigBytes)
	if err != nil {
		fmt.Printf("Galat verify: %v\n", err)
		return
	}
	fmt.Printf("\n[Hasil Verifikasi ML-DSA]\nStatus   : %v\nStandar  : FIPS 204 (%v)\nDurasi   : %.3f ms\nCatatan  : %s\n", res.Valid, res.FIPS204Compliant, res.VerifyDurationMs, res.Reason)
}

func runDualSign(args []string) {
	fs := flag.NewFlagSet("dual-sign", flag.ExitOnError)
	msg := fs.String("msg", "Dokumen Transisi Bersama BSrE - RSA + ML-DSA", "Pesan uji")
	_ = fs.Parse(args)

	fmt.Println("\n[*] Membangkitkan pasangan kunci uji (ML-DSA-65 & RSA-2048)...")
	mldsaKey, _ := crypto.GenerateMLDSAKeyPair("ML-DSA-65")
	rsaKey, _ := crypto.GenerateRSAKeyPair(2048)

	mldsaSK, _ := hex.DecodeString(mldsaKey.PrivateKeyHex)
	mldsaPK, _ := hex.DecodeString(mldsaKey.PublicKeyHex)
	rsaSK, _ := hex.DecodeString(rsaKey.PrivateKeyHex)
	rsaPK, _ := hex.DecodeString(rsaKey.PublicKeyHex)

	h := sha256.Sum256([]byte(*msg))
	digest := h[:]

	fmt.Println("[*] Menandatangani dengan kedua algoritma secara bersamaan...")
	dualRes, err := crypto.SignDual("ML-DSA-65", mldsaSK, rsaSK, digest, "SHA-256")
	if err != nil {
		fmt.Printf("Galat dual sign: %v\n", err)
		return
	}

	fmt.Printf("[+] Skenario Koeksistensi Berhasil!\n")
	fmt.Printf("Total Waktu   : %.3f ms (Target =< 2000 ms: %v)\n", dualRes.TotalDurationMs, dualRes.TargetCompliant)
	fmt.Printf("Total Ukuran  : %d Bytes (ML-DSA: %d B, RSA: %d B)\n", dualRes.TotalSizeBytes, dualRes.MLDSAResult.SignatureBytes, dualRes.RSAResult.SignatureBytes)

	mldsaSig, _ := hex.DecodeString(dualRes.MLDSAResult.SignatureHex)
	rsaSig, _ := hex.DecodeString(dualRes.RSAResult.SignatureHex)

	verifyRes, _ := crypto.VerifyDual("ML-DSA-65", mldsaPK, mldsaSig, rsaPK, rsaSig, digest, "SHA-256")
	fmt.Printf("[+] Verifikasi Dual: %s\n", verifyRes.Summary)
}
