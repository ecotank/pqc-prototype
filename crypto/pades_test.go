package crypto

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPAdESSigningAndVerification(t *testing.T) {
	// 1. Dokumen PDF minimal berstandar PDF-1.7
	dummyPDF := []byte("%PDF-1.7\n" +
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
		"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n" +
		"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF\n")

	// 2. Bangkitkan Kunci Signer
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Gagal generate RSA key: %v", err)
	}

	mldsaKey, err := GenerateMLDSAKeyPair("ML-DSA-65")
	if err != nil {
		t.Fatalf("Gagal generate ML-DSA key: %v", err)
	}
	mldsaSK, _ := hex.DecodeString(mldsaKey.PrivateKeyHex)
	mldsaPK, _ := hex.DecodeString(mldsaKey.PublicKeyHex)

	receiptID := "BSRE-TEST-998811"

	// 3. Terapkan TTE PAdES ISO 32000
	signedPDF, result, err := SignPDFPAdES(
		dummyPDF,
		PAdESSignOptions{
			SignerFullName:  "Satria Alba Pramasha, S.Tr.Kom.",
			SignerEmail:     "satria.alba@bsre.bssn.go.id",
			SignerNIK:       "199910262024011001",
			Institution:     "Balai Besar Sertifikasi Elektronik (BSrE) - BSSN",
			RSAKey:          rsaKey,
			MLDSAPrivateKey: mldsaSK,
			MLDSAPublicKey:  mldsaPK,
			ReceiptID:       receiptID,
		},
	)
	if err != nil {
		t.Fatalf("Gagal SignPDFPAdES: %v", err)
	}

	// 4. Verifikasi Keberadaan Elemen Standar ISO 32000-1
	if !bytes.Contains(signedPDF, []byte("/Type /Sig")) {
		t.Errorf("PDF tidak mengandung objek /Type /Sig")
	}
	if !bytes.Contains(signedPDF, []byte("/Filter /Adobe.PPKLite")) {
		t.Errorf("PDF tidak mengandung /Filter /Adobe.PPKLite")
	}
	if !bytes.Contains(signedPDF, []byte("/SubFilter /adbe.pkcs7.detached")) {
		t.Errorf("PDF tidak mengandung /SubFilter /adbe.pkcs7.detached")
	}
	if !bytes.Contains(signedPDF, []byte("/ByteRange")) {
		t.Errorf("PDF tidak mengandung parameter /ByteRange")
	}
	if !bytes.Contains(signedPDF, []byte("/Contents <")) {
		t.Errorf("PDF tidak mengandung slot biner /Contents")
	}

	// 5. Validasi Integritas ByteRange Kriptografis
	startTag := bytes.Index(signedPDF, []byte("/Contents <")) + 11
	endTag := bytes.IndexByte(signedPDF[startTag:], '>') + startTag
	offset1 := startTag - 1
	offset2 := endTag + 1
	offset3 := len(signedPDF) - offset2

	part1 := signedPDF[:offset1]
	part2 := signedPDF[offset2 : offset2+offset3]

	h := sha256.New()
	h.Write(part1)
	h.Write(part2)
	computedDigest := hex.EncodeToString(h.Sum(nil))

	if computedDigest != result.DocumentHash {
		t.Errorf("Hash ByteRange tidak cocok: dihitung=%s, hasil=%s", computedDigest, result.DocumentHash)
	}

	// 6. Validasi ASN.1 DER PKCS#7 Kontainer
	pkcs7Bytes, err := hex.DecodeString(result.PKCS7SignatureHex)
	if err != nil {
		t.Fatalf("Gagal decode PKCS#7 Hex: %v", err)
	}

	var ci ContentInfo
	_, err = asn1.Unmarshal(pkcs7Bytes, &ci)
	if err != nil {
		t.Fatalf("Gagal unmarshal ContentInfo PKCS#7: %v", err)
	}

	var sd SignedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		t.Fatalf("Gagal unmarshal SignedData: %v", err)
	}

	if len(sd.SignerInfos) != 1 {
		t.Fatalf("Jumlah SignerInfo tidak tepat: %d", len(sd.SignerInfos))
	}

	si := sd.SignerInfos[0]

	// 7. Verifikasi Tanda Tangan RSA atas SignedAttributes
	setAttrs := make([]byte, len(si.AuthAttributes.FullBytes))
	copy(setAttrs, si.AuthAttributes.FullBytes)
	setAttrs[0] = 0x31 // context [0] tag (0xA0) -> SET OF tag (0x31)

	attrsHash := sha256.Sum256(setAttrs)
	err = rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, attrsHash[:], si.Signature)
	if err != nil {
		t.Fatalf("Verifikasi kriptografi RSA PKCS#1 v1.5 gagal: %v", err)
	}

	// 8. Verifikasi Tanda Tangan Pascakuantum FIPS 204 ML-DSA-65
	mldsaSig, _ := hex.DecodeString(result.MLDSASignatureHex)
	docDigestBytes, _ := hex.DecodeString(result.DocumentHash)
	verRes, err := VerifyMLDSA("ML-DSA-65", mldsaPK, docDigestBytes, mldsaSig)
	if err != nil || !verRes.Valid {
		t.Fatalf("Verifikasi tanda tangan ML-DSA-65 gagal: %v", err)
	}

	// 9. Uji Eksternal dengan OpenSSL jika tersedia di mesin host
	tmpDir := t.TempDir()
	p7File := filepath.Join(tmpDir, "signature.p7s")
	_ = os.WriteFile(p7File, pkcs7Bytes, 0644)

	opensslPath := `C:\Program Files\OpenSSL-Win64\bin\openssl.exe`
	if _, err := os.Stat(opensslPath); err == nil {
		cmd := exec.Command(opensslPath, "pkcs7", "-in", p7File, "-inform", "DER", "-print_certs", "-noout")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("OpenSSL pkcs7 output: %s", string(out))
			t.Errorf("OpenSSL gagal memvalidasi struktur PKCS#7: %v", err)
		} else {
			t.Logf("OpenSSL memverifikasi struktur PKCS#7 secara sempurna!")
		}
	}

	t.Logf("PAdES ISO 32000-1 TTE Pascakuantum berhasil diverifikasi secara kriptografis! Durasi: %.2f ms", result.DurationMs)
}
