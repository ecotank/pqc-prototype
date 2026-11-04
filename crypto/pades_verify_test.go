package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// minimalPDF mengembalikan dokumen PDF 1.7 minimal yang sah untuk bahan uji.
func minimalPDF() []byte {
	return []byte("%PDF-1.7\n" +
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n" +
		"xref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n" +
		"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF\n")
}

// signTestPDF menandatangani dokumen dengan pasangan kunci ML-DSA-65 baru.
func signTestPDF(t *testing.T, pdf []byte, receiptID, signerName string) []byte {
	t.Helper()

	keys, err := GenerateMLDSAKeyPair("ML-DSA-65")
	if err != nil {
		t.Fatalf("gagal membangkitkan kunci ML-DSA-65: %v", err)
	}
	sk, err := hex.DecodeString(keys.PrivateKeyHex)
	if err != nil {
		t.Fatalf("kunci privat tidak valid: %v", err)
	}
	pk, err := hex.DecodeString(keys.PublicKeyHex)
	if err != nil {
		t.Fatalf("kunci publik tidak valid: %v", err)
	}

	signed, _, err := SignPDFPAdES(pdf, PAdESSignOptions{
		SignerFullName:  signerName,
		SignerEmail:     "signer@smallcircle.web.id",
		SignerNIK:       "199910262024011001",
		Institution:     "ARSign Trust Network",
		ReceiptID:       receiptID,
		MLDSAPrivateKey: sk,
		MLDSAPublicKey:  pk,
	})
	if err != nil {
		t.Fatalf("SignPDFPAdES gagal: %v", err)
	}
	return signed
}

// contentsSlot mengembalikan posisi awal dan akhir hex kontainer PKCS#7 pertama.
func contentsSlot(t *testing.T, pdf []byte) (int, int) {
	t.Helper()

	idx := bytes.Index(pdf, []byte("/Contents <"))
	if idx == -1 {
		t.Fatal("slot /Contents tidak ditemukan")
	}
	start := idx + len("/Contents <")
	rel := bytes.IndexByte(pdf[start:], '>')
	if rel == -1 {
		t.Fatal("penutup '>' slot /Contents tidak ditemukan")
	}
	return start, start + rel
}

// decodeContents membaca DER PKCS#7 dari slot /Contents.
func decodeContents(t *testing.T, pdf []byte, start, end int) []byte {
	t.Helper()

	raw := strings.TrimRight(string(pdf[start:end]), "0")
	if len(raw)%2 != 0 {
		raw += "0"
	}
	der, err := hex.DecodeString(raw)
	if err != nil {
		t.Fatalf("gagal decode hex /Contents: %v", err)
	}
	return der
}

// rewriteContents menuliskan ulang DER ke dalam slot /Contents dengan padding nol.
func rewriteContents(t *testing.T, pdf []byte, start, end int, der []byte) []byte {
	t.Helper()

	newHex := strings.ToUpper(hex.EncodeToString(der))
	if len(newHex) > end-start {
		t.Fatalf("DER hasil modifikasi (%d) melebihi kapasitas slot (%d)", len(newHex), end-start)
	}
	out := make([]byte, len(pdf))
	copy(out, pdf)
	copy(out[start:end], []byte(newHex+strings.Repeat("0", end-start-len(newHex))))
	return out
}

func TestVerifyPDFPAdESAcceptsGenuineSignature(t *testing.T) {
	signed := signTestPDF(t, minimalPDF(), "ARS-TEST-VALID", "Pejabat Penandatangan Resmi, S.Kom.")

	res, err := VerifyPDFPAdES(signed)
	if err != nil {
		t.Fatalf("VerifyPDFPAdES gagal: %v", err)
	}
	if !res.IsValid {
		t.Fatalf("dokumen asli seharusnya SAH, diperoleh: %s", res.Message)
	}
	if !res.IsDocumentIntact || !res.IsSignatureValid || !res.IsChainValid {
		t.Fatalf("rincian pemeriksaan tidak lengkap: intact=%v signature=%v chain=%v",
			res.IsDocumentIntact, res.IsSignatureValid, res.IsChainValid)
	}
	if !res.IsPQCPresent || !res.IsPQCVerified {
		t.Fatalf("lapisan pascakuantum seharusnya ada dan terverifikasi: present=%v verified=%v",
			res.IsPQCPresent, res.IsPQCVerified)
	}
	if res.TotalSignatures != 1 || res.ValidSignatures != 1 {
		t.Fatalf("jumlah tanda tangan tidak sesuai: total=%d valid=%d", res.TotalSignatures, res.ValidSignatures)
	}
}

// TestVerifyPDFPAdESRejectsStrippedPQCWithBrokenSignature adalah uji regresi untuk
// celah bypass verifikasi: dulu `isValid = digestMatch && (rsaValid || pqcValid)`
// dengan pqcValid berinisial true, sehingga menghapus atribut pascakuantum membuat
// tanda tangan kriptografis tidak pernah benar-benar diwajibkan. Karena slot
// /Contents berada di luar cakupan /ByteRange, perusakan ini tidak mengubah digest.
func TestVerifyPDFPAdESRejectsStrippedPQCWithBrokenSignature(t *testing.T) {
	signed := signTestPDF(t, minimalPDF(), "ARS-TEST-FORGE", "Pejabat Penandatangan Resmi, S.Kom.")
	start, end := contentsSlot(t, signed)
	der := decodeContents(t, signed, start, end)

	marker := []byte("ML-DSA-65|RECEIPT:")
	mIdx := bytes.Index(der, marker)
	if mIdx == -1 {
		t.Fatal("penanda muatan pascakuantum tidak ditemukan di dalam kontainer")
	}
	copy(der[mIdx:], []byte("XX-XXX-XX|XXXXXXX:"))

	// Rusak ekor tanda tangan RSA pada SignerInfo.
	for i := len(der) - 8; i < len(der); i++ {
		der[i] ^= 0xff
	}

	forged := rewriteContents(t, signed, start, end, der)

	res, err := VerifyPDFPAdES(forged)
	if err != nil {
		// Penolakan melalui error juga memenuhi syarat.
		return
	}
	if res.IsValid {
		t.Fatalf("dokumen dengan tanda tangan rusak dinyatakan SAH: %s", res.Message)
	}
	if res.IsSignatureValid {
		t.Fatal("tanda tangan kriptografis rusak seharusnya dilaporkan tidak sah")
	}
}

// TestVerifyPDFPAdESRejectsBrokenPQCLayer memastikan lapisan pascakuantum yang
// rusak tetap menggagalkan verifikasi meski tanda tangan kontainer masih sah.
func TestVerifyPDFPAdESRejectsBrokenPQCLayer(t *testing.T) {
	signed := signTestPDF(t, minimalPDF(), "ARS-TEST-PQCBREAK", "Pejabat Penandatangan Resmi, S.Kom.")
	start, end := contentsSlot(t, signed)
	der := decodeContents(t, signed, start, end)

	marker := []byte("|SIG:")
	mIdx := bytes.Index(der, marker)
	if mIdx == -1 {
		t.Fatal("bagian SIG muatan pascakuantum tidak ditemukan")
	}
	// Ubah digit hex tanda tangan ML-DSA tanpa mengubah panjang muatan.
	for i := mIdx + len(marker); i < mIdx+len(marker)+16 && i < len(der); i++ {
		if der[i] == '0' {
			der[i] = '1'
		} else {
			der[i] = '0'
		}
	}

	forged := rewriteContents(t, signed, start, end, der)

	res, err := VerifyPDFPAdES(forged)
	if err != nil {
		return
	}
	if res.IsValid {
		t.Fatalf("lapisan pascakuantum rusak seharusnya ditolak: %s", res.Message)
	}
}

// TestVerifyPDFPAdESRejectsModifiedDocumentBody memastikan perubahan isi dokumen
// terdeteksi karena digest ByteRange tidak lagi cocok.
func TestVerifyPDFPAdESRejectsModifiedDocumentBody(t *testing.T) {
	signed := signTestPDF(t, minimalPDF(), "ARS-TEST-TAMPER", "Pejabat Penandatangan Resmi, S.Kom.")

	idx := bytes.Index(signed, []byte("/MediaBox [0 0 612 792]"))
	if idx == -1 {
		t.Fatal("isi dokumen uji tidak ditemukan")
	}
	tampered := make([]byte, len(signed))
	copy(tampered, signed)
	copy(tampered[idx:], []byte("/MediaBox [0 0 613 792]"))

	res, err := VerifyPDFPAdES(tampered)
	if err != nil {
		return
	}
	if res.IsValid {
		t.Fatalf("dokumen yang dimodifikasi seharusnya ditolak: %s", res.Message)
	}
	if res.IsDocumentIntact {
		t.Fatal("integritas dokumen seharusnya dilaporkan rusak")
	}
}

// TestVerifyPDFPAdESVerifiesEveryRevision memastikan tanda tangan pertama pada
// dokumen multi-signature juga diverifikasi, bukan hanya /ByteRange terakhir.
func TestVerifyPDFPAdESVerifiesEveryRevision(t *testing.T) {
	first := signTestPDF(t, minimalPDF(), "ARS-TEST-MULTI-1", "Penandatangan Dokumen Satu, S.Kom.")
	second := signTestPDF(t, first, "ARS-TEST-MULTI-2", "Penandatangan Dokumen Dua, S.Kom.")

	res, err := VerifyPDFPAdES(second)
	if err != nil {
		t.Fatalf("VerifyPDFPAdES gagal pada dokumen multi-signature: %v", err)
	}
	if res.TotalSignatures != 2 {
		t.Fatalf("jumlah revisi tanda tangan terdeteksi %d, diharapkan 2", res.TotalSignatures)
	}
	if !res.IsValid || res.ValidSignatures != 2 {
		t.Fatalf("kedua tanda tangan seharusnya sah: valid=%v lulus=%d pesan=%s",
			res.IsValid, res.ValidSignatures, res.Message)
	}

	// Rusak tanda tangan pertama; keseluruhan dokumen harus ditolak.
	start, end := contentsSlot(t, second)
	der := decodeContents(t, second, start, end)
	for i := len(der) - 8; i < len(der); i++ {
		der[i] ^= 0xff
	}
	forged := rewriteContents(t, second, start, end, der)

	res2, err := VerifyPDFPAdES(forged)
	if err != nil {
		return
	}
	if res2.IsValid {
		t.Fatalf("kerusakan pada tanda tangan pertama seharusnya menggagalkan dokumen: %s", res2.Message)
	}
}

// TestSignPDFPAdESProducesValidIncrementalUpdate memeriksa kelengkapan struktur
// incremental update ISO 32000-1: /Prev, /Root, dan /AcroForm.
func TestSignPDFPAdESProducesValidIncrementalUpdate(t *testing.T) {
	signed := signTestPDF(t, minimalPDF(), "ARS-TEST-STRUCT", "Pejabat Penandatangan Resmi, S.Kom.")

	for _, want := range []string{"/Prev ", "/Root 1 0 R", "/AcroForm", "/SigFlags 3"} {
		if !bytes.Contains(signed, []byte(want)) {
			t.Errorf("struktur incremental update tidak memuat %q", want)
		}
	}
}

// TestWriteXrefSubsectionsOrdersEntries memastikan tabel xref ditulis terurut naik
// dan terpecah menjadi subbagian untuk nomor objek yang tidak berurutan.
func TestWriteXrefSubsectionsOrdersEntries(t *testing.T) {
	var buf bytes.Buffer
	writeXrefSubsections(&buf, []xrefEntry{
		{objID: 12, offset: 900},
		{objID: 11, offset: 500},
		{objID: 1, offset: 100},
	})

	got := buf.String()
	want := "xref\n" +
		"1 1\n0000000100 00000 n \n" +
		"11 2\n0000000500 00000 n \n0000000900 00000 n \n"
	if got != want {
		t.Fatalf("tabel xref tidak sesuai.\ndiperoleh:\n%s\ndiharapkan:\n%s", got, want)
	}
}

// TestEscapePDFStringEscapesDelimiters memastikan nama penanda tangan dengan
// tanda kurung tidak merusak literal string PDF.
func TestEscapePDFStringEscapesDelimiters(t *testing.T) {
	got := escapePDFString("Budi (Plt.) \\ Santoso\nJakarta")
	want := `Budi \(Plt.\) \\ Santoso Jakarta`
	if got != want {
		t.Fatalf("hasil escape %q, diharapkan %q", got, want)
	}
}

// TestVerifyPDFPAdESRejectsAppendedRevision adalah uji regresi untuk Incremental
// Saving Attack: penyerang menambahkan revisi inkremental baru di belakang
// rentang yang ditandatangani. Byte tambahan itu tidak tercakup tanda tangan mana
// pun, namun sebelumnya dokumen tetap dinyatakan asli dan utuh.
func TestVerifyPDFPAdESRejectsAppendedRevision(t *testing.T) {
	signed := signTestPDF(t, minimalPDF(), "ARS-TEST-APPEND", "Pejabat Penandatangan Resmi, S.Kom.")

	appended := append(append([]byte(nil), signed...), []byte(
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Perms << >> >>\nendobj\n"+
			"xref\n1 1\n0000000009 00000 n \n"+
			"trailer\n<< /Size 13 /Root 1 0 R /Prev 100 >>\nstartxref\n66700\n%%EOF\n")...)

	res, err := VerifyPDFPAdES(appended)
	if err != nil {
		// Penolakan melalui error juga memenuhi syarat.
		return
	}
	if res.IsValid {
		t.Fatalf("revisi yang ditambahkan setelah penandatanganan seharusnya ditolak: %s", res.Message)
	}
	if !res.HasUnsignedChanges {
		t.Fatal("perubahan di luar cakupan tanda tangan seharusnya dilaporkan")
	}
}

// TestVerifyPDFPAdESAllowsTrailingWhitespace memastikan ruang kosong setelah
// %%EOF tidak dianggap perubahan tak bertanda tangan.
func TestVerifyPDFPAdESAllowsTrailingWhitespace(t *testing.T) {
	signed := signTestPDF(t, minimalPDF(), "ARS-TEST-WS", "Pejabat Penandatangan Resmi, S.Kom.")
	padded := append(append([]byte(nil), signed...), []byte("\r\n \t\n")...)

	res, err := VerifyPDFPAdES(padded)
	if err != nil {
		t.Fatalf("VerifyPDFPAdES gagal: %v", err)
	}
	if res.HasUnsignedChanges {
		t.Fatal("ruang kosong di akhir berkas tidak boleh dianggap perubahan")
	}
	if !res.IsValid {
		t.Fatalf("dokumen seharusnya tetap SAH: %s", res.Message)
	}
}

// TestVerifyPDFPAdESCollectsEverySerial memastikan nomor seri setiap revisi
// dikembalikan, sehingga pemeriksaan pencabutan dapat menyentuh seluruh
// penanda tangan, bukan hanya yang terakhir.
func TestVerifyPDFPAdESCollectsEverySerial(t *testing.T) {
	first := signTestPDF(t, minimalPDF(), "ARS-TEST-SERIAL-1", "Penandatangan Dokumen Satu, S.Kom.")
	second := signTestPDF(t, first, "ARS-TEST-SERIAL-2", "Penandatangan Dokumen Dua, S.Kom.")

	res, err := VerifyPDFPAdES(second)
	if err != nil {
		t.Fatalf("VerifyPDFPAdES gagal: %v", err)
	}
	if len(res.CertSerialNumbers) != 2 {
		t.Fatalf("jumlah nomor seri %d, diharapkan 2", len(res.CertSerialNumbers))
	}
	if res.CertSerialNumbers[0] == res.CertSerialNumbers[1] {
		t.Fatal("kedua revisi seharusnya memakai sertifikat berbeda")
	}
	if res.CertSerialNumbers[1] != res.CertSerialNumber {
		t.Fatal("nomor seri terakhir harus sama dengan penanda tangan terkini")
	}
}
