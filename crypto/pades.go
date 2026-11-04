package crypto

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	oidSignedData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSHA256           = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidContentType      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidPQCDualSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 58333, 1, 204} // OID Ekstensi PQC ARSign
)

type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type SignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	SignerInfos      []SignerInfo  `asn1:"set"`
}

type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
}

type SignerInfo struct {
	Version            int
	IssuerAndSerial    IssuerAndSerialNumber
	DigestAlgorithm    pkix.AlgorithmIdentifier
	AuthAttributes     asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type IssuerAndSerialNumber struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type PAdESSignResult struct {
	ReceiptID         string    `json:"receipt_id"`
	SignedAt          time.Time `json:"signed_at"`
	DocumentHash      string    `json:"document_hash"`
	PKCS7SignatureHex string    `json:"pkcs7_signature_hex"`
	MLDSASignatureHex string    `json:"mldsa_signature_hex"`
	MLDSAPublicKeyHex string    `json:"mldsa_public_key_hex"`
	SignerFullName    string    `json:"signer_fullname"`
	SignerEmail       string    `json:"signer_email"`
	Institution       string    `json:"institution"`
	CertSerialNumber  string    `json:"cert_serial_number"`
	DurationMs        float64   `json:"duration_ms"`
	StandardCompliant bool      `json:"standard_compliant"` // ISO 32000-1 / PAdES ETSI EN 319 142
}

// BuildPKCS7SignedData membangun kontainer biner CMS / PKCS#7 yang sah untuk Adobe Acrobat & BeSign
func BuildPKCS7SignedData(
	docDigest []byte,
	signerCert *x509.Certificate,
	signerCertDER []byte,
	subCACertDER []byte,
	rootCACertDER []byte,
	rsaKey *rsa.PrivateKey,
	mldsaSigHex string,
	mldsaPubKeyHex string,
	receiptId string,
) ([]byte, error) {
	// Atribut 1: ContentType = id-data
	valContentType, _ := asn1.Marshal(oidData)
	// Atribut 2: MessageDigest = SHA-256 ByteRange Dokumen
	valMessageDigest, _ := asn1.Marshal(docDigest)
	// Atribut 3: SigningTime = Waktu Saat Ini
	valSigningTime, _ := asn1.Marshal(time.Now().UTC())
	// Atribut 4: PQC NIST FIPS 204 ML-DSA Signature & Public Key
	pqcPayload := fmt.Sprintf("ML-DSA-65|RECEIPT:%s|PUB:%s|SIG:%s", receiptId, mldsaPubKeyHex, mldsaSigHex)
	valPQC, _ := asn1.Marshal(pqcPayload)

	attrs := []Attribute{
		{Type: oidContentType, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: valContentType}},
		{Type: oidMessageDigest, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: valMessageDigest}},
		{Type: oidSigningTime, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: valSigningTime}},
		{Type: oidPQCDualSignature, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: valPQC}},
	}

	marshaledAttrs, err := asn1.Marshal(attrs)
	if err != nil {
		return nil, fmt.Errorf("gagal marshal atribut terotentikasi: %w", err)
	}

	var rawAttrs asn1.RawValue
	if _, err := asn1.Unmarshal(marshaledAttrs, &rawAttrs); err != nil {
		return nil, err
	}

	attrsForSigning := make([]byte, len(rawAttrs.FullBytes))
	copy(attrsForSigning, rawAttrs.FullBytes)
	attrsForSigning[0] = 0x31 // Ganti tag SEQUENCE menjadi SET OF (wajib CMS RFC 5652)

	attrsHash := sha256.Sum256(attrsForSigning)
	rsaSig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, attrsHash[:])
	if err != nil {
		return nil, fmt.Errorf("gagal menandatangani RSA pada atribut CMS: %w", err)
	}

	signerInfo := SignerInfo{
		Version: 1,
		IssuerAndSerial: IssuerAndSerialNumber{
			IssuerName:   asn1.RawValue{FullBytes: signerCert.RawIssuer},
			SerialNumber: signerCert.SerialNumber,
		},
		DigestAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidSHA256,
		},
		AuthAttributes: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      rawAttrs.Bytes,
		},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: oidRSAEncryption,
		},
		Signature: rsaSig,
	}

	var certsRaw []byte
	certsRaw = append(certsRaw, signerCertDER...)
	certsRaw = append(certsRaw, subCACertDER...)
	if len(rootCACertDER) > 0 {
		certsRaw = append(certsRaw, rootCACertDER...)
	}

	sd := SignedData{
		Version: 1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{
			{Algorithm: oidSHA256},
		},
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: oidData,
		},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      certsRaw,
		},
		SignerInfos: []SignerInfo{signerInfo},
	}

	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("gagal marshal SignedData: %w", err)
	}

	contentInfo := ContentInfo{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      sdBytes,
		},
	}

	return asn1.Marshal(contentInfo)
}

type PAdESSignOptions struct {
	SignerFullName  string
	SignerEmail     string
	SignerNIK       string
	Institution     string
	ReceiptID       string
	RSAKey          *rsa.PrivateKey // jika nil, di-generate otomatis
	MLDSAPrivateKey []byte
	MLDSAPublicKey  []byte
}

// SignPDFPAdES menerapkan tanda tangan digital ISO 32000-1 PAdES resmi pada dokumen PDF
func SignPDFPAdES(pdfData []byte, opts PAdESSignOptions) ([]byte, *PAdESSignResult, error) {
	start := time.Now()

	ca, err := GetARSignAuthority()
	if err != nil {
		return nil, nil, fmt.Errorf("gagal inisialisasi CA: %w", err)
	}

	rsaKey := opts.RSAKey
	if rsaKey == nil {
		rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("gagal bangkitkan RSA key untuk sesi penandatanganan: %w", err)
		}
	}

	receiptId := opts.ReceiptID
	if receiptId == "" {
		receiptId = fmt.Sprintf("ARS-%d", time.Now().UnixNano()%10000000)
	}

	fullname := opts.SignerFullName
	if fullname == "" {
		fullname = "Penanda Tangan ARSign"
	}
	email := opts.SignerEmail
	if email == "" {
		email = "signer@smallcircle.web.id"
	}
	institution := opts.Institution
	if institution == "" {
		institution = "ARSign Trust Network"
	}

	signerCert, signerCertDER, err := ca.IssueSignerCertificate(fullname, email, opts.SignerNIK, institution, &rsaKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal menerbitkan sertifikat: %w", err)
	}

	// Periksa apakah berkas PDF sudah memiliki slot placeholder kosong yang belum terisi (diawali '00000000...')
	// Sebuah tanda tangan nyata selalu diawali '3082...' (ASN.1 DER Sequence), sedangkan placeholder kosong diawali '00000000'
	var workingPDF []byte
	var startContents, endContents int
	var offset1, offset2, offset3 int
	const placeholderLen = 32768 // 32768 byte DER = 65536 karakter hexa

	placeholderRegex := regexp.MustCompile(`/Contents\s*<\s*0{16,}`)
	loc := placeholderRegex.FindIndex(pdfData)

	if loc != nil {
		// Ditemukan slot placeholder alokasi tanda tangan baru yang belum terisi
		workingPDF = make([]byte, len(pdfData))
		copy(workingPDF, pdfData)

		bracketOpen := bytes.IndexByte(workingPDF[loc[0]:], '<')
		if bracketOpen == -1 {
			return nil, nil, fmt.Errorf("tanda pembuka '<' untuk /Contents tidak ditemukan")
		}
		startContents = loc[0] + bracketOpen + 1

		endRel := bytes.IndexByte(workingPDF[startContents:], '>')
		if endRel == -1 {
			return nil, nil, fmt.Errorf("tanda penutup '>' untuk /Contents tidak ditemukan")
		}
		endContents = startContents + endRel

		offset1 = startContents - 1
		offset2 = endContents + 1
		offset3 = len(workingPDF) - offset2

		// Perbarui /ByteRange placeholder spesifik untuk signature baru ini
		prefixForBR := workingPDF[:startContents]
		byteRangePos := bytes.LastIndex(prefixForBR, []byte("/ByteRange"))
		if byteRangePos == -1 {
			return nil, nil, fmt.Errorf("slot /Contents ditemukan tetapi /ByteRange pasangannya tidak ada")
		}
		endBracket := bytes.IndexByte(workingPDF[byteRangePos:], ']')
		if endBracket == -1 {
			return nil, nil, fmt.Errorf("penutup ']' pada /ByteRange tidak ditemukan")
		}
		oldRange := workingPDF[byteRangePos : byteRangePos+endBracket+1]
		newRange := fmt.Sprintf("/ByteRange [ 0 %010d %010d %010d ]", offset1, offset2, offset3)
		// Dulu penulisan dilewati diam-diam bila slot terlalu pendek, menghasilkan
		// berkas tertandatangani dengan /ByteRange salah tanpa pesan error apa pun.
		if len(newRange) > len(oldRange) {
			return nil, nil, fmt.Errorf("slot /ByteRange terlalu pendek (%d byte) untuk nilai baru (%d byte)", len(oldRange), len(newRange))
		}
		padded := []byte(fmt.Sprintf("%-"+strconv.Itoa(len(oldRange))+"s", newRange))
		copy(workingPDF[byteRangePos:], padded)
	} else {
		// Tambahkan incremental update revisi tanda tangan ISO 32000-1 ke akhir berkas
		workingPDF, startContents, endContents, offset1, offset2, offset3, err = appendPDFSignatureStructure(pdfData, fullname, receiptId, placeholderLen)
		if err != nil {
			return nil, nil, fmt.Errorf("gagal menyusun struktur tanda tangan PDF: %w", err)
		}
	}

	// 1. Ekstraksi ByteRange Dokumen dan Hitung SHA-256
	part1 := workingPDF[0:offset1]
	part2 := workingPDF[offset2 : offset2+offset3]

	h := sha256.New()
	h.Write(part1)
	h.Write(part2)
	docDigest := h.Sum(nil)
	docDigestHex := hex.EncodeToString(docDigest)

	// 2. Tandatangani secara Pascakuantum FIPS 204 ML-DSA-65
	mldsaRes, err := SignMLDSA("ML-DSA-65", opts.MLDSAPrivateKey, docDigest)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal menandatangani ML-DSA-65: %w", err)
	}

	// 3. Bangkitkan Kontainer Standar PKCS#7 / CMS (Memuat RSA Signer & Ekstensi ML-DSA)
	pkcs7DER, err := BuildPKCS7SignedData(
		docDigest,
		signerCert,
		signerCertDER,
		ca.SubCACertDER,
		ca.RootCertDER,
		rsaKey,
		mldsaRes.SignatureHex,
		hex.EncodeToString(opts.MLDSAPublicKey),
		receiptId,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal membuat kontainer PKCS#7: %w", err)
	}

	// 4. Konversi PKCS#7 ke Hex dan Masukkan ke Slot /Contents
	pkcs7Hex := strings.ToUpper(hex.EncodeToString(pkcs7DER))
	slotCapacity := endContents - startContents

	if len(pkcs7Hex) > slotCapacity {
		return nil, nil, fmt.Errorf("kapasitas slot /Contents (%d) tidak cukup untuk PKCS#7 (%d)", slotCapacity, len(pkcs7Hex))
	}

	// Isi sisa slot dengan angka nol (padding baku PDF)
	paddedHex := pkcs7Hex + strings.Repeat("0", slotCapacity-len(pkcs7Hex))
	copy(workingPDF[startContents:endContents], []byte(paddedHex))

	durMs := float64(time.Since(start).Microseconds()) / 1000.0

	result := &PAdESSignResult{
		ReceiptID:         receiptId,
		SignedAt:          time.Now(),
		DocumentHash:      docDigestHex,
		PKCS7SignatureHex: pkcs7Hex,
		MLDSASignatureHex: mldsaRes.SignatureHex,
		MLDSAPublicKeyHex: hex.EncodeToString(opts.MLDSAPublicKey),
		SignerFullName:    fullname,
		SignerEmail:       email,
		Institution:       institution,
		CertSerialNumber:  signerCert.SerialNumber.String(),
		DurationMs:        durMs,
		StandardCompliant: true,
	}

	return workingPDF, result, nil
}

// pdfObjHeaderRegex mencocokkan header objek tak langsung PDF ("12 0 obj").
var pdfObjHeaderRegex = regexp.MustCompile(`(?m)^[\s]*(\d+)\s+0\s+obj\b`)

// pdfAcroFormRegex mencocokkan entri /AcroForm yang sudah pernah ditulis ARSign.
var pdfAcroFormRegex = regexp.MustCompile(`(?s)/AcroForm\s*<<.*?>>\s*`)

// pdfRootRefRegex mencocokkan rujukan katalog dokumen pada trailer ("/Root 1 0 R").
var pdfRootRefRegex = regexp.MustCompile(`/Root\s+(\d+)\s+0\s+R`)

// pdfSigFieldRegex mencocokkan penanda widget kolom tanda tangan.
var pdfSigFieldRegex = regexp.MustCompile(`/FT\s*/Sig`)

// lastStartxrefOffset membaca nilai startxref terakhir pada berkas, yaitu posisi
// tabel xref revisi sebelumnya. Nilai ini wajib dirujuk oleh /Prev pada trailer
// revisi baru (ISO 32000-1 bagian 7.5.6); tanpa itu incremental update tidak sah.
func lastStartxrefOffset(pdf []byte) (int, bool) {
	idx := bytes.LastIndex(pdf, []byte("startxref"))
	if idx == -1 {
		return 0, false
	}
	fields := bytes.Fields(pdf[idx+len("startxref"):])
	if len(fields) == 0 {
		return 0, false
	}
	v, err := strconv.Atoi(string(fields[0]))
	if err != nil || v < 0 || v > len(pdf) {
		return 0, false
	}
	return v, true
}

// rootObjectRef membaca nomor objek katalog dokumen dari trailer terakhir.
func rootObjectRef(pdf []byte) (int, bool) {
	all := pdfRootRefRegex.FindAllSubmatch(pdf, -1)
	if len(all) == 0 {
		return 0, false
	}
	id, err := strconv.Atoi(string(all[len(all)-1][1]))
	if err != nil {
		return 0, false
	}
	return id, true
}

// objectIDAt mencari nomor objek pemilik posisi byte tertentu, yaitu header objek
// terdekat sebelum posisi tersebut.
func objectIDAt(pdf []byte, pos int) (int, bool) {
	best, ok := 0, false
	for _, m := range pdfObjHeaderRegex.FindAllSubmatchIndex(pdf, -1) {
		if m[0] >= pos {
			break
		}
		if id, err := strconv.Atoi(string(pdf[m[2]:m[3]])); err == nil {
			best, ok = id, true
		}
	}
	return best, ok
}

// existingSignatureFieldIDs mengumpulkan nomor objek seluruh widget kolom tanda
// tangan (/FT /Sig) yang sudah ada, agar /AcroForm revisi baru tidak menghapus
// kolom tanda tangan penanda tangan sebelumnya.
func existingSignatureFieldIDs(pdf []byte) []int {
	seen := make(map[int]bool)
	var ids []int
	for _, loc := range pdfSigFieldRegex.FindAllIndex(pdf, -1) {
		if id, ok := objectIDAt(pdf, loc[0]); ok && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

// catalogObjectBody mengembalikan isi dalam kamus objek katalog dokumen.
func catalogObjectBody(pdf []byte, catalogID int) (string, bool) {
	re, err := regexp.Compile(`(?m)^[\s]*` + strconv.Itoa(catalogID) + `\s+0\s+obj`)
	if err != nil {
		return "", false
	}
	locs := re.FindAllIndex(pdf, -1)
	if len(locs) == 0 {
		return "", false
	}
	// Revisi terakhir objek katalog yang menang.
	start := locs[len(locs)-1][1]
	endRel := bytes.Index(pdf[start:], []byte("endobj"))
	if endRel == -1 {
		return "", false
	}
	body := strings.TrimSpace(string(pdf[start : start+endRel]))
	if !strings.HasPrefix(body, "<<") || !strings.HasSuffix(body, ">>") {
		return "", false
	}
	return strings.TrimSuffix(strings.TrimPrefix(body, "<<"), ">>"), true
}

type xrefEntry struct {
	objID  int
	offset int
}

// writeXrefSubsections menulis tabel xref dengan entri terurut naik dan
// dikelompokkan menjadi subbagian bernomor berurutan.
func writeXrefSubsections(buf *bytes.Buffer, entries []xrefEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].objID < entries[j].objID })

	buf.WriteString("xref\n")
	for i := 0; i < len(entries); {
		j := i + 1
		for j < len(entries) && entries[j].objID == entries[j-1].objID+1 {
			j++
		}
		fmt.Fprintf(buf, "%d %d\n", entries[i].objID, j-i)
		for _, e := range entries[i:j] {
			fmt.Fprintf(buf, "%010d 00000 n \n", e.offset)
		}
		i = j
	}
}

// escapePDFString meloloskan karakter yang bermakna khusus di dalam literal string PDF.
func escapePDFString(in string) string {
	var b strings.Builder
	for _, r := range in {
		switch r {
		case '\\', '(', ')':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\r', '\n':
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func appendPDFSignatureStructure(originalPDF []byte, signerName, receiptId string, placeholderBytes int) ([]byte, int, int, int, int, int, error) {
	var buf bytes.Buffer
	buf.Write(originalPDF)
	if !bytes.HasSuffix(originalPDF, []byte("\n")) {
		buf.WriteByte('\n')
	}

	// Cari ID objek tertinggi untuk menentukan ID objek baru
	maxObjID := findMaxObjectID(originalPDF)
	sigAnnotID := maxObjID + 1
	sigDictID := maxObjID + 2

	prevStartxref, hasPrev := lastStartxrefOffset(originalPDF)
	catalogID, hasCatalog := rootObjectRef(originalPDF)

	nowStr := time.Now().Format("20060102150405-07'00'")

	// Placeholder panjang tetap untuk kontainer PKCS#7
	hexPlaceholder := strings.Repeat("0", placeholderBytes*2)
	byteRangeFmt := "/ByteRange [ 0 0000000000 0000000000 0000000000 ]"

	// 1. Objek Tanda Tangan Digital (/Type /Sig)
	sigDictStartOffset := buf.Len()
	fmt.Fprintf(&buf, "%d 0 obj\n", sigDictID)
	buf.WriteString("<<\n")
	buf.WriteString("  /Type /Sig\n")
	buf.WriteString("  /Filter /Adobe.PPKLite\n")
	buf.WriteString("  /SubFilter /adbe.pkcs7.detached\n")
	byteRangePosInBuf := buf.Len()
	buf.WriteString("  " + byteRangeFmt + "\n")
	buf.WriteString("  /Contents <")
	startContentsOffset := buf.Len()
	buf.WriteString(hexPlaceholder)
	endContentsOffset := buf.Len()
	buf.WriteString(">\n")
	fmt.Fprintf(&buf, "  /Name (%s)\n", escapePDFString(signerName))
	fmt.Fprintf(&buf, "  /M (D:%s)\n", nowStr)
	buf.WriteString("  /Reason (Tanda Tangan Elektronik Tersertifikasi ARSign)\n")
	buf.WriteString("  /Location (Jakarta, Indonesia)\n")
	buf.WriteString(">>\n")
	buf.WriteString("endobj\n\n")

	// 2. Objek Form Widget Annotation
	sigAnnotOffset := buf.Len()
	fmt.Fprintf(&buf, "%d 0 obj\n", sigAnnotID)
	buf.WriteString("<<\n")
	buf.WriteString("  /Type /Annot\n")
	buf.WriteString("  /Subtype /Widget\n")
	buf.WriteString("  /FT /Sig\n")
	fmt.Fprintf(&buf, "  /T (ARS_SIG_%s)\n", escapePDFString(receiptId))
	fmt.Fprintf(&buf, "  /V %d 0 R\n", sigDictID)
	buf.WriteString("  /F 4\n")
	buf.WriteString("  /Rect [ 350 50 560 142 ]\n")
	buf.WriteString(">>\n")
	buf.WriteString("endobj\n\n")

	entries := []xrefEntry{
		{objID: sigDictID, offset: sigDictStartOffset},
		{objID: sigAnnotID, offset: sigAnnotOffset},
	}

	// 3. Terbitkan ulang objek katalog dengan /AcroForm agar pembaca PDF
	//    (Adobe Acrobat, PDF.js) mengenali kolom tanda tangan. Kolom tanda
	//    tangan revisi sebelumnya tetap dipertahankan di dalam /Fields.
	if hasCatalog {
		if inner, ok := catalogObjectBody(originalPDF, catalogID); ok {
			inner = pdfAcroFormRegex.ReplaceAllString(inner, " ")

			fieldIDs := append(existingSignatureFieldIDs(originalPDF), sigAnnotID)
			refs := make([]string, 0, len(fieldIDs))
			for _, id := range fieldIDs {
				refs = append(refs, fmt.Sprintf("%d 0 R", id))
			}

			catalogOffset := buf.Len()
			fmt.Fprintf(&buf, "%d 0 obj\n", catalogID)
			fmt.Fprintf(&buf, "<< %s /AcroForm << /Fields [ %s ] /SigFlags 3 >> >>\n",
				strings.TrimSpace(inner), strings.Join(refs, " "))
			buf.WriteString("endobj\n\n")

			entries = append(entries, xrefEntry{objID: catalogID, offset: catalogOffset})
		}
	}

	// 4. Tabel Xref Tambahan Inkremental.
	//    Entri wajib terurut naik menurut nomor objek. Implementasi sebelumnya
	//    menulis offset objek /Sig pada slot nomor objek widget (dan sebaliknya),
	//    sehingga tabel xref revisi tanda tangan menunjuk objek yang salah.
	xrefOffset := buf.Len()
	writeXrefSubsections(&buf, entries)

	// 5. Trailer revisi. /Root dan /Prev wajib ada pada incremental update.
	buf.WriteString("trailer\n")
	buf.WriteString("<<\n")
	fmt.Fprintf(&buf, "  /Size %d\n", sigDictID+1)
	if hasCatalog {
		fmt.Fprintf(&buf, "  /Root %d 0 R\n", catalogID)
	}
	if hasPrev {
		fmt.Fprintf(&buf, "  /Prev %d\n", prevStartxref)
	}
	buf.WriteString(">>\n")
	buf.WriteString("startxref\n")
	fmt.Fprintf(&buf, "%d\n", xrefOffset)
	buf.WriteString("%%EOF\n")

	finalBytes := buf.Bytes()

	// Hitung offset akurat untuk parameter /ByteRange
	offset1 := startContentsOffset - 1
	offset2 := endContentsOffset + 1
	offset3 := len(finalBytes) - offset2

	newRange := fmt.Sprintf("/ByteRange [ 0 %010d %010d %010d ]", offset1, offset2, offset3)
	if len(newRange) != len(byteRangeFmt) {
		return nil, 0, 0, 0, 0, 0, fmt.Errorf("panjang nilai /ByteRange (%d) tidak sama dengan slot cadangan (%d)", len(newRange), len(byteRangeFmt))
	}
	copy(finalBytes[byteRangePosInBuf+2:byteRangePosInBuf+2+len(byteRangeFmt)], []byte(newRange))

	return finalBytes, startContentsOffset, endContentsOffset, offset1, offset2, offset3, nil
}

func findMaxObjectID(pdf []byte) int {
	maxID := 10
	lines := bytes.Split(pdf, []byte("\n"))
	for _, l := range lines {
		l = bytes.TrimSpace(l)
		if bytes.HasSuffix(l, []byte(" obj")) {
			parts := bytes.Fields(l)
			if len(parts) >= 2 {
				id, err := strconv.Atoi(string(parts[0]))
				if err == nil && id > maxID {
					maxID = id
				}
			}
		}
	}
	return maxID
}

type PAdESVerifyDetail struct {
	IsValid          bool   `json:"is_valid"`
	SignerFullName   string `json:"signer_fullname"`
	SignerEmail      string `json:"signer_email"`
	Institution      string `json:"institution"`
	ReceiptID        string `json:"receipt_id"`
	SignedAt         string `json:"signed_at"`
	CertSerialNumber string `json:"cert_serial_number"`
	CertIssuer       string `json:"cert_issuer"`
	IsChainValid     bool   `json:"is_chain_valid"`
	IsRevoked        bool   `json:"is_revoked"`
	IntegrityStatus  string `json:"integrity_status"`
	DocumentHash     string `json:"document_hash"`
	Message          string `json:"message"`

	// Rincian per lapisan pemeriksaan, dipakai audit internal.
	IsDocumentIntact bool `json:"is_document_intact"` // digest ByteRange cocok dengan atribut tertandatangani
	IsSignatureValid bool `json:"is_signature_valid"` // tanda tangan kriptografis kontainer CMS sah
	IsPQCPresent     bool `json:"is_pqc_present"`     // lapisan pascakuantum tersedia di dokumen
	IsPQCVerified    bool `json:"is_pqc_verified"`    // lapisan pascakuantum ikut terverifikasi
	TotalSignatures  int  `json:"total_signatures"`   // jumlah revisi tanda tangan di dalam berkas
	ValidSignatures  int  `json:"valid_signatures"`   // jumlah revisi yang lulus seluruh pemeriksaan

	// HasUnsignedChanges menandai adanya byte di luar cakupan tanda tangan terakhir,
	// yaitu revisi inkremental yang ditambahkan setelah dokumen ditandatangani.
	HasUnsignedChanges bool `json:"has_unsigned_changes"`

	// CertSerialNumbers memuat nomor seri sertifikat SETIAP revisi tanda tangan,
	// agar pemeriksaan pencabutan tidak hanya menyentuh penanda tangan terakhir.
	CertSerialNumbers []string `json:"cert_serial_numbers"`
}

// isPDFWhitespace melaporkan apakah byte termasuk pemisah ruang kosong PDF
// (ISO 32000-1 Tabel 1).
func isPDFWhitespace(b byte) bool {
	switch b {
	case 0x00, 0x09, 0x0a, 0x0c, 0x0d, 0x20:
		return true
	}
	return false
}

// parseASN1DERLength membaca tag SEQUENCE dan length ASN.1 DER untuk memotong hex secara presisi tanpa merusak trailing byte
func parseASN1DERLength(derHex string) (int, error) {
	if len(derHex) < 12 {
		return 0, fmt.Errorf("data hex terlalu pendek")
	}
	headerBytes, err := hex.DecodeString(derHex[:12])
	if err != nil {
		return 0, err
	}
	if headerBytes[0] != 0x30 {
		return 0, fmt.Errorf("bukan ASN.1 SEQUENCE (tag: %02x)", headerBytes[0])
	}
	lenByte := headerBytes[1]
	if lenByte <= 0x7f {
		return int(lenByte) + 2, nil
	}
	numLenBytes := int(lenByte & 0x7f)
	if numLenBytes == 1 {
		return int(headerBytes[2]) + 3, nil
	} else if numLenBytes == 2 {
		contentLen := int(headerBytes[2])<<8 | int(headerBytes[3])
		return contentLen + 4, nil
	} else if numLenBytes == 3 {
		contentLen := int(headerBytes[2])<<16 | int(headerBytes[3])<<8 | int(headerBytes[4])
		return contentLen + 5, nil
	} else if numLenBytes == 4 {
		contentLen := int(headerBytes[2])<<24 | int(headerBytes[3])<<16 | int(headerBytes[4])<<8 | int(headerBytes[5])
		return contentLen + 6, nil
	}
	return 0, fmt.Errorf("panjang ASN.1 tidak didukung")
}

// signedAttributes memuat atribut tertandatangani (authenticatedAttributes) CMS
// hasil parsing ASN.1 yang sah. Implementasi sebelumnya memindai OID secara
// mentah dengan bytes.Index sehingga kemunculan pertama di mana pun dalam DER
// yang menang — termasuk nilai umpan yang ditanam penyerang di luar cakupan
// tanda tangan.
type signedAttributes struct {
	ContentType   asn1.ObjectIdentifier
	MessageDigest []byte
	SigningTime   time.Time
	PQCPayload    string
}

// parseSignedAttributes mengurai authenticatedAttributes SignerInfo secara ASN.1.
func parseSignedAttributes(raw asn1.RawValue) (*signedAttributes, error) {
	if len(raw.FullBytes) == 0 {
		return nil, fmt.Errorf("SignerInfo tidak memuat authenticatedAttributes")
	}

	// authenticatedAttributes dikirim bertag [0] IMPLICIT. Ubah ke SEQUENCE OF
	// agar dapat diurai menjadi []Attribute oleh encoding/asn1.
	seq := make([]byte, len(raw.FullBytes))
	copy(seq, raw.FullBytes)
	seq[0] = 0x30

	var attrs []Attribute
	if _, err := asn1.Unmarshal(seq, &attrs); err != nil {
		return nil, fmt.Errorf("gagal parse authenticatedAttributes: %w", err)
	}

	out := &signedAttributes{}
	for _, a := range attrs {
		switch {
		case a.Type.Equal(oidContentType):
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(a.Value.Bytes, &oid); err == nil {
				out.ContentType = oid
			}
		case a.Type.Equal(oidMessageDigest):
			var md []byte
			if _, err := asn1.Unmarshal(a.Value.Bytes, &md); err != nil {
				return nil, fmt.Errorf("atribut messageDigest tidak valid: %w", err)
			}
			out.MessageDigest = md
		case a.Type.Equal(oidSigningTime):
			var t time.Time
			if _, err := asn1.Unmarshal(a.Value.Bytes, &t); err == nil {
				out.SigningTime = t
			}
		case a.Type.Equal(oidPQCDualSignature):
			var payload string
			if _, err := asn1.Unmarshal(a.Value.Bytes, &payload); err == nil {
				out.PQCPayload = payload
			}
		}
	}

	if len(out.MessageDigest) == 0 {
		return nil, fmt.Errorf("atribut messageDigest tidak ditemukan pada authenticatedAttributes")
	}
	return out, nil
}

// parsePQCPayload memecah muatan atribut pascakuantum ARSign.
func parsePQCPayload(payload string) (receiptID, pubKeyHex, sigHex string) {
	for _, part := range strings.Split(payload, "|") {
		switch {
		case strings.HasPrefix(part, "RECEIPT:"):
			receiptID = strings.TrimPrefix(part, "RECEIPT:")
		case strings.HasPrefix(part, "PUB:"):
			pubKeyHex = strings.TrimPrefix(part, "PUB:")
		case strings.HasPrefix(part, "SIG:"):
			sigHex = strings.TrimPrefix(part, "SIG:")
		}
	}
	return receiptID, pubKeyHex, sigHex
}

// byteRangeValues memuat empat angka parameter /ByteRange satu revisi tanda tangan.
type byteRangeValues struct {
	o0, l0, o1, l1 int
}

var byteRangeRegex = regexp.MustCompile(`/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]`)

// collectByteRanges mengumpulkan seluruh revisi tanda tangan di dalam berkas.
func collectByteRanges(pdfData []byte) ([]byteRangeValues, error) {
	matches := byteRangeRegex.FindAllSubmatch(pdfData, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("tidak ditemukan struktur tanda tangan elektronik PAdES (/ByteRange) pada berkas")
	}

	out := make([]byteRangeValues, 0, len(matches))
	for _, m := range matches {
		var v byteRangeValues
		var err error
		if v.o0, err = strconv.Atoi(string(m[1])); err != nil {
			return nil, fmt.Errorf("nilai /ByteRange tidak valid: %w", err)
		}
		if v.l0, err = strconv.Atoi(string(m[2])); err != nil {
			return nil, fmt.Errorf("nilai /ByteRange tidak valid: %w", err)
		}
		if v.o1, err = strconv.Atoi(string(m[3])); err != nil {
			return nil, fmt.Errorf("nilai /ByteRange tidak valid: %w", err)
		}
		if v.l1, err = strconv.Atoi(string(m[4])); err != nil {
			return nil, fmt.Errorf("nilai /ByteRange tidak valid: %w", err)
		}
		if v.o0 != 0 || v.l0 <= 0 || v.o1 <= v.l0 || v.l1 <= 0 || (v.o1+v.l1) > len(pdfData) {
			return nil, fmt.Errorf("parameter offset /ByteRange (%d, %d, %d, %d) melebihi ukuran berkas PDF (%d)", v.o0, v.l0, v.o1, v.l1, len(pdfData))
		}
		out = append(out, v)
	}
	return out, nil
}

// verifySignatureRevision memverifikasi satu revisi tanda tangan PAdES.
func verifySignatureRevision(pdfData []byte, br byteRangeValues) (*PAdESVerifyDetail, error) {
	// 1. Hitung digest aktual atas rentang byte yang dicakup tanda tangan
	h := sha256.New()
	h.Write(pdfData[br.o0 : br.o0+br.l0])
	h.Write(pdfData[br.o1 : br.o1+br.l1])
	actualDigest := h.Sum(nil)
	actualDigestHex := hex.EncodeToString(actualDigest)

	// 2. Ekstraksi hex kontainer PKCS#7 pada lubang /Contents
	rawHex := strings.Trim(string(pdfData[br.l0:br.o1]), "<> \r\n\t")

	// Panjang DER eksak dibaca dari header ASN.1 ContentInfo
	derLen, errLen := parseASN1DERLength(rawHex)
	if errLen == nil && derLen > 0 && derLen*2 <= len(rawHex) {
		rawHex = rawHex[:derLen*2]
	} else {
		rawHex = strings.TrimRight(rawHex, "0")
		if len(rawHex)%2 != 0 {
			rawHex += "0"
		}
	}

	pkcs7Bytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, fmt.Errorf("gagal membaca kontainer PKCS#7 /Contents: %w", err)
	}

	// 3. Urai ContentInfo & SignedData
	var ci ContentInfo
	if _, err := asn1.Unmarshal(pkcs7Bytes, &ci); err != nil {
		return nil, fmt.Errorf("gagal parse struktur ASN.1 ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("ContentInfo bukan tipe SignedData")
	}

	var sd SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("gagal parse struktur ASN.1 SignedData: %w", err)
	}
	if len(sd.SignerInfos) == 0 {
		return nil, fmt.Errorf("SignedData tidak memuat SignerInfo")
	}

	// 4. Sertifikat di dalam SignedData
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("gagal mengekstrak sertifikat digital penanda tangan: %v", err)
	}

	si := sd.SignerInfos[0]
	var signerCert *x509.Certificate
	for _, c := range certs {
		if c.SerialNumber.Cmp(si.IssuerAndSerial.SerialNumber) == 0 {
			signerCert = c
			break
		}
	}
	if signerCert == nil {
		return nil, fmt.Errorf("sertifikat penanda tangan yang dirujuk SignerInfo tidak ada di dalam kontainer")
	}

	// 5. Atribut tertandatangani diurai secara ASN.1
	attrs, err := parseSignedAttributes(si.AuthAttributes)
	if err != nil {
		return nil, err
	}
	if len(attrs.ContentType) > 0 && !attrs.ContentType.Equal(oidData) {
		return nil, fmt.Errorf("atribut contentType bukan id-data")
	}

	// 6. Integritas dokumen: digest aktual vs digest yang ikut ditandatangani
	documentIntact := len(attrs.MessageDigest) == len(actualDigest) &&
		subtle.ConstantTimeCompare(attrs.MessageDigest, actualDigest) == 1

	// 7. Tanda tangan kriptografis kontainer CMS atas atribut tertandatangani.
	//    Pemeriksaan ini WAJIB lulus: ia yang mengikat digest dokumen, waktu
	//    penandatanganan, dan kunci publik pascakuantum kepada sertifikat.
	signatureValid := false
	attrsForVerify := make([]byte, len(si.AuthAttributes.FullBytes))
	copy(attrsForVerify, si.AuthAttributes.FullBytes)
	attrsForVerify[0] = 0x31 // SET OF, sesuai CMS RFC 5652
	hAttrs := sha256.Sum256(attrsForVerify)
	if rsaPub, ok := signerCert.PublicKey.(*rsa.PublicKey); ok {
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hAttrs[:], si.Signature); err == nil {
			signatureValid = true
		}
	}

	// 8. Rantai sertifikat ke Root CA ARSign
	chainValid := false
	ca, caErr := GetARSignAuthority()
	if caErr == nil && ca != nil {
		roots := x509.NewCertPool()
		roots.AddCert(ca.RootCert)
		intermediates := x509.NewCertPool()
		intermediates.AddCert(ca.SubCACert)

		if _, err := signerCert.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err == nil {
			chainValid = true
		}
	}

	// 9. Lapisan tanda tangan pascakuantum
	receiptID, mldsaPubKeyHex, mldsaSigHex := parsePQCPayload(attrs.PQCPayload)
	pqcPresent := mldsaPubKeyHex != "" && mldsaSigHex != ""
	pqcVerified := false
	if pqcPresent {
		pubBytes, pErr := hex.DecodeString(mldsaPubKeyHex)
		sigBytes, sErr := hex.DecodeString(mldsaSigHex)
		if pErr == nil && sErr == nil {
			if pqcRes, vErr := VerifyMLDSA("ML-DSA-65", pubBytes, actualDigest, sigBytes); vErr == nil && pqcRes.Valid {
				pqcVerified = true
			}
		}
	}

	// 10. Keabsahan akhir. Tanda tangan kriptografis kontainer tidak lagi boleh
	//     digantikan oleh lapisan pascakuantum: dulu `(rsaValid || pqcValid)`
	//     dengan pqcValid berinisial true membuat dokumen bertanda tangan rusak
	//     tetap dinyatakan sah ketika atribut pascakuantum dihapus.
	isValid := documentIntact && signatureValid && chainValid && (!pqcPresent || pqcVerified)

	timeStr := attrs.SigningTime.Format("02-01-2006 15:04:05")
	if attrs.SigningTime.IsZero() {
		timeStr = signerCert.NotBefore.Format("02-01-2006 15:04:05")
	}

	signerName := signerCert.Subject.CommonName
	if signerName == "" {
		signerName = "Penanda Tangan Sah"
	}
	email := ""
	if len(signerCert.EmailAddresses) > 0 {
		email = signerCert.EmailAddresses[0]
	}
	inst := ""
	if len(signerCert.Subject.Organization) > 0 {
		inst = signerCert.Subject.Organization[0]
	}

	msg := "Dokumen Asli & Utuh — Belum pernah diubah atau dimodifikasi sejak ditandatangani."
	switch {
	case !documentIntact:
		msg = "DOKUMEN TIDAK VALID: Berkas telah mengalami modifikasi atau manipulasi setelah ditandatangani!"
	case !signatureValid:
		msg = "DOKUMEN TIDAK VALID: Tanda tangan digital kriptografis tidak cocok dengan sertifikat penanda tangan."
	case pqcPresent && !pqcVerified:
		msg = "DOKUMEN TIDAK VALID: Lapisan tanda tangan tersertifikasi tambahan gagal diverifikasi."
	case !chainValid:
		msg = "DOKUMEN TIDAK VALID: Rantai sertifikat digital penerbit tidak dapat diverifikasi."
	}

	return &PAdESVerifyDetail{
		IsValid:          isValid,
		SignerFullName:   signerName,
		SignerEmail:      email,
		Institution:      inst,
		ReceiptID:        receiptID,
		SignedAt:         timeStr,
		CertSerialNumber: signerCert.SerialNumber.String(),
		CertIssuer:       signerCert.Issuer.CommonName,
		IsChainValid:     chainValid,
		IsRevoked:        false,
		IntegrityStatus:  msg,
		DocumentHash:     actualDigestHex,
		Message:          msg,

		IsDocumentIntact: documentIntact,
		IsSignatureValid: signatureValid,
		IsPQCPresent:     pqcPresent,
		IsPQCVerified:    pqcVerified,
	}, nil
}

// VerifyPDFPAdES memverifikasi keaslian dan integritas SELURUH revisi tanda tangan
// PAdES ISO 32000-1 pada dokumen PDF. Rincian yang dikembalikan berasal dari revisi
// terakhir (penanda tangan terkini), namun status keabsahan hanya SAH bila setiap
// revisi tanda tangan lulus pemeriksaan. Implementasi sebelumnya hanya memeriksa
// /ByteRange terakhir, sehingga tanda tangan sebelumnya pada dokumen multi-signature
// tidak pernah diverifikasi.
func VerifyPDFPAdES(pdfData []byte) (*PAdESVerifyDetail, error) {
	ranges, err := collectByteRanges(pdfData)
	if err != nil {
		return nil, err
	}

	var last *PAdESVerifyDetail
	validCount := 0
	var firstFailure *PAdESVerifyDetail
	serials := make([]string, 0, len(ranges))

	for idx, br := range ranges {
		detail, err := verifySignatureRevision(pdfData, br)
		if err != nil {
			return nil, fmt.Errorf("revisi tanda tangan ke-%d tidak dapat diverifikasi: %w", idx+1, err)
		}
		if detail.IsValid {
			validCount++
		} else if firstFailure == nil {
			firstFailure = detail
		}
		serials = append(serials, detail.CertSerialNumber)
		last = detail
	}

	last.TotalSignatures = len(ranges)
	last.ValidSignatures = validCount
	last.CertSerialNumbers = serials

	// Cakupan tanda tangan terakhir wajib mencapai akhir berkas. Tanpa syarat ini,
	// penyerang dapat menambahkan revisi inkremental baru (isi halaman, anotasi)
	// di belakang rentang yang ditandatangani: byte tambahan itu tidak tercakup
	// tanda tangan mana pun, namun dokumen tetap dinyatakan asli dan utuh.
	// Ini kelas serangan Incremental Saving Attack pada tanda tangan PDF.
	lastRange := ranges[len(ranges)-1]
	coverageEnd := lastRange.o1 + lastRange.l1
	for _, b := range pdfData[coverageEnd:] {
		if !isPDFWhitespace(b) {
			last.HasUnsignedChanges = true
			break
		}
	}
	if last.HasUnsignedChanges {
		last.IsValid = false
		last.IntegrityStatus = "DOKUMEN TIDAK VALID: Terdapat perubahan yang ditambahkan setelah dokumen ditandatangani dan tidak tercakup tanda tangan mana pun."
		last.Message = last.IntegrityStatus
		return last, nil
	}

	if validCount != len(ranges) {
		last.IsValid = false
		if firstFailure != nil && firstFailure != last {
			last.IntegrityStatus = fmt.Sprintf("DOKUMEN TIDAK VALID: %d dari %d tanda tangan pada dokumen ini gagal diverifikasi. %s",
				len(ranges)-validCount, len(ranges), firstFailure.Message)
			last.Message = last.IntegrityStatus
		}
	}

	return last, nil
}
