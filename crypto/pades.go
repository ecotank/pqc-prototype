package crypto

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
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
	unfilledPlaceholderTag := []byte("/Contents <00000000")
	idxPlaceholder := bytes.LastIndex(pdfData, unfilledPlaceholderTag)

	var workingPDF []byte
	var startContents, endContents int
	var offset1, offset2, offset3 int
	const placeholderLen = 32768 // 32768 byte DER = 65536 karakter hexa

	if idxPlaceholder != -1 {
		// Ditemukan slot placeholder alokasi tanda tangan baru yang belum terisi
		workingPDF = make([]byte, len(pdfData))
		copy(workingPDF, pdfData)

		startContents = idxPlaceholder + len("/Contents <")
		endContents = bytes.IndexByte(workingPDF[startContents:], '>')
		if endContents == -1 {
			return nil, nil, fmt.Errorf("tanda penutup '>' untuk /Contents tidak ditemukan")
		}
		endContents += startContents

		offset1 = startContents - 1
		offset2 = endContents + 1
		offset3 = len(workingPDF) - offset2

		// Perbarui /ByteRange placeholder spesifik untuk signature baru ini
		prefixForBR := workingPDF[:startContents]
		byteRangePos := bytes.LastIndex(prefixForBR, []byte("/ByteRange"))
		if byteRangePos != -1 {
			endBracket := bytes.IndexByte(workingPDF[byteRangePos:], ']')
			if endBracket != -1 {
				oldRange := workingPDF[byteRangePos : byteRangePos+endBracket+1]
				newRange := fmt.Sprintf("/ByteRange [ 0 %010d %010d %010d ]", offset1, offset2, offset3)
				if len(newRange) <= len(oldRange) {
					padded := []byte(fmt.Sprintf("%-"+strconv.Itoa(len(oldRange))+"s", newRange))
					copy(workingPDF[byteRangePos:], padded)
				}
			}
		}
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

	nowStr := time.Now().Format("20060102150405-07'00'")

	// Placeholder panjang tetap 16384 karakter hexa
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
	fmt.Fprintf(&buf, "  /Name (%s)\n", signerName)
	fmt.Fprintf(&buf, "  /M (D:%s)\n", nowStr)
	fmt.Fprintf(&buf, "  /Reason (TTE Pascakuantum Sah ARSign - FIPS 204 ML-DSA-65)\n")
	fmt.Fprintf(&buf, "  /Location (Jakarta, Indonesia)\n")
	buf.WriteString(">>\n")
	buf.WriteString("endobj\n\n")

	// 2. Objek Form Widget Annotation
	sigAnnotOffset := buf.Len()
	fmt.Fprintf(&buf, "%d 0 obj\n", sigAnnotID)
	buf.WriteString("<<\n")
	buf.WriteString("  /Type /Annot\n")
	buf.WriteString("  /Subtype /Widget\n")
	buf.WriteString("  /FT /Sig\n")
	fmt.Fprintf(&buf, "  /T (ARS_SIG_%s)\n", receiptId)
	fmt.Fprintf(&buf, "  /V %d 0 R\n", sigDictID)
	buf.WriteString("  /F 4\n")
	buf.WriteString("  /Rect [ 350 50 560 142 ]\n")
	buf.WriteString(">>\n")
	buf.WriteString("endobj\n\n")

	// 3. Xref Tambahan Inkremental
	xrefOffset := buf.Len()
	buf.WriteString("xref\n")
	fmt.Fprintf(&buf, "%d 2\n", sigAnnotID)
	fmt.Fprintf(&buf, "%010d 00000 n \n", sigDictStartOffset)
	fmt.Fprintf(&buf, "%010d 00000 n \n", sigAnnotOffset)

	// 4. Trailer
	buf.WriteString("trailer\n")
	buf.WriteString("<<\n")
	fmt.Fprintf(&buf, "  /Size %d\n", sigDictID+1)
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
}

// VerifyPDFPAdES memverifikasi keaslian dan integritas tanda tangan PAdES ISO 32000-1 pada dokumen PDF
func VerifyPDFPAdES(pdfData []byte) (*PAdESVerifyDetail, error) {
	// 1. Cari /ByteRange terakhir
	brRegex := regexp.MustCompile(`/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]`)
	matches := brRegex.FindAllSubmatchIndex(pdfData, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("tidak ditemukan struktur tanda tangan elektronik PAdES (/ByteRange) pada berkas")
	}

	lastMatch := matches[len(matches)-1]
	brStr := string(pdfData[lastMatch[0]:lastMatch[1]])
	submatches := brRegex.FindStringSubmatch(brStr)
	if len(submatches) < 5 {
		return nil, fmt.Errorf("format /ByteRange tanda tangan tidak valid")
	}

	o0, _ := strconv.Atoi(submatches[1])
	l0, _ := strconv.Atoi(submatches[2])
	o1, _ := strconv.Atoi(submatches[3])
	l1, _ := strconv.Atoi(submatches[4])

	if o0 != 0 || l0 <= 0 || o1 <= l0 || l1 <= 0 || (o1+l1) > len(pdfData) {
		return nil, fmt.Errorf("parameter offset /ByteRange (%d, %d, %d, %d) melebihi ukuran berkas PDF (%d)", o0, l0, o1, l1, len(pdfData))
	}

	// 2. Hitung digest aktual ByteRange dokumen
	h := sha256.New()
	h.Write(pdfData[o0 : o0+l0])
	h.Write(pdfData[o1 : o1+l1])
	actualDigest := h.Sum(nil)
	actualDigestHex := hex.EncodeToString(actualDigest)

	// 3. Ekstraksi hex PKCS#7 di antara l0 dan o1
	contentsSlice := pdfData[l0:o1]
	rawHex := strings.Trim(string(contentsSlice), "<> \r\n\t")
	// Hilangkan trailing zeros yang merupakan padding alokasi PDF
	rawHex = strings.TrimRight(rawHex, "0")
	if len(rawHex)%2 != 0 {
		rawHex += "0"
	}

	pkcs7Bytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, fmt.Errorf("gagal membaca kontainer PKCS#7 /Contents: %w", err)
	}

	// 4. Unmarshal PKCS#7 ContentInfo & SignedData
	var ci ContentInfo
	if _, err := asn1.Unmarshal(pkcs7Bytes, &ci); err != nil {
		return nil, fmt.Errorf("gagal parse struktur ASN.1 ContentInfo: %w", err)
	}

	var sd SignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("gagal parse struktur ASN.1 SignedData: %w", err)
	}

	if len(sd.SignerInfos) == 0 {
		return nil, fmt.Errorf("SignedData tidak memuat SignerInfo")
	}

	// 5. Parse Sertifikat di dalam SignedData
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("gagal mengekstrak sertifikat digital penanda tangan: %v", err)
	}

	var signerCert *x509.Certificate
	si := sd.SignerInfos[0]
	for _, c := range certs {
		if c.SerialNumber.Cmp(si.IssuerAndSerial.SerialNumber) == 0 {
			signerCert = c
			break
		}
	}
	if signerCert == nil {
		signerCert = certs[0]
	}

	// 6. Ekstraksi Digest Dokumen, Waktu TTE, dan Metadata PQC dari PKCS#7
	var embeddedDigest []byte
	mdOidBytes := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04}
	idxMD := bytes.Index(pkcs7Bytes, mdOidBytes)
	if idxMD != -1 && idxMD+len(mdOidBytes)+40 <= len(pkcs7Bytes) {
		start := idxMD + len(mdOidBytes)
		octIdx := bytes.IndexByte(pkcs7Bytes[start:start+10], 0x04)
		if octIdx != -1 {
			digStart := start + octIdx + 2
			if digStart+32 <= len(pkcs7Bytes) {
				embeddedDigest = pkcs7Bytes[digStart : digStart+32]
			}
		}
	}

	var signingTime time.Time
	timeOidBytes := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05}
	idxTime := bytes.Index(pkcs7Bytes, timeOidBytes)
	if idxTime != -1 && idxTime+40 <= len(pkcs7Bytes) {
		slice := pkcs7Bytes[idxTime : idxTime+40]
		if tPos := bytes.IndexByte(slice, 0x17); tPos != -1 && tPos+15 < len(slice) {
			tLen := int(slice[tPos+1])
			if tPos+2+tLen <= len(slice) {
				tBytes := slice[tPos+2 : tPos+2+tLen]
				signingTime, _ = time.Parse("060102150405Z", string(tBytes))
			}
		}
	}

	var receiptID, mldsaPubKeyHex, mldsaSigHex string
	pqcOidBytes := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xc7, 0x5d, 0x01, 0x81, 0x4c}
	idxPQC := bytes.Index(pkcs7Bytes, pqcOidBytes)
	if idxPQC != -1 {
		rawStr := string(pkcs7Bytes[idxPQC:])
		if rIdx := strings.Index(rawStr, "ML-DSA-65|RECEIPT:"); rIdx != -1 {
			endStr := strings.IndexByte(rawStr[rIdx:], 0x00)
			if endStr == -1 {
				endStr = len(rawStr[rIdx:])
			}
			pqcPayload := rawStr[rIdx : rIdx+endStr]
			parts := strings.Split(pqcPayload, "|")
			for _, p := range parts {
				if strings.HasPrefix(p, "RECEIPT:") {
					receiptID = strings.TrimPrefix(p, "RECEIPT:")
				} else if strings.HasPrefix(p, "PUB:") {
					mldsaPubKeyHex = strings.TrimPrefix(p, "PUB:")
				} else if strings.HasPrefix(p, "SIG:") {
					mldsaSigHex = strings.TrimPrefix(p, "SIG:")
				}
			}
		}
	}

	// 7. Validasi Integritas Dokumen (ByteRange hash vs embedded digest)
	digestMatch := len(embeddedDigest) == 32 && bytes.Equal(actualDigest, embeddedDigest)

	// 8. Validasi Signature RSA pada AuthAttributes
	rsaValid := false
	if len(si.AuthAttributes.FullBytes) > 0 {
		attrsForVerify := make([]byte, len(si.AuthAttributes.FullBytes))
		copy(attrsForVerify, si.AuthAttributes.FullBytes)
		attrsForVerify[0] = 0x31 // SET OF tag
		hAttrs := sha256.Sum256(attrsForVerify)
		if rsaPub, ok := signerCert.PublicKey.(*rsa.PublicKey); ok {
			if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hAttrs[:], si.Signature); err == nil {
				rsaValid = true
			}
		}
	}

	// 9. Validasi Rantai Sertifikat (Chain)
	chainValid := true
	ca, caErr := GetARSignAuthority()
	if caErr == nil && ca != nil {
		roots := x509.NewCertPool()
		roots.AddCert(ca.RootCert)
		intermediates := x509.NewCertPool()
		intermediates.AddCert(ca.SubCACert)

		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if _, err := signerCert.Verify(opts); err != nil {
			chainValid = false
		}
	}

	// 10. Jika ada tanda tangan pascakuantum ML-DSA, verifikasi juga
	pqcValid := true
	if mldsaPubKeyHex != "" && mldsaSigHex != "" {
		pubBytes, pErr := hex.DecodeString(mldsaPubKeyHex)
		sigBytes, sErr := hex.DecodeString(mldsaSigHex)
		if pErr == nil && sErr == nil {
			pqcRes, vErr := VerifyMLDSA("ML-DSA-65", pubBytes, actualDigest, sigBytes)
			if vErr != nil || !pqcRes.Valid {
				pqcValid = false
			}
		}
	}

	timeStr := signingTime.Format("02-01-2006 15:04:05")
	if signingTime.IsZero() {
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

	isValid := digestMatch && (rsaValid || pqcValid) && chainValid

	msg := "Dokumen Asli & Utuh — Belum pernah diubah atau dimodifikasi sejak ditandatangani."
	if !digestMatch {
		msg = "DOKUMEN TIDAK VALID: Berkas telah mengalami modifikasi atau manipulasi setelah ditandatangani!"
	} else if !rsaValid && !pqcValid {
		msg = "DOKUMEN TIDAK VALID: Tanda tangan digital kriptografis tidak cocok."
	} else if !chainValid {
		msg = "DOKUMEN PERINGATAN: Rantai sertifikat digital penerbit tidak dapat diverifikasi."
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
	}, nil
}
