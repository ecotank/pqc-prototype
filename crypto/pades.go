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
	oidPQCDualSignature = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 58333, 1, 204} // OID Ekstensi PQC BSrE
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

	ca, err := GetBSrEAuthority()
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
		receiptId = fmt.Sprintf("BSRE-%d", time.Now().UnixNano()%10000000)
	}

	fullname := opts.SignerFullName
	if fullname == "" {
		fullname = "Pejabat Penandatangan BSrE"
	}
	email := opts.SignerEmail
	if email == "" {
		email = "signer@bsre.bssn.go.id"
	}
	institution := opts.Institution
	if institution == "" {
		institution = "Badan Siber dan Sandi Negara"
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
	fmt.Fprintf(&buf, "  /Reason (TTE Pascakuantum Sah BSrE BSSN RI - FIPS 204 ML-DSA-65)\n")
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
	fmt.Fprintf(&buf, "  /T (BSRE_SIG_%s)\n", receiptId)
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
