package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ARSignAuthority mengelola infrastruktur kunci publik (PKI) resmi ARSign
type ARSignAuthority struct {
	mu           sync.RWMutex
	RootKey      *rsa.PrivateKey
	RootCert     *x509.Certificate
	RootCertDER  []byte
	SubCAKey     *rsa.PrivateKey
	SubCACert    *x509.Certificate
	SubCACertDER []byte
}

var (
	globalCA     *ARSignAuthority
	globalCAErr  error
	globalCAOnce sync.Once
)

// GetARSignAuthority mengembalikan instance tunggal Otoritas Sertifikasi ARSign.
// Error inisialisasi disimpan di variabel paket; tanpa itu sync.Once membuat
// pemanggilan kedua mengembalikan (nil, nil) dan memicu nil dereference di pemanggil.
func GetARSignAuthority() (*ARSignAuthority, error) {
	globalCAOnce.Do(func() {
		globalCA, globalCAErr = initARSignAuthority()
	})
	if globalCAErr != nil {
		return nil, globalCAErr
	}
	if globalCA == nil {
		return nil, fmt.Errorf("otoritas sertifikasi ARSign tidak tersedia")
	}
	return globalCA, nil
}

// caKeysDir mengembalikan direktori penyimpanan material CA.
// Dapat dialihkan lewat ARSIGN_CA_DIR agar proses uji tidak menulis ke direktori kerja repo.
func caKeysDir() string {
	if dir := strings.TrimSpace(os.Getenv("ARSIGN_CA_DIR")); dir != "" {
		return dir
	}
	return "ca_keys"
}

func initARSignAuthority() (*ARSignAuthority, error) {
	caDir := caKeysDir()
	if err := os.MkdirAll(caDir, 0700); err != nil {
		return nil, fmt.Errorf("gagal membuat direktori penyimpanan CA: %w", err)
	}

	rootKeyPath := filepath.Join(caDir, "arsign_root_ca.key")
	rootCertPath := filepath.Join(caDir, "arsign_root_ca.crt")
	subKeyPath := filepath.Join(caDir, "arsign_sub_ca.key")
	subCertPath := filepath.Join(caDir, "arsign_sub_ca.crt")

	// 1. Periksa apakah kunci & sertifikat CA sudah tersimpan permanen di disk
	if fileExists(rootKeyPath) && fileExists(rootCertPath) && fileExists(subKeyPath) && fileExists(subCertPath) {
		rootKey, rootCert, rootCertDER, err := loadKeyAndCert(rootKeyPath, rootCertPath)
		if err == nil {
			subKey, subCert, subCertDER, sErr := loadKeyAndCert(subKeyPath, subCertPath)
			if sErr == nil {
				return &ARSignAuthority{
					RootKey:      rootKey,
					RootCert:     rootCert,
					RootCertDER:  rootCertDER,
					SubCAKey:     subKey,
					SubCACert:    subCert,
					SubCACertDER: subCertDER,
				}, nil
			}
		}
	}

	// 2. Jika belum ada di disk, bangkitkan Kunci & Sertifikat Root CA ARSign (Masa Berlaku 20 Tahun)
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("gagal bangkitkan kunci Root CA: %w", err)
	}

	rootSubj := pkix.Name{
		CommonName:         "ARSign Root CA (Pascakuantum Ready)",
		Organization:       []string{"ARSign Trust Network"},
		OrganizationalUnit: []string{"Otoritas Sertifikasi Digital"},
		Country:            []string{"ID"},
		Province:           []string{"DKI Jakarta"},
		Locality:           []string{"Jakarta Selatan"},
	}

	rootSKID, err := computeSKI(&rootKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("gagal menghitung SubjectKeyIdentifier Root CA: %w", err)
	}

	rootSerial, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("gagal membangkitkan serial Root CA: %w", err)
	}

	rootTemplate := x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               rootSubj,
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		MaxPathLenZero:        false,
		SubjectKeyId:          rootSKID,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat sertifikat Root CA: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootCertDER)
	if err != nil {
		return nil, fmt.Errorf("gagal parsing Root CA: %w", err)
	}

	// 3. Bangkitkan Kunci & Sertifikat Sub-CA Penerbit TTE ARSign (10 Tahun)
	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("gagal bangkitkan kunci Sub-CA: %w", err)
	}

	subSubj := pkix.Name{
		CommonName:         "ARSign Sub-CA Pelayanan TTE Pascakuantum",
		Organization:       []string{"ARSign Trust Network"},
		OrganizationalUnit: []string{"Layanan TTE Pascakuantum"},
		Country:            []string{"ID"},
	}

	subSKID, err := computeSKI(&subKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("gagal menghitung SubjectKeyIdentifier Sub-CA: %w", err)
	}

	subSerial, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("gagal membangkitkan serial Sub-CA: %w", err)
	}

	subTemplate := x509.Certificate{
		SerialNumber:          subSerial,
		Subject:               subSubj,
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
		SubjectKeyId:          subSKID,
		AuthorityKeyId:        rootSKID,
	}

	subCertDER, err := x509.CreateCertificate(rand.Reader, &subTemplate, rootCert, &subKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat sertifikat Sub-CA: %w", err)
	}
	subCert, err := x509.ParseCertificate(subCertDER)
	if err != nil {
		return nil, fmt.Errorf("gagal parsing Sub-CA: %w", err)
	}

	// 4. Simpan Kunci & Sertifikat ke Disk Permanen
	_ = saveKeyAndCert(rootKeyPath, rootCertPath, rootKey, rootCertDER)
	_ = saveKeyAndCert(subKeyPath, subCertPath, subKey, subCertDER)

	// Salinan PEM untuk kemudahan akses ditulis DI DALAM direktori CA.
	// Sebelumnya ditulis ke direktori kerja, sehingga `go test ./crypto` menimpa
	// crypto/ARSIGN_*.crt|pem dan memunculkan diff palsu pada repo.
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertDER})
	subPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCertDER})
	_ = os.WriteFile(filepath.Join(caDir, "ARSIGN_Root_and_SubCA.pem"), append(subPEM, rootPEM...), 0644)
	_ = os.WriteFile(filepath.Join(caDir, "ARSIGN_Root_CA.crt"), rootPEM, 0644)
	_ = os.WriteFile(filepath.Join(caDir, "ARSIGN_Sub_CA.crt"), subPEM, 0644)

	return &ARSignAuthority{
		RootKey:      rootKey,
		RootCert:     rootCert,
		RootCertDER:  rootCertDER,
		SubCAKey:     subKey,
		SubCACert:    subCert,
		SubCACertDER: subCertDER,
	}, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func saveKeyAndCert(keyPath, certPath string, key *rsa.PrivateKey, certDER []byte) error {
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return os.WriteFile(certPath, certPEM, 0644)
}

func loadKeyAndCert(keyPath, certPath string) (*rsa.PrivateKey, *x509.Certificate, []byte, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, nil, fmt.Errorf("gagal decode key PEM %s", keyPath)
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, nil, fmt.Errorf("gagal decode cert PEM %s", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	return key, cert, certBlock.Bytes, nil
}

// CreateCRL menerbitkan Certificate Revocation List (CRL) resmi X.509 RFC 5280
func (ca *ARSignAuthority) CreateCRL(revokedList []pkix.RevokedCertificate) ([]byte, error) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	crlDER, err := ca.SubCACert.CreateCRL(rand.Reader, ca.SubCAKey, revokedList, time.Now(), time.Now().Add(7*24*time.Hour))
	if err != nil {
		return nil, fmt.Errorf("gagal menerbitkan CRL: %w", err)
	}
	return crlDER, nil
}

// ExportCRLPEM mengekspor CRL dalam format teks PEM
func (ca *ARSignAuthority) ExportCRLPEM(revokedList []pkix.RevokedCertificate) (string, error) {
	crlDER, err := ca.CreateCRL(revokedList)
	if err != nil {
		return "", err
	}
	crlPEM := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	return string(crlPEM), nil
}

// IssueSignerCertificate menerbitkan sertifikat digital resmi X.509 penanda tangan
func (ca *ARSignAuthority) IssueSignerCertificate(fullname, email, nikNip, institution string, signerPubKey *rsa.PublicKey) (*x509.Certificate, []byte, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, nil, fmt.Errorf("gagal membangkitkan serial sertifikat: %w", err)
	}

	subj := pkix.Name{
		CommonName:         fullname,
		SerialNumber:       nikNip,
		Organization:       []string{institution},
		OrganizationalUnit: []string{"Penandatangan TTE Pascakuantum"},
		Country:            []string{"ID"},
	}

	signerSKID, err := computeSKI(signerPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal menghitung SubjectKeyIdentifier penanda tangan: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subj,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(3 * 365 * 24 * time.Hour), // Berlaku 3 Tahun
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		// Sertifikat tanda tangan dokumen: hanya EmailProtection (S/MIME-CMS).
		// CodeSigning & TimeStamping dihapus karena di luar peruntukan TTE.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          signerSKID,
		AuthorityKeyId:        ca.SubCACert.SubjectKeyId,
		EmailAddresses:        []string{email},
		CRLDistributionPoints: []string{crlDistributionPoint()},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.SubCACert, signerPubKey, ca.SubCAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal menerbitkan sertifikat penanda tangan: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("gagal parsing sertifikat terbitan: %w", err)
	}

	return cert, certDER, nil
}

// ExportPEMCertificates mengekspor rantai sertifikat dalam format PEM
func (ca *ARSignAuthority) ExportPEMCertificates() string {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.RootCertDER})
	subPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.SubCACertDER})
	return string(subPEM) + "\n" + string(rootPEM)
}

// computeSKI menghitung SubjectKeyIdentifier sesuai RFC 5280 bagian 4.2.1.2 metode (1):
// SHA-1 atas isi BIT STRING subjectPublicKey pada struktur SubjectPublicKeyInfo.
// Implementasi lama meng-hash asn1.Marshal(rsa.PublicKey) sehingga nilainya tidak
// dikenali verifier X.509 standar.
func computeSKI(pub crypto.PublicKey) ([]byte, error) {
	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("gagal marshal SubjectPublicKeyInfo: %w", err)
	}

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return nil, fmt.Errorf("gagal parse SubjectPublicKeyInfo: %w", err)
	}

	h := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return h[:], nil
}

// randomSerialNumber membangkitkan serial sertifikat 128-bit positif sesuai RFC 5280.
func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

// crlDistributionPoint mengembalikan URL CRL yang disematkan pada sertifikat terbitan.
func crlDistributionPoint() string {
	if base := strings.TrimSpace(os.Getenv("ARSIGN_CRL_URL")); base != "" {
		return base
	}
	return "http://localhost:8080/api/v1/ca/crl?format=pem"
}
