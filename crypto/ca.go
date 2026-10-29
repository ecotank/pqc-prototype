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
	"sync"
	"time"
)

// BSrEAuthority mengelola infrastruktur kunci publik (PKI) resmi BSrE BSSN
type BSrEAuthority struct {
	mu           sync.RWMutex
	RootKey      *rsa.PrivateKey
	RootCert     *x509.Certificate
	RootCertDER  []byte
	SubCAKey     *rsa.PrivateKey
	SubCACert    *x509.Certificate
	SubCACertDER []byte
}

var (
	globalCA     *BSrEAuthority
	globalCAOnce sync.Once
)

// GetBSrEAuthority mengembalikan instance tunggal Otoritas Sertifikasi BSrE
func GetBSrEAuthority() (*BSrEAuthority, error) {
	var err error
	globalCAOnce.Do(func() {
		globalCA, err = initBSrEAuthority()
	})
	return globalCA, err
}

func initBSrEAuthority() (*BSrEAuthority, error) {
	// 1. Bangkitkan Kunci & Sertifikat Root CA BSrE (Masa Berlaku 20 Tahun)
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("gagal bangkitkan kunci Root CA: %w", err)
	}

	rootSubj := pkix.Name{
		CommonName:         "BSrE BSSN Root CA (Pascakuantum Ready)",
		Organization:       []string{"Badan Siber dan Sandi Negara"},
		OrganizationalUnit: []string{"Balai Besar Sertifikasi Elektronik"},
		Country:            []string{"ID"},
		Province:           []string{"DKI Jakarta"},
		Locality:           []string{"Jakarta Selatan"},
	}

	rootSKID := computeSKI(&rootKey.PublicKey)

	rootTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1000000001),
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

	// 2. Bangkitkan Kunci & Sertifikat Sub-CA Penerbit TTE Instansi Pemerintah
	subKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("gagal bangkitkan kunci Sub-CA: %w", err)
	}

	subSubj := pkix.Name{
		CommonName:         "BSrE Sub-CA Pelayanan TTE Pascakuantum Nasional",
		Organization:       []string{"Badan Siber dan Sandi Negara"},
		OrganizationalUnit: []string{"Otoritas Sertifikasi Elektronik Induk"},
		Country:            []string{"ID"},
	}

	subSKID := computeSKI(&subKey.PublicKey)

	subTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2000000002),
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

	return &BSrEAuthority{
		RootKey:      rootKey,
		RootCert:     rootCert,
		RootCertDER:  rootCertDER,
		SubCAKey:     subKey,
		SubCACert:    subCert,
		SubCACertDER: subCertDER,
	}, nil
}

// IssueSignerCertificate menerbitkan sertifikat digital resmi X.509 penanda tangan
func (ca *BSrEAuthority) IssueSignerCertificate(fullname, email, nikNip, institution string, signerPubKey *rsa.PublicKey) (*x509.Certificate, []byte, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000000000000000))
	if err != nil {
		serialNumber = big.NewInt(time.Now().UnixNano())
	}

	subj := pkix.Name{
		CommonName:         fullname,
		SerialNumber:       nikNip,
		Organization:       []string{institution},
		OrganizationalUnit: []string{"Penandatangan TTE Pascakuantum"},
		Country:            []string{"ID"},
	}

	signerSKID := computeSKI(signerPubKey)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subj,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(3 * 365 * 24 * time.Hour), // Berlaku 3 Tahun
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection, x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          signerSKID,
		AuthorityKeyId:        ca.SubCACert.SubjectKeyId,
		EmailAddresses:        []string{email},
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
func (ca *BSrEAuthority) ExportPEMCertificates() string {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.RootCertDER})
	subPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.SubCACertDER})
	return string(subPEM) + "\n" + string(rootPEM)
}

func computeSKI(pub crypto.PublicKey) []byte {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		b, err := asn1.Marshal(*k)
		if err == nil {
			h := sha1.Sum(b)
			return h[:]
		}
	}
	h := sha1.Sum([]byte(fmt.Sprintf("%v", pub)))
	return h[:]
}
