package crypto

import (
	"strings"
	"testing"
)

func TestEncryptDecryptPrivateKeyRoundTrip(t *testing.T) {
	const plain = "a1b2c3d4e5f6"
	const pass = "PassphraseUji#2026"

	enc, err := EncryptPrivateKey(plain, pass)
	if err != nil {
		t.Fatalf("EncryptPrivateKey gagal: %v", err)
	}
	if !strings.HasPrefix(enc, "ENC2:") {
		t.Fatalf("vault baru wajib berformat ENC2, diperoleh: %.12s", enc)
	}
	if strings.Contains(enc, plain) {
		t.Fatal("ciphertext memuat kunci privat dalam bentuk terang")
	}

	got, err := DecryptPrivateKey(enc, pass)
	if err != nil {
		t.Fatalf("DecryptPrivateKey gagal: %v", err)
	}
	if got != plain {
		t.Fatalf("hasil dekripsi %q, diharapkan %q", got, plain)
	}

	if _, err := DecryptPrivateKey(enc, "PassphraseSalah"); err == nil {
		t.Fatal("passphrase salah seharusnya menolak membuka vault")
	}
}

func TestEncryptPrivateKeyUsesFreshSalt(t *testing.T) {
	a, err := EncryptPrivateKey("aabbcc", "PassphraseUji#2026")
	if err != nil {
		t.Fatalf("enkripsi pertama gagal: %v", err)
	}
	b, err := EncryptPrivateKey("aabbcc", "PassphraseUji#2026")
	if err != nil {
		t.Fatalf("enkripsi kedua gagal: %v", err)
	}
	if a == b {
		t.Fatal("dua enkripsi atas data dan passphrase yang sama tidak boleh identik")
	}
}

func TestEncryptPrivateKeyRejectsEmptyPassphrase(t *testing.T) {
	if _, err := EncryptPrivateKey("aabbcc", ""); err == nil {
		t.Fatal("passphrase kosong seharusnya ditolak, bukan memakai kunci sistem bawaan")
	}
}

func TestDecryptPrivateKeySupportsLegacyVault(t *testing.T) {
	// Vault lama dibuat ulang memakai penurunan kunci versi lama agar jalur
	// kompatibilitas tetap terjaga setelah migrasi ke PBKDF2.
	const plain = "0f1e2d3c"
	const pass = "KataSandiLama"

	gcm, err := newGCM(DeriveKeyLegacy(pass))
	if err != nil {
		t.Fatalf("gagal menyiapkan GCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	legacy := "ENC:" + hexEncode(gcm.Seal(nonce, nonce, []byte(plain), nil))

	if !IsVaultLegacyFormat(legacy) {
		t.Fatal("vault ENC: seharusnya dikenali sebagai format lama")
	}
	got, err := DecryptPrivateKey(legacy, pass)
	if err != nil {
		t.Fatalf("vault lama gagal dibuka: %v", err)
	}
	if got != plain {
		t.Fatalf("hasil dekripsi vault lama %q, diharapkan %q", got, plain)
	}
}

func TestDecryptPrivateKeyPassesThroughPlaintext(t *testing.T) {
	got, err := DecryptPrivateKey("deadbeef", "apa pun")
	if err != nil {
		t.Fatalf("data tanpa vault seharusnya diteruskan: %v", err)
	}
	if got != "deadbeef" {
		t.Fatalf("hasil %q, diharapkan %q", got, "deadbeef")
	}
}

func TestComputeSKIMatchesRFC5280(t *testing.T) {
	keys, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("gagal membangkitkan kunci RSA: %v", err)
	}
	_ = keys

	ca, err := GetARSignAuthority()
	if err != nil {
		t.Fatalf("gagal inisialisasi CA: %v", err)
	}

	ski, err := computeSKI(ca.SubCACert.PublicKey)
	if err != nil {
		t.Fatalf("computeSKI gagal: %v", err)
	}
	if len(ski) != 20 {
		t.Fatalf("panjang SubjectKeyIdentifier %d byte, diharapkan 20", len(ski))
	}
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
