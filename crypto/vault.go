package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	// vaultPrefixV2 menandai vault yang kuncinya diturunkan dengan PBKDF2-HMAC-SHA256.
	vaultPrefixV2 = "ENC2:"
	// vaultPrefixV1 menandai vault lama dengan penurunan kunci SHA-256 tunggal.
	vaultPrefixV1 = "ENC:"

	// vaultPBKDF2Iterations mengikuti rekomendasi OWASP untuk PBKDF2-HMAC-SHA256.
	vaultPBKDF2Iterations = 210000
	vaultSaltBytes        = 16
	vaultKeyBytes         = 32

	// legacyVaultDefaultPassphrase hanya dipakai untuk MEMBUKA data lama yang
	// dulu dienkripsi tanpa passphrase. Tidak pernah dipakai untuk enkripsi baru.
	legacyVaultDefaultPassphrase = "arsign-default-vault-key-2026"
)

// DeriveKeyLegacy mereproduksi penurunan kunci versi lama (SHA-256 tunggal dengan
// salt statis). Dipertahankan semata agar vault berformat ENC: masih dapat dibuka.
func DeriveKeyLegacy(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase + "-arsign-pqc-salt-2026-nist-fips-204"))
	return h[:]
}

// deriveVaultKey menurunkan kunci AES-256 dari passphrase memakai PBKDF2-HMAC-SHA256
// dengan salt acak per vault. Penurunan kunci lama hanya satu putaran SHA-256 tanpa
// salt unik, sehingga seluruh vault dapat diserang paralel dengan biaya sangat murah.
func deriveVaultKey(passphrase string, salt []byte, iterations int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, salt, iterations, vaultKeyBytes)
}

// EncryptPrivateKey mengamankan kunci privat ML-DSA di basis data memakai AES-256-GCM
// dengan kunci hasil PBKDF2. Format keluaran: ENC2:<iterasi>:<saltHex>:<ciphertextHex>.
func EncryptPrivateKey(plaintextHex, passphrase string) (string, error) {
	if plaintextHex == "" {
		return "", errors.New("kunci privat tidak boleh kosong")
	}
	if passphrase == "" {
		return "", errors.New("passphrase vault tidak boleh kosong")
	}

	salt := make([]byte, vaultSaltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("gagal membangkitkan salt CSPRNG: %w", err)
	}

	key, err := deriveVaultKey(passphrase, salt, vaultPBKDF2Iterations)
	if err != nil {
		return "", fmt.Errorf("gagal menurunkan kunci vault: %w", err)
	}

	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("gagal membangkitkan nonce CSPRNG: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintextHex), nil)
	return fmt.Sprintf("%s%d:%s:%s", vaultPrefixV2, vaultPBKDF2Iterations,
		hex.EncodeToString(salt), hex.EncodeToString(ciphertext)), nil
}

// DecryptPrivateKey membuka vault kunci privat ML-DSA. Mendukung format PBKDF2
// (ENC2:), format lama (ENC:), serta data yang belum pernah dienkripsi.
func DecryptPrivateKey(storedValue, passphrase string) (string, error) {
	switch {
	case strings.HasPrefix(storedValue, vaultPrefixV2):
		return decryptVaultV2(storedValue, passphrase)
	case strings.HasPrefix(storedValue, vaultPrefixV1):
		return decryptVaultV1(storedValue, passphrase)
	default:
		// Kompatibilitas data yang tersimpan sebelum vault diperkenalkan.
		return storedValue, nil
	}
}

// IsVaultLegacyFormat melaporkan apakah vault masih memakai penurunan kunci lama,
// sehingga pemanggil dapat mengenkripsi ulang secara transparan.
func IsVaultLegacyFormat(storedValue string) bool {
	return strings.HasPrefix(storedValue, vaultPrefixV1)
}

// IsVaultEncrypted melaporkan apakah nilai tersimpan berbentuk vault terenkripsi.
func IsVaultEncrypted(storedValue string) bool {
	return strings.HasPrefix(storedValue, vaultPrefixV2) || strings.HasPrefix(storedValue, vaultPrefixV1)
}

func decryptVaultV2(storedValue, passphrase string) (string, error) {
	if passphrase == "" {
		return "", errors.New("passphrase vault tidak boleh kosong")
	}

	parts := strings.SplitN(strings.TrimPrefix(storedValue, vaultPrefixV2), ":", 3)
	if len(parts) != 3 {
		return "", errors.New("format vault ENC2 tidak valid")
	}

	iterations, err := strconv.Atoi(parts[0])
	if err != nil || iterations <= 0 {
		return "", errors.New("jumlah iterasi vault tidak valid")
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil || len(salt) == 0 {
		return "", errors.New("salt vault tidak valid")
	}
	cipherBytes, err := hex.DecodeString(parts[2])
	if err != nil {
		return "", errors.New("ciphertext vault tidak valid")
	}

	key, err := deriveVaultKey(passphrase, salt, iterations)
	if err != nil {
		return "", fmt.Errorf("gagal menurunkan kunci vault: %w", err)
	}
	return openGCM(key, cipherBytes)
}

func decryptVaultV1(storedValue, passphrase string) (string, error) {
	rawHex := strings.TrimPrefix(storedValue, vaultPrefixV1)
	cipherBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return "", fmt.Errorf("format ciphertext hex tidak valid: %w", err)
	}

	candidates := []string{passphrase}
	if passphrase == "" {
		candidates = []string{legacyVaultDefaultPassphrase}
	}

	var lastErr error
	for _, cand := range candidates {
		plaintext, err := openGCM(DeriveKeyLegacy(cand), cipherBytes)
		if err == nil {
			return plaintext, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("gagal inisialisasi AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gagal inisialisasi GCM: %w", err)
	}
	return gcm, nil
}

func openGCM(key, cipherBytes []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	if len(cipherBytes) < gcm.NonceSize() {
		return "", errors.New("panjang ciphertext terlalu pendek")
	}

	nonce, actualCipher := cipherBytes[:gcm.NonceSize()], cipherBytes[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, actualCipher, nil)
	if err != nil {
		return "", fmt.Errorf("passphrase salah atau data kunci rusak: %w", err)
	}
	return string(plaintext), nil
}
