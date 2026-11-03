package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// DeriveKey menghasilkan kunci enkripsi 256-bit dari passphrase pengguna
func DeriveKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase + "-arsign-pqc-salt-2026-nist-fips-204"))
	return h[:]
}

// EncryptPrivateKey mengamankan kunci privat ML-DSA di database menggunakan AES-256-GCM
func EncryptPrivateKey(plaintextHex, passphrase string) (string, error) {
	if plaintextHex == "" {
		return "", errors.New("kunci privat tidak boleh kosong")
	}
	if passphrase == "" {
		// Jika passphrase kosong, fallback ke kunci sistem internal
		passphrase = "arsign-default-vault-key-2026"
	}

	key := DeriveKey(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("gagal inisialisasi AES: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gagal inisialisasi GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("gagal membangkitkan nonce CSPRNG: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintextHex), nil)
	return "ENC:" + hex.EncodeToString(ciphertext), nil
}

// DecryptPrivateKey membuka enkripsi kunci privat ML-DSA
func DecryptPrivateKey(storedValue, passphrase string) (string, error) {
	// Dukung backward compatibility jika data belum terenkripsi
	if !strings.HasPrefix(storedValue, "ENC:") {
		return storedValue, nil
	}

	if passphrase == "" {
		passphrase = "arsign-default-vault-key-2026"
	}

	rawHex := strings.TrimPrefix(storedValue, "ENC:")
	cipherBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		return "", fmt.Errorf("format ciphertext hex tidak valid: %w", err)
	}

	key := DeriveKey(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
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

