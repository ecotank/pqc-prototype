package storage

import (
	"path/filepath"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) *Storage {
	t.Helper()
	store, err := InitStorage(filepath.Join(t.TempDir(), "uji.db"))
	if err != nil {
		t.Fatalf("InitStorage gagal: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestHashPasswordIsSaltedAndVerifiable(t *testing.T) {
	const pwd = "KataSandiUji#2026"

	a := HashPassword(pwd)
	b := HashPassword(pwd)
	if a == b {
		t.Fatal("dua hash atas kata sandi yang sama tidak boleh identik (salt tidak dipakai)")
	}
	if !strings.HasPrefix(a, "pbkdf2-sha256$") {
		t.Fatalf("format hash tidak sesuai: %.20s", a)
	}
	if strings.Contains(a, pwd) {
		t.Fatal("hash memuat kata sandi dalam bentuk terang")
	}

	if !VerifyPassword(a, pwd) {
		t.Fatal("kata sandi benar seharusnya lolos verifikasi")
	}
	if VerifyPassword(a, pwd+"x") {
		t.Fatal("kata sandi salah seharusnya ditolak")
	}
	if VerifyPassword("", pwd) {
		t.Fatal("hash kosong seharusnya selalu ditolak")
	}
	if IsLegacyPasswordHash(a) {
		t.Fatal("hash format baru tidak boleh dianggap format lama")
	}
}

func TestVerifyPasswordAcceptsLegacyHash(t *testing.T) {
	const pwd = "arsign2026"
	legacy := hashPasswordLegacy(pwd)

	if !IsLegacyPasswordHash(legacy) {
		t.Fatal("hash SHA-256 telanjang seharusnya dikenali sebagai format lama")
	}
	if !VerifyPassword(legacy, pwd) {
		t.Fatal("kredensial lama harus tetap dapat diverifikasi untuk migrasi")
	}
	if VerifyPassword(legacy, "salah") {
		t.Fatal("kata sandi salah pada hash lama seharusnya ditolak")
	}
}

func TestCreateUserRejectsDuplicate(t *testing.T) {
	store := newTestStore(t)

	first := &User{
		ID: "USR-ASN-aaaa", Username: "budi", PasswordHash: HashPassword("rahasia"),
		FullName: "Budi Santoso", NikNip: "1", Institution: "ARSign", Email: "budi@contoh.id",
		Role: "ASN", MldsaPublicKey: "aa", MldsaPrivateKey: "bb", CreatedAt: "2026-01-01 00:00:00",
	}
	if err := store.CreateUser(first); err != nil {
		t.Fatalf("pendaftaran pertama gagal: %v", err)
	}

	// Id sama, pemilik berbeda: dulu INSERT OR REPLACE menimpa akun tanpa jejak.
	clash := *first
	clash.Username = "siti"
	clash.FullName = "Siti Aminah"
	if err := store.CreateUser(&clash); err == nil {
		t.Fatal("tabrakan id akun seharusnya menghasilkan error, bukan menimpa akun lain")
	}

	got, err := store.GetUserByUsername("budi")
	if err != nil {
		t.Fatalf("akun pertama hilang: %v", err)
	}
	if got.FullName != "Budi Santoso" {
		t.Fatalf("akun pertama tertimpa: %q", got.FullName)
	}
	if got.VaultCredential != VaultCredentialPassword {
		t.Fatalf("kredensial vault bawaan %q, diharapkan %q", got.VaultCredential, VaultCredentialPassword)
	}
}

func TestUpdateUserVaultRejectsUnknownCredential(t *testing.T) {
	store := newTestStore(t)

	u := &User{
		ID: "USR-ASN-bbbb", Username: "rina", PasswordHash: HashPassword("rahasia"),
		FullName: "Rina", NikNip: "2", Institution: "ARSign", Email: "rina@contoh.id",
		Role: "PUBLIC", MldsaPublicKey: "aa", MldsaPrivateKey: "bb", CreatedAt: "2026-01-01 00:00:00",
	}
	if err := store.CreateUser(u); err != nil {
		t.Fatalf("pendaftaran gagal: %v", err)
	}

	if err := store.UpdateUserVault("rina", "ENC2:1:aa:bb", "sembarang"); err == nil {
		t.Fatal("kredensial vault tak dikenal seharusnya ditolak")
	}
	if err := store.UpdateUserVault("rina", "ENC2:1:aa:bb", VaultCredentialPassphrase); err != nil {
		t.Fatalf("pembaruan vault gagal: %v", err)
	}

	got, err := store.GetUserByUsername("rina")
	if err != nil {
		t.Fatalf("akun tidak ditemukan: %v", err)
	}
	if got.VaultCredential != VaultCredentialPassphrase {
		t.Fatalf("kredensial vault %q, diharapkan %q", got.VaultCredential, VaultCredentialPassphrase)
	}
}

func TestRevocationLifecycle(t *testing.T) {
	store := newTestStore(t)

	if store.IsCertificateRevoked("12345") {
		t.Fatal("sertifikat belum dicabut seharusnya dilaporkan aktif")
	}
	if err := store.RevokeCertificate("12345", "Budi Santoso", "keyCompromise"); err != nil {
		t.Fatalf("pencabutan gagal: %v", err)
	}
	if !store.IsCertificateRevoked("12345") {
		t.Fatal("sertifikat yang dicabut seharusnya terdeteksi")
	}

	list, err := store.GetRevokedCertificates()
	if err != nil {
		t.Fatalf("gagal memuat daftar pencabutan: %v", err)
	}
	if len(list) != 1 || list[0].SerialNumber != "12345" {
		t.Fatalf("daftar pencabutan tidak sesuai: %+v", list)
	}
}

func TestGetSystemActivityLogsFilters(t *testing.T) {
	store := newTestStore(t)

	entries := []struct{ category, level string }{
		{"SECURITY", "WARN"},
		{"SECURITY", "CRITICAL"},
		{"AUTH", "INFO"},
	}
	for _, e := range entries {
		if err := store.RecordActivity(e.category, e.level, "uji", "AKSI", "rincian", "127.0.0.1", "uji-agent"); err != nil {
			t.Fatalf("pencatatan aktivitas gagal: %v", err)
		}
	}

	logs, total, err := store.GetSystemActivityLogs("SECURITY", "", 10, 0)
	if err != nil {
		t.Fatalf("pembacaan log gagal: %v", err)
	}
	if total != 2 || len(logs) != 2 {
		t.Fatalf("filter kategori salah: total=%d dimuat=%d", total, len(logs))
	}

	logs, total, err = store.GetSystemActivityLogs("SECURITY", "CRITICAL", 10, 0)
	if err != nil {
		t.Fatalf("pembacaan log gagal: %v", err)
	}
	if total != 1 || len(logs) != 1 || logs[0].Level != "CRITICAL" {
		t.Fatalf("filter level salah: total=%d dimuat=%d", total, len(logs))
	}
}
