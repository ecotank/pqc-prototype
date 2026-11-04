package storage

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type AuditEntry struct {
	ID         int64   `json:"id"`
	Timestamp  string  `json:"timestamp"`
	Operation  string  `json:"operation"`
	Algorithm  string  `json:"algorithm"`
	DurationMs float64 `json:"duration_ms"`
	Status     string  `json:"status"`
	Details    string  `json:"details"`
}

type SystemActivityLog struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Category  string `json:"category"` // "SECURITY", "AUTH", "CRYPTO_PQC", "ERROR", "SYSTEM", "DOCUMENT", "ADMIN"
	Level     string `json:"level"`    // "INFO", "WARN", "ERROR", "CRITICAL"
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Details   string `json:"details"`
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

type RegistryEntry struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Signer       string `json:"signer"`
	Algorithm    string `json:"algorithm"`
	Time         string `json:"time"`
	DocumentHash string `json:"document_hash"`
	SignatureHex string `json:"signature_hex,omitempty"`
	Username     string `json:"username,omitempty"`
}

type User struct {
	ID                    string `json:"id"`
	Username              string `json:"username"`
	PasswordHash          string `json:"password_hash,omitempty"`
	FullName              string `json:"fullname"`
	NikNip                string `json:"nik_nip"`
	Institution           string `json:"institution"`
	Email                 string `json:"email"`
	Role                  string `json:"role"` // "ASN", "PUBLIC", "ADMIN"
	MldsaPublicKey        string `json:"mldsa_public_key"`
	MldsaPrivateKey       string `json:"mldsa_private_key,omitempty"`
	SpecimenSignature     string `json:"specimen_signature,omitempty"`
	SigningPassphraseHash string `json:"signing_passphrase_hash,omitempty"`
	HasPassphrase         bool   `json:"has_passphrase"`
	CreatedAt             string `json:"created_at"`

	// VaultCredential menyatakan kredensial mana yang membungkus kunci privat:
	// "password" (bawaan) atau "passphrase" (passphrase penandatanganan).
	// Tidak pernah diserialkan ke respons API publik.
	VaultCredential string `json:"-"`
}

// Kredensial pembungkus vault kunci privat.
const (
	VaultCredentialPassword   = "password"
	VaultCredentialPassphrase = "passphrase"
)

const (
	// passwordHashPrefix menandai format hash kata sandi bersalt.
	passwordHashPrefix = "pbkdf2-sha256"
	// passwordHashIterations mengikuti rekomendasi OWASP untuk PBKDF2-HMAC-SHA256.
	passwordHashIterations = 210000
	passwordSaltBytes      = 16
	passwordHashBytes      = 32
)

// HashPassword menghasilkan hash kata sandi bersalt memakai PBKDF2-HMAC-SHA256.
// Format: pbkdf2-sha256$<iterasi>$<saltHex>$<hashHex>.
//
// Implementasi lama memakai SHA-256 telanjang tanpa salt dan tanpa iterasi,
// sehingga seluruh basis data kata sandi dapat dipecahkan dengan tabel rainbow
// atau serangan GPU paralel berbiaya sangat rendah.
func HashPassword(pwd string) string {
	salt := make([]byte, passwordSaltBytes)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		// Tanpa CSPRNG tidak ada hash yang dapat dipertanggungjawabkan.
		panic(fmt.Sprintf("gagal membangkitkan salt kata sandi: %v", err))
	}
	sum, err := pbkdf2.Key(sha256.New, pwd, salt, passwordHashIterations, passwordHashBytes)
	if err != nil {
		panic(fmt.Sprintf("gagal menurunkan hash kata sandi: %v", err))
	}
	return fmt.Sprintf("%s$%d$%s$%s", passwordHashPrefix, passwordHashIterations,
		hex.EncodeToString(salt), hex.EncodeToString(sum))
}

// hashPasswordLegacy mereproduksi hash versi lama, hanya untuk memverifikasi
// kredensial yang sudah tersimpan sebelum migrasi.
func hashPasswordLegacy(pwd string) string {
	h := sha256.Sum256([]byte(pwd))
	return hex.EncodeToString(h[:])
}

// IsLegacyPasswordHash melaporkan apakah hash tersimpan masih berformat lama,
// sehingga pemanggil dapat memperbaruinya secara transparan setelah login sukses.
func IsLegacyPasswordHash(stored string) bool {
	return stored != "" && !strings.HasPrefix(stored, passwordHashPrefix+"$")
}

// VerifyPassword membandingkan kata sandi kandidat dengan hash tersimpan secara
// waktu-konstan. Mendukung format lama maupun format bersalt.
func VerifyPassword(stored, candidate string) bool {
	if stored == "" {
		return false
	}

	if IsLegacyPasswordHash(stored) {
		return subtle.ConstantTimeCompare([]byte(stored), []byte(hashPasswordLegacy(candidate))) == 1
	}

	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != passwordHashPrefix {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations <= 0 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil || len(want) == 0 {
		return false
	}

	got, err := pbkdf2.Key(sha256.New, candidate, salt, iterations, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

type Storage struct {
	db *sql.DB
	mu sync.Mutex
}

func InitStorage(dbPath string) (*Storage, error) {
	// WAL meningkatkan konkurensi baca/tulis; busy_timeout mencegah kegagalan
	// "database is locked" seketika saat ada penulis lain.
	dsn := dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("gagal membuka database sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	createSchema := `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		operation TEXT NOT NULL,
		algorithm TEXT NOT NULL,
		duration_ms REAL NOT NULL,
		status TEXT NOT NULL,
		details TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS document_registry (
		id TEXT PRIMARY KEY,
		title TEXT NOT NULL,
		signer TEXT NOT NULL,
		algorithm TEXT NOT NULL,
		time_str TEXT NOT NULL,
		document_hash TEXT NOT NULL,
		signature_hex TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		fullname TEXT NOT NULL,
		nik_nip TEXT NOT NULL,
		institution TEXT NOT NULL,
		email TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'PUBLIC',
		mldsa_public_key TEXT NOT NULL,
		mldsa_private_key TEXT NOT NULL,
		created_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS system_activity_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		category TEXT NOT NULL,
		level TEXT NOT NULL,
		actor TEXT NOT NULL,
		action TEXT NOT NULL,
		details TEXT NOT NULL,
		ip_address TEXT,
		user_agent TEXT
	);

	CREATE TABLE IF NOT EXISTS revoked_certificates (
		serial_number TEXT PRIMARY KEY,
		signer_name TEXT NOT NULL,
		revocation_date TEXT NOT NULL,
		reason TEXT NOT NULL
	);
	`

	if _, err := db.Exec(createSchema); err != nil {
		return nil, fmt.Errorf("gagal migrasi skema database: %w", err)
	}

	_, _ = db.Exec("ALTER TABLE document_registry ADD COLUMN username TEXT DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE users ADD COLUMN specimen_signature TEXT DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE users ADD COLUMN signing_passphrase_hash TEXT DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE users ADD COLUMN vault_credential TEXT DEFAULT 'password'")

	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_activity_category_level ON system_activity_logs (category, level)`,
		`CREATE INDEX IF NOT EXISTS idx_activity_id_desc ON system_activity_logs (id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_registry_username ON document_registry (username)`,
	}
	for _, stmt := range indexes {
		if _, err := db.Exec(stmt); err != nil {
			return nil, fmt.Errorf("gagal membuat indeks database: %w", err)
		}
	}

	s := &Storage{db: db}
	s.seedInitialData()
	return s, nil
}

func (s *Storage) seedInitialData() {
	// Real Production: Buku registrasi hanya memuat dokumen yang riil ditandatangani oleh pengguna
}

func (s *Storage) RecordAudit(op, alg string, dur float64, status, details string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT INTO audit_logs (timestamp, operation, algorithm, duration_ms, status, details) VALUES (?, ?, ?, ?, ?, ?)`
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := s.db.Exec(query, now, op, alg, dur, status, details)
	return err
}

func (s *Storage) GetAuditLogs(limit int) ([]AuditEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 {
		limit = 100
	}

	query := `SELECT id, timestamp, operation, algorithm, duration_ms, status, details FROM audit_logs ORDER BY id DESC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Operation, &e.Algorithm, &e.DurationMs, &e.Status, &e.Details); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (s *Storage) RecordRegistry(id, title, signer, alg, timeStr, docHash, sigHex, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT OR REPLACE INTO document_registry (id, title, signer, algorithm, time_str, document_hash, signature_hex, username) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, id, title, signer, alg, timeStr, docHash, sigHex, username)
	return err
}

func (s *Storage) GetRegistryList(username string, limit int) ([]RegistryEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 {
		limit = 100
	}

	var rows *sql.Rows
	var err error
	if username != "" {
		query := `SELECT id, title, signer, algorithm, time_str, document_hash, signature_hex, COALESCE(username, '') FROM document_registry WHERE username = ? OR signer LIKE ? ORDER BY rowid DESC LIMIT ?`
		rows, err = s.db.Query(query, username, "%"+username+"%", limit)
	} else {
		query := `SELECT id, title, signer, algorithm, time_str, document_hash, signature_hex, COALESCE(username, '') FROM document_registry ORDER BY rowid DESC LIMIT ?`
		rows, err = s.db.Query(query, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []RegistryEntry
	for rows.Next() {
		var r RegistryEntry
		if err := rows.Scan(&r.ID, &r.Title, &r.Signer, &r.Algorithm, &r.Time, &r.DocumentHash, &r.SignatureHex, &r.Username); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func (s *Storage) CreateUser(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred := u.VaultCredential
	if cred == "" {
		cred = VaultCredentialPassword
	}

	// INSERT biasa, bukan INSERT OR REPLACE: tabrakan id atau username wajib
	// memunculkan error, bukan menimpa akun pengguna lain tanpa jejak.
	query := `INSERT INTO users (id, username, password_hash, fullname, nik_nip, institution, email, role, mldsa_public_key, mldsa_private_key, vault_credential, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, u.ID, u.Username, u.PasswordHash, u.FullName, u.NikNip, u.Institution, u.Email, u.Role, u.MldsaPublicKey, u.MldsaPrivateKey, cred, u.CreatedAt)
	return err
}

func (s *Storage) GetUserByUsername(username string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `SELECT id, username, password_hash, fullname, nik_nip, institution, email, role, mldsa_public_key, mldsa_private_key, COALESCE(specimen_signature, ''), COALESCE(signing_passphrase_hash, ''), COALESCE(vault_credential, 'password'), created_at FROM users WHERE username = ?`
	var u User
	err := s.db.QueryRow(query, username).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.FullName, &u.NikNip, &u.Institution, &u.Email, &u.Role, &u.MldsaPublicKey, &u.MldsaPrivateKey, &u.SpecimenSignature, &u.SigningPassphraseHash, &u.VaultCredential, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	u.HasPassphrase = (u.SigningPassphraseHash != "")
	if u.VaultCredential == "" {
		u.VaultCredential = VaultCredentialPassword
	}
	return &u, nil
}

// UpdateUserPasswordHash memperbarui hanya hash kata sandi, dipakai untuk migrasi
// transparan dari format hash lama ke format bersalt setelah login berhasil.
func (s *Storage) UpdateUserPasswordHash(username, newPassHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`UPDATE users SET password_hash = ? WHERE username = ?`, newPassHash, username)
	return err
}

// UpdateUserVault menyimpan vault kunci privat baru beserta kredensial pembungkusnya.
func (s *Storage) UpdateUserVault(username, encPrivateKey, credential string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if credential != VaultCredentialPassword && credential != VaultCredentialPassphrase {
		return fmt.Errorf("kredensial vault tidak dikenal: %s", credential)
	}
	_, err := s.db.Exec(`UPDATE users SET mldsa_private_key = ?, vault_credential = ? WHERE username = ?`,
		encPrivateKey, credential, username)
	return err
}

func (s *Storage) UpdateUserPassphrase(username, passHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `UPDATE users SET signing_passphrase_hash = ? WHERE username = ?`
	_, err := s.db.Exec(query, passHash, username)
	return err
}

func (s *Storage) UpdateUserPassword(username, newPassHash, newEncKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `UPDATE users SET password_hash = ?, mldsa_private_key = ? WHERE username = ?`
	_, err := s.db.Exec(query, newPassHash, newEncKey, username)
	return err
}

func (s *Storage) UpdateUserProfile(username, fullname, email, institution string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `UPDATE users SET fullname = ?, email = ?, institution = ? WHERE username = ?`
	_, err := s.db.Exec(query, fullname, email, institution, username)
	return err
}

func (s *Storage) UpdateUserSpecimen(username, specimen string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `UPDATE users SET specimen_signature = ? WHERE username = ?`
	_, err := s.db.Exec(query, specimen, username)
	return err
}

func (s *Storage) GetUsersList() ([]User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `SELECT id, username, fullname, nik_nip, institution, email, role, mldsa_public_key, COALESCE(specimen_signature, ''), created_at FROM users ORDER BY role DESC, fullname ASC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.FullName, &u.NikNip, &u.Institution, &u.Email, &u.Role, &u.MldsaPublicKey, &u.SpecimenSignature, &u.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, u)
	}
	return list, nil
}

// RecordActivity mencatat log komprehensif seluruh aktivitas sistem, error, dan perubahan
func (s *Storage) RecordActivity(category, level, actor, action, details, ip, ua string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT INTO system_activity_logs (timestamp, category, level, actor, action, details, ip_address, user_agent) 
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	now := time.Now().Format("2006-01-02 15:04:05")
	_, err := s.db.Exec(query, now, category, level, actor, action, details, ip, ua)
	return err
}

// GetSystemActivityLogs mengambil daftar log aktivitas terperinci dengan filter kategori & level
func (s *Storage) GetSystemActivityLogs(category, level string, limit, offset int) ([]SystemActivityLog, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	whereClause := "WHERE 1=1"
	var args []interface{}
	if category != "" && category != "ALL" {
		whereClause += " AND category = ?"
		args = append(args, category)
	}
	if level != "" && level != "ALL" {
		whereClause += " AND level = ?"
		args = append(args, level)
	}

	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM system_activity_logs %s", whereClause)
	_ = s.db.QueryRow(countQuery, args...).Scan(&total)

	dataQuery := fmt.Sprintf("SELECT id, timestamp, category, level, actor, action, details, COALESCE(ip_address, ''), COALESCE(user_agent, '') FROM system_activity_logs %s ORDER BY id DESC LIMIT ? OFFSET ?", whereClause)
	queryArgs := append(args, limit, offset)

	rows, err := s.db.Query(dataQuery, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []SystemActivityLog
	for rows.Next() {
		var l SystemActivityLog
		if err := rows.Scan(&l.ID, &l.Timestamp, &l.Category, &l.Level, &l.Actor, &l.Action, &l.Details, &l.IPAddress, &l.UserAgent); err != nil {
			return nil, 0, err
		}
		logs = append(logs, l)
	}
	return logs, total, nil
}

// GetSystemActivityStats mengembalikan statistik ringkasan aktivitas sistem
func (s *Storage) GetSystemActivityStats() (map[string]interface{}, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := make(map[string]interface{})

	var totalLogs, errorCount, securityCount, docCount, revokedCount int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM system_activity_logs").Scan(&totalLogs)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM system_activity_logs WHERE level = 'ERROR' OR level = 'CRITICAL'").Scan(&errorCount)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM system_activity_logs WHERE category = 'SECURITY'").Scan(&securityCount)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM document_registry").Scan(&docCount)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM revoked_certificates").Scan(&revokedCount)

	stats["total_activity_logs"] = totalLogs
	stats["total_errors"] = errorCount
	stats["total_security_events"] = securityCount
	stats["total_signed_documents"] = docCount
	stats["total_revoked_certificates"] = revokedCount

	return stats, nil
}

type RevokedCertificateEntry struct {
	SerialNumber   string `json:"serial_number"`
	SignerName     string `json:"signer_name"`
	RevocationDate string `json:"revocation_date"`
	Reason         string `json:"reason"`
}

func (s *Storage) RevokeCertificate(serialNumber, signerName, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Format("2006-01-02 15:04:05")
	query := `INSERT OR REPLACE INTO revoked_certificates (serial_number, signer_name, revocation_date, reason) VALUES (?, ?, ?, ?)`
	_, err := s.db.Exec(query, serialNumber, signerName, now, reason)
	return err
}

func (s *Storage) GetRevokedCertificates() ([]RevokedCertificateEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `SELECT serial_number, signer_name, revocation_date, reason FROM revoked_certificates ORDER BY revocation_date DESC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []RevokedCertificateEntry
	for rows.Next() {
		var e RevokedCertificateEntry
		if err := rows.Scan(&e.SerialNumber, &e.SignerName, &e.RevocationDate, &e.Reason); err != nil {
			return nil, err
		}
		list = append(list, e)
	}
	return list, nil
}

func (s *Storage) IsCertificateRevoked(serialNumber string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM revoked_certificates WHERE serial_number = ?", serialNumber).Scan(&count)
	return count > 0
}

func (s *Storage) Close() error {
	return s.db.Close()
}
