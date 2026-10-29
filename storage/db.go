package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
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

type RegistryEntry struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	Signer       string `json:"signer"`
	Algorithm    string `json:"algorithm"`
	Time         string `json:"time"`
	DocumentHash string `json:"document_hash"`
	SignatureHex string `json:"signature_hex,omitempty"`
}

type User struct {
	ID              string `json:"id"`
	Username        string `json:"username"`
	PasswordHash    string `json:"password_hash,omitempty"`
	FullName        string `json:"fullname"`
	NikNip          string `json:"nik_nip"`
	Institution     string `json:"institution"`
	Email           string `json:"email"`
	Role            string `json:"role"` // "ASN", "PUBLIC", "ADMIN"
	MldsaPublicKey  string `json:"mldsa_public_key"`
	MldsaPrivateKey string `json:"mldsa_private_key,omitempty"`
	CreatedAt       string `json:"created_at"`
}

func HashPassword(pwd string) string {
	h := sha256.Sum256([]byte(pwd))
	return hex.EncodeToString(h[:])
}

type Storage struct {
	db *sql.DB
	mu sync.Mutex
}

func InitStorage(dbPath string) (*Storage, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("gagal membuka database sqlite: %w", err)
	}

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
	`

	if _, err := db.Exec(createSchema); err != nil {
		return nil, fmt.Errorf("gagal migrasi skema database: %w", err)
	}

	s := &Storage{db: db}
	s.seedInitialData()
	return s, nil
}

func (s *Storage) seedInitialData() {
	var count int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM document_registry").Scan(&count)
	if count == 0 {
		_ = s.RecordRegistry(
			"BSRE-PQC-2026-0091",
			"Keputusan Kepala BSSN tentang Roadmap Migrasi Algoritma Kriptografi Pascakuantum 2026-2035",
			"Satria Alba Pramasha",
			"ML-DSA-65",
			"2026-10-27 09:14 WIB",
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"",
		)
		_ = s.RecordRegistry(
			"BSRE-PQC-2026-0089",
			"Surat Edaran Bersama Standar Sertifikat Elektronik FIPS 204 Instansi Pemerintah",
			"Satria Alba Pramasha",
			"ML-DSA-65 + RSA",
			"2026-10-26 14:32 WIB",
			"d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
			"",
		)
	}
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

func (s *Storage) RecordRegistry(id, title, signer, alg, timeStr, docHash, sigHex string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT OR REPLACE INTO document_registry (id, title, signer, algorithm, time_str, document_hash, signature_hex) VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, id, title, signer, alg, timeStr, docHash, sigHex)
	return err
}

func (s *Storage) GetRegistryList(limit int) ([]RegistryEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, title, signer, algorithm, time_str, document_hash, signature_hex FROM document_registry ORDER BY rowid DESC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []RegistryEntry
	for rows.Next() {
		var r RegistryEntry
		if err := rows.Scan(&r.ID, &r.Title, &r.Signer, &r.Algorithm, &r.Time, &r.DocumentHash, &r.SignatureHex); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func (s *Storage) CreateUser(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `INSERT OR REPLACE INTO users (id, username, password_hash, fullname, nik_nip, institution, email, role, mldsa_public_key, mldsa_private_key, created_at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.Exec(query, u.ID, u.Username, u.PasswordHash, u.FullName, u.NikNip, u.Institution, u.Email, u.Role, u.MldsaPublicKey, u.MldsaPrivateKey, u.CreatedAt)
	return err
}

func (s *Storage) GetUserByUsername(username string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `SELECT id, username, password_hash, fullname, nik_nip, institution, email, role, mldsa_public_key, mldsa_private_key, created_at FROM users WHERE username = ?`
	var u User
	err := s.db.QueryRow(query, username).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.FullName, &u.NikNip, &u.Institution, &u.Email, &u.Role, &u.MldsaPublicKey, &u.MldsaPrivateKey, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Storage) GetUsersList() ([]User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `SELECT id, username, fullname, nik_nip, institution, email, role, mldsa_public_key, created_at FROM users ORDER BY role DESC, fullname ASC`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.FullName, &u.NikNip, &u.Institution, &u.Email, &u.Role, &u.MldsaPublicKey, &u.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, u)
	}
	return list, nil
}

func (s *Storage) Close() error {
	return s.db.Close()
}
