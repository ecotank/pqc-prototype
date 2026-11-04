# CLAUDE.md — Panduan Pengembangan ARSign untuk Claude Code

## 1. Ringkasan Proyek
**ARSign** adalah purwarupa sistem Penandatanganan Elektronik (TTE) Tersertifikasi berbasis **Kriptografi Pascakuantum (PQC)** berstandar **NIST FIPS 204 (ML-DSA)** dan kepatuhan format **PAdES ISO 32000-1**.

## 2. Arsitektur & Struktur Direktori
- `main.go`: Entrypoint server HTTP Go, embedding aset web, router port (`PORT` / `PORT_PROD`).
- `api/`: Handler REST API (`handlers.go`), registrasi rute (`routes.go`), administrasi (`admin.go`).
- `crypto/`: 
  - `pades.go`: Ekstraksi ByteRange PDF, parsing ASN.1 DER PKCS#7 presisi, penandatanganan dan verifikasi PAdES.
  - `ca.go`: Infrastruktur Otoritas Sertifikasi (Root CA & Sub-CA) 3-tier.
  - `mldsa.go`: Primitif kriptografi ML-DSA (Cloudflare CIRCL).
- `storage/`: Database SQLite lokal murni Go (`modernc.org/sqlite`, tanpa CGO), audit trail, dan registri dokumen.
- `web/`: Antarmuka frontend (Vue 3 standalone, PDF.js, Tailwind-like styling).
  - `production.html` & `prod.js`: Portal tanda tangan & verifikasi utama.
  - `process.html`: Visualisasi lab kriptografi pascakuantum.
  - `admin.html`: Audit log & administrasi sertifikat.
  - `pdf-signer.js`: Engine interaktif visual stamp PDF (drag & resize spesimen).

## 3. Perintah Utama (Commands)
```bash
# Jalankan server lokal
go run .

# Compile binary Windows
go build -o pqc-server.exe .

# Compile binary Linux (untuk VPS / Production)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o arsign-linux .

# Uji Fungsional & E2E
node scratch/test_live_functional.js
node test_e2e_pades.js
```

## 4. Aturan Kritis & Standar Keamanan (Rules)
1. **Integritas Parsing PAdES**: Jangan pernah potong hex ASN.1 secara serampangan. Selalu gunakan helper `parseASN1DERLength` untuk menjaga keaslian trailing byte DER.
2. **Keamanan Basis Data**: Wajib gunakan *parameterized queries* (`?`) pada seluruh fungsi di `storage/db.go`. Dilarang konkatenasi string SQL mentah.
3. **Privasi UI**: Jangan tampilkan nama internal algoritma atau kunci mentah pada antarmuka publik pengguna umum. Gunakan label "Tersertifikasi Sah" atau indikator ramah pengguna.
4. **Pencegahan Kebocoran Kunci**: `mldsa_private_key` dan `signing_passphrase_hash` tidak boleh diekspos dalam respons JSON API publik.
5. **Git Workflow**: Buat branch baru untuk tiap fitur (`feature/nama-fitur`), jangan commit langsung kode eksperimental ke branch `main`.
