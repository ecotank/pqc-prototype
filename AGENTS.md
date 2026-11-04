# AGENTS.md — Aturan Bersama untuk Semua Agen AI di ARSign

File ini adalah **sumber aturan tunggal** untuk setiap agen AI yang bekerja di repo ini
(Claude Code, Codex, Cursor, Copilot, Gemini, dll.) dan untuk manusia yang memakainya.
`CLAUDE.md` mengimpor file ini, jadi aturan cukup diubah di sini.

Jika agen Anda tidak membaca `AGENTS.md` secara otomatis, arahkan agen untuk membaca
file ini di awal setiap sesi.

## 1. Ringkasan Proyek
**ARSign** adalah purwarupa sistem Tanda Tangan Elektronik (TTE) Tersertifikasi berbasis
**Kriptografi Pascakuantum (PQC)** berstandar **NIST FIPS 204 (ML-DSA)** dengan format
**PAdES (ISO 32000-1)**. Dikembangkan dalam rangka PKL di BSrE.

## 2. Arsitektur & Struktur Direktori
- `main.go`: entrypoint server HTTP Go, embedding aset web, port (`PORT` / `PORT_PROD`, `PORT_PROC`, `PORT_ADMIN`).
- `api/`: handler REST (`handlers.go`), rute (`routes.go`), administrasi (`admin.go`), OTP email (`otp.go`).
- `crypto/`:
  - `pades.go`: ekstraksi ByteRange PDF, parsing ASN.1 DER PKCS#7, sign & verify PAdES.
  - `ca.go`: infrastruktur CA 3-tier (Root CA & Sub-CA).
  - `fips204.go`, `pqc.go`: primitif ML-DSA (Cloudflare CIRCL).
  - `rsa.go`, `dual.go`, `benchmark.go`: pembanding RSA dan benchmark.
- `storage/db.go`: SQLite murni Go (`modernc.org/sqlite`, tanpa CGO), audit trail, registri dokumen.
- `web/`: frontend (Vue 3 standalone, PDF.js).
  - `production.html` & `prod.js`: portal tanda tangan & verifikasi utama.
  - `process.html` & `process.js`: visualisasi lab kriptografi.
  - `admin.html`: audit log & administrasi sertifikat.
  - `pdf-signer.js`: engine visual stamp PDF (drag & resize spesimen).
- `cli/`: CLI pendukung. `client-mock/`: klien ECS tiruan.
- `docs/`: dokumentasi, termasuk `docs/changelog/` (lihat bagian 6).

## 3. Perintah Utama
Prasyarat: Go ≥ 1.26 (sesuai `go.mod`), Node.js ≥ 18 (untuk `fetch` bawaan), OpenSSL CLI (untuk uji E2E).

Salin `.env.example` menjadi `.env` dan isi `ADMIN_SECRET_KEY` sebelum menjalankan server.

```bash
# Jalankan server lokal (port 8080, 8081, 8082)
go run .

# Unit test Go (catatan: menulis ulang crypto/ARSIGN_*.crt|pem, lihat bagian 7)
go test ./...
go vet ./...

# Build binary
go build -o pqc-server.exe .
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o arsign-linux .

# Uji E2E PAdES (server harus sudah berjalan di :8080)
node test_e2e_pades.js
```

## 4. Aturan Kritis & Standar Keamanan
1. **Integritas parsing PAdES**: jangan memotong hex ASN.1 sembarangan. Selalu pakai helper `parseASN1DERLength`.
2. **Keamanan basis data**: wajib *parameterized queries* (`?`) di seluruh `storage/db.go`. Dilarang konkatenasi string SQL.
3. **Privasi UI**: jangan tampilkan nama algoritma internal atau kunci mentah di antarmuka publik. Gunakan label seperti "Tersertifikasi Sah".
4. **Pencegahan kebocoran kunci**: `mldsa_private_key` dan `signing_passphrase_hash` tidak boleh muncul di respons JSON API publik.
5. **Rahasia**: jangan commit `.env`, kunci privat baru, database (`*.db`), atau token API. Jangan menyalin isi rahasia ke changelog, commit message, atau PR.

## 5. Alur Kerja Git (Kolaborasi Dua Orang + Agen AI)
1. **Jangan commit langsung ke `main`.** Selalu mulai dari `main` terbaru:
   `git switch main && git pull origin main && git switch -c <prefix>/<nama-singkat>`.
2. **Prefix branch**: `feature/`, `fix/`, `docs/`, `refactor/`, `test/`, `chore/`. Contoh: `feature/batch-signing`.
3. **Satu branch = satu topik.** Jangan mencampur perbaikan tak terkait.
4. **Commit message** memakai Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`), boleh berbahasa Indonesia.
5. **Masuk ke `main` hanya lewat Pull Request**, ditinjau oleh anggota tim yang lain (bukan hanya agennya sendiri).
6. Sebelum membuka PR: `go build ./...`, `go vet ./...`, `go test ./...` lulus, dan entri changelog sudah ditulis.
7. Agen **tidak boleh** melakukan `git push --force` ke `main`, menghapus branch orang lain, atau menulis ulang riwayat yang sudah di-push tanpa izin eksplisit dari manusia.
8. Sebelum mengubah file yang sedang dikerjakan rekan (cek branch/PR terbuka), koordinasikan dulu untuk menghindari konflik.

## 6. Aturan Changelog (WAJIB)
Setiap perubahan, sekecil apa pun, **wajib** dicatat secara rinci di changelog pribadi
kontributor, **di commit/PR yang sama** dengan perubahan kodenya. Changelog ini lebih rinci
daripada commit message: menjelaskan alasan, dampak, dan cara pengujian.

- Lokasi: `docs/changelog/<github-login>.md` (satu file per kontributor, sehingga tidak saling konflik).
- Urutan: entri **terbaru di paling atas**.
- Format dan contoh entri: lihat `docs/changelog/README.md`.
- Agen AI wajib menulis atau memperbarui entri sebelum menyatakan pekerjaan selesai, dan mencantumkan agen yang dipakai di kolom "Agen AI".
- Jika agen tidak tahu login GitHub penggunanya, tanyakan; jangan menebak.

## 7. Jebakan yang Diketahui
- **`ADMIN_SECRET_KEY` wajib disetel.** Tanpa itu seluruh endpoint administrator dan `GET /api/v1/auth/users` membalas `503`. Salin `.env.example` ke `.env` lalu isi nilainya.
- **Penandatanganan wajib terautentikasi.** `POST /api/v1/pades/sign` memerlukan `username` beserta `passphrase` (atau `password` bila passphrase belum disetel). Identitas pada sertifikat diambil dari registri akun, bukan dari badan permintaan.
- **Kunci privat tidak pernah dikirim ke klien.** Jangan menambahkan kembali `mldsa_private_key` ke respons API mana pun.
- `go test ./crypto` membuat `crypto/ca_keys/` (diabaikan git). Setel `ARSIGN_CA_DIR` ke direktori sementara bila ingin benar-benar terisolasi. Berkas `crypto/ARSIGN_*` tidak lagi ditulis ulang oleh pengujian.
- Material CA (`ca_keys/`) **tidak boleh di-commit**. Kunci CA pernah bocor ke riwayat git pada commit `87e444c`; rotasi kunci dan pembersihan riwayat masih menunggu keputusan manusia.

Jebakan berikut sudah diperbaiki pada branch `fix/security-audit-hardening`
(lihat `docs/changelog/EzrDH.md` entri 2026-11-04) dan tidak berlaku lagi:
`go test ./crypto` menimpa `crypto/ARSIGN_*`, `test_functional_flow.js` gagal di
tahap OTP, dan `Dockerfile` berbeda versi Go dengan `go.mod`.
