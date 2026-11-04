# Changelog — EzrDH

Catatan rinci setiap perubahan oleh EzrDH. Format: lihat `README.md` di folder ini.

---

## [2026-11-04] Tindak lanjut tinjauan keamanan: gerbang fail-open, Incremental Saving Attack, dan pencabutan per penanda tangan

- **Branch**: `fix/security-audit-hardening`
- **Commit/PR**: (belum di-commit)
- **Agen AI**: Claude Code
- **Jenis**: fix

### Ringkasan
Tinjauan keamanan otomatis atas commit `5506581` menemukan tiga cacat yang lolos
dari audit sebelumnya: gerbang endpoint bantu uji bersifat fail-open, verifikasi
PAdES masih dapat ditembus dengan menyisipkan revisi inkremental baru di belakang
rentang yang ditandatangani, dan pemeriksaan pencabutan sertifikat hanya menyentuh
penanda tangan terakhir. Ketiganya diperbaiki dan dikunci oleh uji regresi.

### Alasan

1. **Fail-open pada endpoint pembocor kode OTP (tinggi).**
   `if !IsProductionEnv()` hanya memeriksa `APP_ENV == "production"`. Repo ini
   tidak menyertakan `.env`, sehingga `APP_ENV` kosong pada pemasangan baru dan
   `/api/v1/auth/otp/test-inspect` langsung aktif. Siapa pun yang tahu alamat
   surel seorang penandatangan dapat membaca kode OTP-nya dan mengambil alih
   akun. Keamanan tidak boleh bergantung pada variabel lingkungan yang lupa diisi.

2. **Incremental Saving Attack (tinggi).** `VerifyPDFPAdES` tidak memastikan
   cakupan tanda tangan terakhir mencapai akhir berkas. Penyerang dapat
   menambahkan revisi inkremental baru di belakang `o1+l1`: byte tambahan itu
   tidak tercakup tanda tangan mana pun, namun seluruh pemeriksaan tetap lulus
   dan dokumen dinyatakan "Asli & Utuh". Pembaca PDF menampilkan revisi terakhir,
   sehingga isi yang dilihat pengguna adalah isi kendali penyerang.
   Dibuktikan langsung: dokumen hasil tanda tangan yang disisipi satu revisi
   palsu sebelumnya membalas `is_valid: true`.

3. **Pencabutan hanya diperiksa pada penanda tangan terakhir (sedang).**
   `HandlePAdESVerify` memeriksa `res.CertSerialNumber`, yaitu nomor seri revisi
   terakhir saja. Dokumen multi-signature yang penanda tangan pertamanya sudah
   dicabut tetap dinyatakan sah.

### Rincian Perubahan

| File | Perubahan |
|---|---|
| `api/routes.go` | `IsTestEndpointsEnabled()` baru: aktivasi endpoint bantu uji bersifat opt-in lewat `ARSIGN_ENABLE_TEST_ENDPOINTS=1`, dan ditolak mutlak bila `APP_ENV=production`. Pendaftaran rute `otp/test-inspect` memakai gerbang ini, bukan lagi negasi `IsProductionEnv()`. |
| `api/otp.go` | Lapis kedua pada `HandleAuthTestInspectOTP` ikut memakai `IsTestEndpointsEnabled()`. |
| `crypto/pades.go` | `VerifyPDFPAdES` mewajibkan cakupan tanda tangan terakhir mencapai akhir berkas; hanya ruang kosong PDF (`isPDFWhitespace`) yang diperbolehkan sesudahnya. Field `HasUnsignedChanges` baru. Nomor seri sertifikat SETIAP revisi dikumpulkan ke `CertSerialNumbers`. |
| `api/handlers.go` | Pemeriksaan pencabutan menelusuri seluruh nomor seri revisi; bila ada yang tercabut, dokumen ditolak, jumlahnya dilaporkan, dan peristiwa dicatat sebagai `PAdES_VERIFY_REVOKED`. |
| `Dockerfile` | `APP_ENV=production` disetel sebagai nilai bawaan image. |
| `.env.example` | `ARSIGN_ENABLE_TEST_ENDPOINTS=0` beserta peringatan eksplisit bahwa nilai 1 membocorkan kode OTP. |
| `test_functional_flow.js` | Pesan bantuan menyebut `ARSIGN_ENABLE_TEST_ENDPOINTS=1` sebagai prasyarat. |
| `crypto/pades_verify_test.go` | Tiga tes baru: penolakan revisi yang disisipkan setelah penandatanganan, toleransi ruang kosong di akhir berkas, dan pengumpulan nomor seri setiap revisi. |
| `api/api_test.go` | Dua tes baru: endpoint bantu uji nonaktif tanpa opt-in (termasuk pemeriksaan bahwa respons tidak memuat kode OTP) dan penolakan dokumen ketika sertifikat penanda tangan PERTAMA dicabut. `TestOTPVerifyRejectsReplayAndWrongCode` mengaktifkan sakelar secara eksplisit. |

### Dampak
- **Konfigurasi baru:** `ARSIGN_ENABLE_TEST_ENDPOINTS`. Tanpa nilai `1`,
  `/api/v1/auth/otp/test-inspect` membalas `404`. `test_functional_flow.js`
  memerlukan sakelar ini saat dijalankan.
- Image Docker kini default `APP_ENV=production`.
- Respons verifikasi bertambah `has_unsigned_changes` dan `cert_serial_numbers`.
- Dokumen yang pernah dianggap sah dan memuat revisi tak bertanda tangan kini
  ditolak. Ini perubahan perilaku yang disengaja.

### Pengujian
- `go build ./...`, `go vet ./...`, `gofmt -l .` — bersih.
- `go test -count=1 ./...` — lulus, **33 tes** (naik dari 28).
- `node test_e2e_pades.js` — 12/12 lulus.
- `node test_functional_flow.js` — lulus.
- Bukti temuan 2 terhadap server hasil build: dokumen asli `is_valid=true`,
  `has_unsigned_changes=false`; dokumen yang disisipi revisi `is_valid=false`,
  `has_unsigned_changes=true`.
- Bukti temuan 1: server dijalankan tanpa `APP_ENV` dan tanpa sakelar; permintaan
  `GET /api/v1/auth/otp/test-inspect` membalas `404`.
- Bukti temuan 3: `TestPAdESVerifyChecksRevocationOfEverySigner` mencabut
  sertifikat penanda tangan pertama pada dokumen berlapis; verifikasi menolak.

### Risiko & Catatan Lanjutan
- Dua catatan dari entri sebelumnya masih berlaku dan tetap menunggu keputusan
  manusia: rotasi kunci CA yang pernah bocor ke riwayat git, dan pencabutan token
  bot Telegram lama lewat @BotFather.
- Syarat cakupan sampai akhir berkas mengasumsikan penanda tangan terakhir selalu
  menyegel seluruh berkas. Itu berlaku untuk dokumen yang ditandatangani ARSign.
  Dokumen dari penerbit lain yang menyisakan byte bukan-ruang-kosong setelah
  rentang tanda tangan akan ditolak; bila kelak perlu interoperabilitas, byte
  tersebut harus diurai sebagai revisi PDF dan diperiksa apakah hanya memuat
  perubahan yang diizinkan `/DocMDP`.
- Pemeriksaan pencabutan masih hanya menyentuh sertifikat penanda tangan, belum
  sertifikat perantara.

---

## [2026-11-04] Audit menyeluruh: penutupan bypass verifikasi PAdES, autentikasi penandatanganan, dan pengerasan kredensial

- **Branch**: `fix/security-audit-hardening`
- **Commit/PR**: (belum di-commit)
- **Agen AI**: Claude Code
- **Jenis**: fix

### Ringkasan
Audit menyeluruh atas seluruh repo menemukan 8 cacat kritis, 10 tingkat tinggi,
15 sedang, dan 6 rendah. Seluruhnya diperbaiki pada branch ini, kecuali dua hal
yang membutuhkan keputusan manusia (lihat bagian Risiko). Perbaikan terbesar:
verifikasi PAdES tidak lagi dapat ditembus, penandatanganan wajib terautentikasi,
dan kunci privat ML-DSA tidak pernah lagi meninggalkan server.

### Alasan
Pengujian awal (`go test ./...`, `node test_e2e_pades.js`) lulus semua, tetapi
cakupan uji hanya menyentuh jalur sukses paket `crypto`. Paket `api`, `storage`,
dan `cli` tidak punya satu pun tes. Pemeriksaan manual dan satu bukti konsep
menemukan bahwa seluruh jaminan keamanan platform dapat ditembus.

Temuan kritis yang dibuktikan dengan percobaan langsung:

1. **Bypass verifikasi PAdES.** `isValid := digestMatch && (rsaValid || pqcValid)`
   dengan `pqcValid` berinisial `true`. Bila atribut pascakuantum dihapus dari
   kontainer, tanda tangan kriptografis tidak pernah benar-benar diwajibkan.
   Karena slot `/Contents` berada di luar cakupan `/ByteRange`, perusakan tanda
   tangan tidak mengubah digest dokumen. Bukti konsep: merusak 8 byte tanda
   tangan dan mengganti penanda muatan pascakuantum menghasilkan respons
   `is_valid: true` dengan pesan "Dokumen Asli & Utuh".
2. **Penandatanganan tanpa kredensial.** `POST /api/v1/pades/sign` menerima nama
   dan NIK apa pun tanpa autentikasi; CA menerbitkan sertifikat untuk identitas
   tersebut. Bukti konsep: dokumen berhasil ditandatangani atas nama jabatan
   publik dengan NIK karangan, tanpa akun.
3. **Kunci privat ML-DSA dikirim ke peramban.** `/auth/login` mengembalikan kunci
   privat 4032 byte dalam bentuk terang, lalu disimpan di `sessionStorage`.
4. **Kunci privat Root CA dan Sub-CA ter-commit ke git** sejak `87e444c`.
5. **Token bot Telegram hardcoded** di berkas alur kerja GitHub Actions.
6. **Passphrase hardcoded** dicoba berurutan untuk membuka vault pengguna mana pun.
7. **Kunci sesi acak sebagai cadangan**: bila kunci penanda tangan gagal dibuka,
   server membangkitkan pasangan kunci baru dan tetap menandatangani.
8. **Atribut PKCS#7 dibaca dengan pemindaian byte**, bukan parsing ASN.1,
   sehingga kemunculan OID pertama di mana pun dalam DER yang menang.

### Rincian Perubahan

| File | Perubahan |
|---|---|
| `crypto/pades.go` | Verifikasi dipecah menjadi `verifySignatureRevision` per revisi tanda tangan; `VerifyPDFPAdES` kini memeriksa SELURUH `/ByteRange`, bukan hanya yang terakhir. Keabsahan menjadi `documentIntact && signatureValid && chainValid && (!pqcPresent \|\| pqcVerified)` — tanda tangan kontainer CMS wajib lulus. Atribut tertandatangani diurai lewat `parseSignedAttributes` (ASN.1), menggantikan pemindaian `bytes.Index` atas OID. Perbandingan digest memakai `crypto/subtle`. Struktur revisi melengkapi `/Prev`, `/Root`, dan `/AcroForm` dengan `/SigFlags 3`; `writeXrefSubsections` menulis entri xref terurut naik (sebelumnya offset objek `/Sig` dan widget tertukar). Penulisan ulang `/ByteRange` yang gagal kini menghasilkan error, bukan dilewati diam-diam. `escapePDFString` meloloskan `(`, `)`, dan `\` pada nama penanda tangan. |
| `crypto/ca.go` | `GetARSignAuthority` menyimpan error inisialisasi di variabel paket; sebelumnya `sync.Once` membuat panggilan kedua mengembalikan `(nil, nil)`. `computeSKI` dihitung sesuai RFC 5280 (SHA-1 atas BIT STRING `subjectPublicKey`) dan mengembalikan error. Serial Root/Sub-CA/penanda tangan menjadi 128-bit acak. `ExtKeyUsage` sertifikat penanda tangan dipersempit ke E-mail Protection saja. Ditambah `CRLDistributionPoints`. Direktori CA dapat dialihkan lewat `ARSIGN_CA_DIR`, dan salinan PEM ditulis ke dalam direktori CA, bukan ke direktori kerja. |
| `crypto/vault.go` | Penurunan kunci vault beralih ke PBKDF2-HMAC-SHA256 210.000 iterasi dengan salt acak per vault (format `ENC2:<iterasi>:<salt>:<ciphertext>`). Format lama `ENC:` tetap dapat dibuka untuk migrasi. Passphrase kosong ditolak; kunci sistem bawaan tidak lagi dipakai untuk enkripsi baru. |
| `storage/db.go` | `HashPassword` memakai PBKDF2-HMAC-SHA256 bersalt; ditambah `VerifyPassword` (waktu konstan) dan `IsLegacyPasswordHash` untuk migrasi transparan. `CreateUser` memakai `INSERT` biasa agar tabrakan id/username menghasilkan error, bukan menimpa akun lain. Kolom `vault_credential` baru menandai kredensial pembungkus vault. Ditambah `UpdateUserPasswordHash`, `UpdateUserVault`, tiga indeks, serta pragma `busy_timeout` dan `journal_mode=WAL`. |
| `api/handlers.go` | `HandlePAdESSign` kini mewajibkan akun terdaftar beserta kredensial pembuka vault; identitas sertifikat diambil dari registri akun, bukan dari badan permintaan. Percobaan passphrase hardcoded dan pembangkitan kunci sesi acak dihapus. `HandleAuthLogin` dan `HandleAuthRegister` tidak lagi mengembalikan kunci privat (lewat `sanitizeUser`), dan memigrasikan hash/vault format lama secara transparan. `HandleSetPassphrase` mewajibkan kata sandi akun lalu membungkus ulang vault dengan passphrase. Id akun dan nomor tanda terima dibangkitkan dari CSPRNG. Dereferensi `err.Error()` pada error `nil` dihapus. Serial CRL yang rusak dilewati dan dicatat, tidak lagi menjadi 0. |
| `api/admin.go` | Kunci administrator tidak lagi diterima lewat query string, dibandingkan dengan `crypto/subtle`, dan tidak punya nilai cadangan hardcoded — tanpa `ADMIN_SECRET_KEY` layanan membalas 503. |
| `api/routes.go` | CORS berbasis daftar izin (`ALLOWED_ORIGINS`) menggantikan `Access-Control-Allow-Origin: *`. Ditambah `http.MaxBytesReader` 32 MiB, header `X-Content-Type-Options` dan `Referrer-Policy`. `GET /api/v1/auth/users` dipindah ke belakang `AdminAuthMiddleware`. Rute bantu uji OTP didaftarkan hanya di luar produksi. |
| `api/otp.go` | `loadEnvFile` tidak lagi menimpa variabel lingkungan yang sudah ada dan tidak dibaca ulang setiap pengiriman surel. Kirim ulang OTP mempertahankan penghitung percobaan. Ditambah pembersih entri kedaluwarsa berkala dan perbandingan kode waktu-konstan. Cadangan CSPRNG berbasis jam sistem dihapus. |
| `main.go` | `ReadHeaderTimeout` 15 detik, `ReadTimeout`/`WriteTimeout` 120 detik, `MaxHeaderBytes` 1 MiB. Galat listener produksi dikirim lewat kanal agar graceful shutdown tetap berjalan. Peringatan bila `ADMIN_SECRET_KEY` belum disetel. |
| `web/prod.js`, `web/production.html` | Peramban tidak lagi menyimpan atau mengirim kunci privat; cadangan `keys/generate` dihapus. Formulir passphrase menerima kata sandi akun dan membersihkannya dari memori setelah tersimpan. |
| `Dockerfile` | Image builder `golang:1.24-alpine` menjadi `golang:1.26-alpine` sesuai `go.mod`. Berjalan sebagai pengguna non-root, `EXPOSE 8080 8081 8082`, dan `DB_PATH`/`ARSIGN_CA_DIR` diarahkan ke direktori khusus. |
| `.dockerignore` | Mengecualikan `.env`, `*.key`, `*.pem`, `ca_keys/`, dan `*.db` agar material CA dan basis data tidak ikut masuk ke dalam image. |
| `.gitignore` | `ca_keys/` dan `crypto/ARSIGN_*` ditambahkan. |
| `.github/workflows/telegram-notify.yml` | Kredensial bot dipindah ke GitHub Secrets; langkah dilewati bila secret belum disetel. |
| `.github/workflows/go-ci.yml` | Baru. Menjalankan `gofmt -l`, `go build`, `go vet`, `go test`, dan memeriksa bahwa pengujian tidak meninggalkan perubahan pada working tree. |
| `.env.example` | `ADMIN_SECRET_KEY` dikosongkan beserta cara membangkitkannya; ditambah `ARSIGN_CA_DIR`, `ARSIGN_CRL_URL`, dan `ALLOWED_ORIGINS`. |
| `crypto/pades_verify_test.go`, `crypto/vault_extra_test.go`, `storage/db_test.go`, `api/api_test.go` | Baru. 24 tes termasuk regresi untuk bypass verifikasi, penandatanganan tanpa kredensial, kebocoran kunci pada respons API, dan penolakan kunci administrator lewat query string. |
| `crypto/pades_test.go` | OpenSSL dicari lewat `exec.LookPath`; jalur Windows hardcoded membuat uji silang ini dilewati diam-diam di hampir semua mesin. |
| `test_e2e_pades.js` | Ditulis ulang: alamat server lewat `BASE_URL`, alur penandatanganan terautentikasi, dan 12 uji termasuk empat uji negatif (penandatanganan anonim, passphrase salah, tanda tangan rusak, isi dokumen diubah). |
| `test_functional_flow.js` | Ditulis ulang: alur OTP lengkap (kode salah, kode benar, penolakan pakai ulang), pendaftaran, penyetelan passphrase, penandatanganan, dan verifikasi. |
| Sembilan berkas Go lain | Diformat dengan `gofmt`. |

### Dampak

**Perubahan yang memutus kompatibilitas pada API:**

- `POST /api/v1/pades/sign` kini mewajibkan `username` beserta `passphrase`
  (atau `password` bila passphrase belum disetel). Field `signer_fullname`,
  `signer_nik`, `institution`, `mldsa_private_key`, dan `mldsa_public_key`
  diabaikan; identitas diambil dari registri akun.
- `POST /api/v1/auth/passphrase/set` kini mewajibkan field `password`.
- `GET /api/v1/auth/users` memerlukan header `X-Admin-Key`.
- `/auth/login` dan `/auth/register` tidak lagi mengembalikan `mldsa_private_key`.
- Respons verifikasi bertambah: `is_document_intact`, `is_signature_valid`,
  `is_pqc_present`, `is_pqc_verified`, `total_signatures`, `valid_signatures`.

**Konfigurasi:**

- `ADMIN_SECRET_KEY` kini WAJIB. Tanpa itu seluruh endpoint administrator dan
  daftar pengguna membalas 503.
- Variabel baru: `ARSIGN_CA_DIR`, `ARSIGN_CRL_URL`, `ALLOWED_ORIGINS`.
- `.env` tidak lagi menimpa variabel lingkungan yang sudah disetel.

**Skema basis data:** kolom `users.vault_credential` ditambahkan lewat
`ALTER TABLE` idempoten. Basis data lama tetap terbaca: hash kata sandi format
lama diverifikasi dan dimigrasikan otomatis saat login berhasil, vault `ENC:`
lama dienkripsi ulang ke format PBKDF2.

**Dependensi:** tidak ada dependensi pihak ketiga baru. `crypto/pbkdf2` dan
`crypto/subtle` berasal dari pustaka standar Go.

**Jebakan yang hilang** (perlu dicoret dari `AGENTS.md` bagian 7 saat bagian itu
diperbarui): `go test ./crypto` tidak lagi menimpa `crypto/ARSIGN_*`,
`test_functional_flow.js` tidak lagi gagal, dan `Dockerfile` tidak lagi berbeda
versi dengan `go.mod`.

### Pengujian

Seluruh perintah dijalankan pada 2026-11-04 (Windows 11, Go 1.27.3,
Node.js 24.22.1, OpenSSL 3.2.1):

- `go build ./...` — lulus.
- `go vet ./...` — bersih.
- `gofmt -l .` — tidak ada berkas tersisa.
- `go test ./...` — lulus (`api`, `crypto`, `storage`). Dari 2 tes menjadi 26 tes.
- `git status --porcelain` setelah pengujian — tidak ada efek samping pada repo.
- `node test_e2e_pades.js` terhadap server hasil build — 12/12 uji lulus.
- `node test_functional_flow.js` — seluruh tahap lulus (sebelumnya gagal di tahap OTP).
- Bukti konsep bypass verifikasi dijalankan ulang: dokumen bertanda tangan rusak
  kini DITOLAK (sebelumnya `is_valid: true`).
- Uji manual endpoint: `/api/v1/admin/logs` membalas 401 tanpa kunci, 401 bila
  kunci dikirim lewat `?key=`, 200 lewat header `X-Admin-Key`; `/api/v1/ca/revoke`
  401 tanpa kunci; `/api/v1/ca/crl`, `/registry`, `/audit`, `/keys/generate`,
  `/benchmarks`, serta ketiga halaman web membalas 200.
- Batas ukuran badan permintaan: permintaan 40 MiB ditolak dengan HTTP 400.
- Pemeriksaan sertifikat terbitan dengan OpenSSL: serial 128-bit acak,
  `Extended Key Usage` hanya E-mail Protection, `CRL Distribution Points` ada,
  `Subject Key Identifier` 20 byte.

### Risiko & Catatan Lanjutan

1. **Kunci CA harus dianggap bocor dan perlu dirotasi.** Berkas kunci sudah
   dikeluarkan dari pelacakan git dan masuk `.gitignore`, tetapi isinya masih ada
   di dalam riwayat commit. Penulisan ulang riwayat dan penerbitan ulang CA
   membutuhkan persetujuan manusia (`AGENTS.md` bagian 5.7) dan akan membatalkan
   seluruh dokumen yang sudah ditandatangani. **Belum dikerjakan.**
2. **Token bot Telegram lama harus dicabut** lewat @BotFather, lalu nilai baru
   disimpan sebagai secret `TELEGRAM_TOKEN` dan `TELEGRAM_CHAT_ID`. Memindahkan
   token ke secret tidak membatalkan token yang sudah terlanjur publik.
   **Belum dikerjakan.**
3. Akun yang belum menyetel passphrase TTE harus mengirim `password` saat
   menandatangani. Antarmuka sudah memaksa penyetelan passphrase saat onboarding,
   tetapi akun lama (termasuk `admin` hasil seed) perlu menyetel passphrase dahulu.
4. Verifikasi rantai sertifikat belum memeriksa CRL terhadap sertifikat perantara;
   pencabutan masih diperiksa hanya pada nomor seri sertifikat penanda tangan.
5. `/AcroForm` ditulis ulang pada objek katalog, tetapi widget tanda tangan belum
   ditambahkan ke `/Annots` halaman. Kolom tanda tangan akan tampil di panel
   tanda tangan pembaca PDF, bukan sebagai anotasi halaman. Stempel visual tetap
   digambar oleh `web/pdf-signer.js` ke dalam isi halaman seperti sebelumnya.
6. `PORT_PROC` dan `PORT_ADMIN` masih memakai `api.CORSMiddleware` yang sama;
   daftar origin bawaan mencakup ketiga port lokal. Untuk penerapan nyata,
   `ALLOWED_ORIGINS` wajib disetel eksplisit.

---

## [2026-11-04] Setup aturan kolaborasi, AGENTS.md, dan changelog kontributor

- **Branch**: `docs/collab-setup`
- **Commit/PR**: (belum di-commit)
- **Agen AI**: Claude Code
- **Jenis**: docs

### Ringkasan
Menyiapkan aturan kerja bersama untuk dua kontributor yang memakai agen AI berbeda:
`AGENTS.md` sebagai sumber aturan tunggal, `CLAUDE.md` mengimpornya, dan sistem
changelog rinci per kontributor di `docs/changelog/`.

### Alasan
Proyek dikerjakan bersama rekan tim yang memakai agen AI lain. Tanpa aturan bersama,
tiap agen bisa mengikuti konvensi berbeda. Selain itu, setiap perubahan perlu
terdokumentasi lebih rinci daripada commit message untuk keperluan laporan PKL.

### Rincian Perubahan
| File | Perubahan |
|---|---|
| `AGENTS.md` | Baru. Berisi ringkasan proyek, arsitektur, perintah, aturan keamanan (dipindah dari `CLAUDE.md`), alur Git berbasis branch + PR, aturan changelog wajib, dan daftar jebakan yang diketahui. |
| `CLAUDE.md` | Ditulis ulang menjadi lapisan tipis yang mengimpor `@AGENTS.md`, ditambah aturan khusus Claude Code (changelog sebelum selesai, konfirmasi sebelum push, bersihkan efek samping test). Perintah `scratch/test_live_functional.js` yang tidak ada di repo dihapus. |
| `TEAM_GUIDE.md` | Bagian 4 diganti: perintah `node scratch/test_live_functional.js` (file tidak ada di repo) diganti `go vet`, `go test`, dan `node test_e2e_pades.js`. Ditambah bagian 5 yang merujuk ke `AGENTS.md` dan aturan changelog. |
| `docs/changelog/README.md` | Baru. Aturan dan template entri changelog. |
| `docs/changelog/EzrDH.md` | Baru. Changelog pribadi EzrDH (file ini). |

### Dampak
- Tidak ada perubahan kode, API, skema DB, atau dependensi.
- Agen AI (Claude Code, Codex, Cursor, dll.) kini membaca aturan yang sama dari `AGENTS.md`.

### Pengujian
Pemeriksaan lingkungan pengembangan pada 2026-11-04 (Windows 11):
- Go 1.27.3, Node.js 24.22.1, npm 10.8.2, OpenSSL 3.2.1, Docker 29.2.1, `gh` login sebagai EzrDH.
- `go mod verify`: semua modul terverifikasi.
- `go vet ./...`: tanpa temuan. `go build .`: berhasil.
- `go test ./...`: paket `crypto` lulus; paket lain belum punya test.
- `node test_e2e_pades.js` (server lokal di :8080): 5/5 tes PAdES lulus, termasuk verifikasi OpenSSL dan multi-signature.
- `node test_functional_flow.js`: gagal di tahap OTP karena endpoint `/api/v1/auth/otp/test-inspect` sudah tidak ada.

### Risiko & Catatan Lanjutan
- Akses collaborator (Write) untuk EzrDH ke `ecotank/pqc-prototype` sudah aktif per 2026-11-04. `setup-dev.bat` berhasil menjalankan server di :8080, :8081, :8082.
- `.github/workflows/telegram-notify.yml` menulis token bot Telegram dan chat ID langsung di file (repo publik). Token perlu dicabut lewat BotFather dan dipindah ke GitHub Secrets (`secrets.TELEGRAM_TOKEN`).
- `ca_keys/*.key` (kunci privat Root CA & Sub-CA) ter-commit di repo publik, dan `.env.example` berisi nilai `ADMIN_SECRET_KEY` yang tampak nyata. Perlu diputuskan bersama apakah kunci dirotasi dan dikeluarkan dari repo.
- `go test ./crypto` menulis ulang `crypto/ARSIGN_*.crt|pem` yang ter-track git.
- `Dockerfile` memakai Go 1.24, sedangkan `go.mod` meminta Go 1.26.
- `git config user.name` belum diisi di mesin ini.
