# ARSIP DOKUMENTASI KETIDAKSESUAIAN, HALUSINASI, DAN PERBAIKAN PROGRAM
**Purwarupa Penandatanganan Digital Post-Quantum (ML-DSA NIST FIPS 204)**  
**ARSign Platform — Tim 3 RPLK: Alba, Radit, Sulthan**  
*Tanggal Pencatatan: 2 November 2026*

---

## 1. Pendahuluan
Dokumen ini mencatat seluruh anomali, halusinasi asumsi perancangan, ketidaksesuaian standar teknis, serta bug implementasi yang terjadi selama siklus pengembangan platform TTE Pascakuantum ARSign, lengkap dengan akar penyebab (*root cause*) dan solusi implementasi perbaikannya.

---

## 2. Rincian Halusinasi & Asumsi Keliru

### A. Halusinasi Format Kontainer TTE PDF (Simulasi Hex vs ASN.1 CMS Otentik)
* **Deskripsi Anomali**: Pada fase awal, AI mengasumsikan bahwa penampil PDF (Adobe Acrobat Reader dan BeSign Desktop) dapat membaca tanda tangan elektronik pascakuantum hanya dengan memasukkan representasi heksadesimal mentah dari signature ML-DSA (`3082...`) ke dalam slot `/Contents`.
* **Dampak**: Dokumen ditolak keras oleh Adobe Acrobat dengan pesan galat:  
  `"Signature is invalid: Formatting or information contained in this signature has errors."`  
  BeSign Desktop mendeteksi berkas sebagai dokumen tanpa tanda tangan sah.
* **Akar Penyebab**: Standar ISO 32000-1 dan ETSI EN 319 142 (PAdES) mewajibkan slot `/Contents` memuat struktur biner ASN.1 DER `CMS SignedData` (RFC 5652) yang valid, berisi *SignedAttributes*, *MessageDigest*, dan rantai sertifikat X.509.
* **Solusi & Implementasi**:
  1. Membangun modul kontainer PKCS#7 otentik di [`crypto/pades.go`](file:///d:/PKL/pqc-prototype/crypto/pades.go).
  2. Mengimplementasikan skema *Dual-Signing / Composite Signature*: Tanda tangan klasik RSA membungkus integritas PDF standar, dan tanda tangan pascakuantum ML-DSA-65 (3.309 byte) disematkan secara aman pada atribut terotentikasi (*Authenticated Attributes*) di bawah OID resmi ARSign `1.3.6.1.4.1.58333.1.204`.
  3. Diverifikasi 100% lolos via OpenSSL CLI (`openssl smime -verify`).

---

### B. Halusinasi Alur OTP (Pembocoran Kode pada Antarmuka Web Klien)
* **Deskripsi Anomali**: Pada implementasi awal verifikasi registrasi, dibuat komponen "Simulasi Kotak Masuk" yang langsung menampilkan 6-digit kode OTP di layar browser web (`web/production.html` dan `web/prod.js`).
* **Dampak**: Cacat desain keamanan fatal (*security flaw*); kode verifikasi rahasia bocor ke sisi klien dan dapat dimanipulasi oleh skrip peramban tanpa membuktikan kepemilikan email sebenarnya.
* **Akar Penyebab**: Asumsi kenyamanan pengujian demo lokal yang mengabaikan prinsip autentikasi *Out-of-Band* (OOB).
* **Solusi & Implementasi**:
  1. Menghapus total seluruh variabel dan elemen visual simulasi kode di frontend.
  2. Pembuatan kode OTP dipindahkan murni ke backend Go menggunakan CSPRNG (`crypto/rand`).
  3. Backend mengintegrasikan layanan pengiriman email riil via Resend API dan SMTP Relay.

---

### C. Halusinasi Kemampuan Sandbox Pengiriman Email
* **Deskripsi Anomali**: Asumsi bahwa domain uji gratis `onboarding@resend.dev` dapat mengirim email verifikasi ke alamat email publik sembarang (`@gmail.com`, `@kampus.ac.id`, dll) tanpa konfigurasi domain sendiri.
* **Dampak**: Layanan Resend API mengembalikan galat HTTP `403 Forbidden: You can only send testing emails to your own email address`.
* **Akar Penyebab**: Kebijakan anti-spam global provider cloud transactional email membatasi sandbox hanya ke email pemilik akun terverifikasi.
* **Solusi & Implementasi**:
  1. Menyiapkan arsitektur produksi dengan dukungan Custom Domain (`RESEND_FROM`) dan protokol SMTP internal kantor.
  2. Menambahkan fallback *Smart Sandbox Routing* otomatis untuk tahap pengujian: jika target penerima di luar email terdaftar pada mode non-produksi, email dialihkan ke verifikator dengan penandaan subjek identitas pemohon asli.

---

## 3. Rincian Ketidaksesuaian Teknis & Bug Implementasi

### A. Bug Javascript Runtime: `now is not defined`
* **Lokasi Berkas**: `web/prod.js` fungsi `signDocument()`.
* **Gejala**: Tombol "Tandatangani Dokumen" tidak merespons di peramban pengguna; konsol browser melempar galat `ReferenceError: now is not defined`.
* **Akar Masalah**: Properti `signedResult.signedAt = now.toISOString()` dipanggil sebelum deklarasi `const now = new Date()`.
* **Solusi**: Inisialisasi eksplisit objek tanggal di awal blok penandatanganan dan redeploy ke Netlify.

---

### B. Kerusakan Dokumen Multi-Signature (AcroForm Clobbering)
* **Lokasi Berkas**: Engine penyusunan PDF incremental update.
* **Gejala**: Ketika dokumen yang sudah memiliki tanda tangan pertama ditandatangani ulang oleh pihak kedua, tanda tangan pertama menjadi rusak (*broken signature* / *invalid hash*).
* **Akar Masalah**: Kamus `/Fields` pada objek `/AcroForm` ditimpa ulang hanya dengan field tanda tangan baru, menghilangkan referensi field tanda tangan lama.
* **Solusi**: Memperbaiki logika parser PDF agar membaca seluruh array `/Fields` eksisting, kemudian menyematkan field baru secara inkremental tanpa memodifikasi byte revisi sebelumnya.

---

### C. Injeksi ByteRange Non-Deterministik
* **Lokasi Berkas**: Modul penyusunan biner PAdES.
* **Gejala**: Injeksi biner tanda tangan meleset jika dokumen PDF memiliki objek teks yang kebetulan mengandung kata `/Contents <`.
* **Akar Masalah**: Penggunaan fungsi string pencarian maju `indexOf('/Contents <')`.
* **Solusi**: Mengganti pencarian dengan penargetan deterministik deretan 65.536 karakter nol (`lastIndexOf(placeholder)`), menjamin penempatan biner PKCS#7 100% presisi.

---

### D. Rantai Sertifikat Tidak Lengkap pada Kontainer PKCS#7
* **Lokasi Berkas**: `crypto/ca.go` dan `crypto/pades.go`.
* **Gejala**: OpenSSL dan Adobe Acrobat menampilkan status `unable to get local issuer certificate`.
* **Akar Masalah**: Hanya menyertakan *Signer Certificate* (End-Entity) ke dalam array `certificates` pada ASN.1 SignedData, tanpa menyertakan Sub-CA dan Root CA ARSign.
* **Solusi**: Mengemas utuh 3-tier rantai sertifikat (*ARSign Root CA* -> *ARSign Sub-CA Pelayanan TTE* -> *Signer Certificate*) ke dalam biner PKCS#7.

---

## 4. Status Pengujian Pasca-Perbaikan
Seluruh perbaikan di atas telah melalui pengujian otomatis E2E (`node test_functional_flow.js`) dengan hasil:
* **Generasi Kunci ML-DSA-65**: LULUS (FIPS 204: 1.952 B public key, 4.032 B private key).
* **Onboarding & OTP Email**: LULUS (Pengiriman riil & anti-brute force).
* **Eksekusi TTE PAdES ISO 32000-1**: LULUS (Komputasi ~140 ms, 3.309 B signature).
* **Verifikasi ByteRange & Rantai Trust**: LULUS (Integritas 100%, 3-tier trust terverifikasi).

