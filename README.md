# Purwarupa Penandatanganan Digital ML-DSA (NIST FIPS 204) & Simulasi Migrasi RSA ke PQC
**Balai Besar Sertifikasi Elektronik (BSrE) - Badan Siber dan Sandi Negara (BSSN)**

Purwarupa (Proof of Concept / Mini Project) penandatanganan digital pascakuantum berbasis **ML-DSA (Module-Lattice-Based Digital Signature Algorithm - NIST FIPS 204)** dengan perbandingan performa dan karakteristik terhadap **RSA-2048 / RSA-3072**, meniru pola layanan **Esign Client Service (ECS)** BSrE.

Tersedia **2 Antarmuka Web Terpisah**:
1. **Web Siap Produksi (Enterprise TTE Portal)**: Tampilan bersih, resmi, siap pakai untuk pengguna/instansi pemerintah (layanan TTE publik).
2. **Web Visualisasi Proses (Laboratorium Riset Kriptografi)**: Tampilan teknis mendalam untuk meneliti proses matematis, matriks lattice, penolakan sampling (*rejection sampling*), dan inspeksi byte tanda tangan.

---

## 👥 Tim Pengembang (Kelompok RPLK 2 BSrE)
- **Muhammad Ezra Dhiatara** (NPM: 2322101945) - Layanan Penandatanganan Golang & Arsitektur API
- **Satria Alba Pramasha** (NPM: 2322101974) - Kriptografi Pascakuantum & Kepatuhan FIPS 204
- **Sulthan Aidhan Afiq Sukarto** (NPM: 2322101979) - Antarmuka Web Dashboard & Klien Tiruan ECS

---

## 🌐 2 Antarmuka Web (Dual Portal)

| Antarmuka | URL Akses | Sasaran Pengguna | Fokus Konten yang Ditampilkan |
|---|---|---|---|
| **Web Siap Produksi** | [http://localhost:8080](http://localhost:8080) | Pejabat, ASN, Masyarakat, Aplikasi Instansi | • Layanan penandatanganan dokumen resmi (PDF/Teks)<br>• Tanda terima resmi TTE BSrE & Segel Elektronik<br>• Portal verifikasi keabsahan publik (Status Hijau/Merah)<br>• Buku registrasi dokumen instansi |
| **Web Visualisasi Proses** | [http://localhost:8081](http://localhost:8081) atau [http://localhost:8080/process](http://localhost:8080/process) | Peneliti, Katim Dev BSrE, Penguji Akademik | • 6-Step Visualizer Alur Sign FIPS 204 (Pre-hash, ExpandA, Masking, Fiat-Shamir, Rejection, Packing)<br>• 5-Step Visualizer Alur Verify & pinpoint kegagalan tampering<br>• Anatomi 3.309 byte signature (c, z, h)<br>• Dasbor benchmark performa & 18 uji ACVP |

> *Kedua web dilengkapi tombol toggle switcher di bagian header atas untuk berpindah mode secara instan.*

---

## 📌 Ringkasan Implementasi Sesuai PRD & Analisis Kebutuhan
1. **Algoritma Pascakuantum (PQC)**:
   - **ML-DSA-44** (NIST Security Category 2 / Setara SHA-256)
   - **ML-DSA-65** (NIST Security Category 3 / Standar Rekomendasi BSrE)
   - **ML-DSA-87** (NIST Security Category 5 / Rekomendasi Root CA)
2. **Algoritma Pembanding (Klasik)**:
   - **RSA-2048** & **RSA-3072** (PKCS#1 v1.5 dengan digest SHA-256)
3. **Pola Penandatanganan ECS (Pre-Hash)**:
   - Klien menghitung hash dokumen secara lokal (SHA-256).
   - Hanya nilai hash yang dikirim ke API penandatanganan (dokumen asli tidak pernah keluar dari jaringan instansi).
4. **Skenario Koeksistensi Masa Transisi (Dual Signing)**:
   - Penandatanganan ganda (*dual sign*) di mana payload ditandatangani oleh ML-DSA dan RSA sekaligus.
5. **Kepatuhan & Batasan Khusus Proyek Mini**:
   - **Kepatuhan FIPS 204**: Memenuhi spesifikasi FIPS 204 (ukuran kunci publik 1.312–2.592 B, signature 2.420–4.627 B, derivasi seed deterministik, resistansi manipulasi).
   - **Target Latensi Penandatanganan**: `=< 2.0 detik` (**Realisasi aktual: < 1 ms / sub-milidetik**).
   - **Manajemen Kunci**: Disederhanakan (*in-memory / on-demand key generation*) tanpa enkripsi keystore rumit sesuai instruksi penyederhanaan prototype.

---

## 🚀 Cara Menjalankan

### 1. Menjalankan Server Web (Menjalankan Sekaligus Port 8080 & 8081)
```powershell
cd d:\pkl\pqc-prototype
.\pqc-server.exe
```
- Buka Web Siap Produksi: **`http://localhost:8080`**
- Buka Web Visualisasi Proses: **`http://localhost:8081`**

### 2. Menjalankan Uji Melalui Baris Perintah (CLI - Rilis 0)
```powershell
cd d:\pkl\pqc-prototype

# Uji kepatuhan FIPS 204
.\pqc-cli.exe test-fips

# Jalankan benchmark kinerja perbandingan ML-DSA vs RSA (50 iterasi)
.\pqc-cli.exe benchmark -n 50

# Bangkitkan pasangan kunci baru
.\pqc-cli.exe keygen -alg ML-DSA-65

# Tandatangani pesan
.\pqc-cli.exe sign -alg ML-DSA-65 -msg "Surat Keputusan BSrE 2026"

# Simulasi skema transisi dual-sign (ML-DSA + RSA)
.\pqc-cli.exe dual-sign -msg "Dokumen Bersama Transisi"
```

### 3. Menjalankan Simulasi Klien ECS (Node.js)
```powershell
cd d:\pkl\pqc-prototype
node client-mock/ecs_client.js
```

### 4. Menjalankan Pengujian Unit Kriptografi (Go Test)
```powershell
cd d:\pkl\pqc-prototype
go test -v ./crypto
```

---

## 📊 Hasil Pengukuran Kinerja Empiris

| Algoritma | Standar | Kunci Publik | Kunci Privat | Tanda Tangan | Waktu Sign (Rata-rata) | Waktu Sign (P95) | Waktu Verify | Status Target `=< 2s` |
|---|---|---:|---:|---:|---:|---:|---:|:---:|
| **ML-DSA-44** | FIPS 204 | 1.312 B | 2.560 B | 2.420 B | 0,155 ms | 0,520 ms | 0,026 ms | **LULUS** |
| **ML-DSA-65** | FIPS 204 | 1.952 B | 4.032 B | 3.309 B | 0,161 ms | 0,543 ms | 0,000 ms | **LULUS** |
| **ML-DSA-87** | FIPS 204 | 2.592 B | 4.896 B | 4.627 B | 0,052 ms | 0,520 ms | 0,026 ms | **LULUS** |
| **RSA-2048** | PKCS#1 | 294 B | 1.190 B | 256 B | 0,933 ms | 1,510 ms | 0,021 ms | **LULUS** |
| **RSA-3072** | PKCS#1 | 422 B | 1.750 B | 384 B | 2,997 ms | 3,647 ms | 0,134 ms | **LULUS** |

---

## 📡 Referensi Endpoint REST API

- `POST /api/v1/keys/generate?algorithm={alg}`: Bangkitkan pasangan kunci baru.
- `POST /api/v1/sign`: Menerima hash dokumen (`digest`), mengembalikan tanda tangan.
- `POST /api/v1/verify`: Memvalidasi integritas pesan/digest terhadap tanda tangan & kunci publik.
- `POST /api/v1/dual-sign`: Menghasilkan tanda tangan hibrida/ganda (ML-DSA + RSA).
- `POST /api/v1/dual-verify`: Memverifikasi kedua tanda tangan secara simultan.
- `POST /api/v1/process/trace-sign`: Dekomposisi 6-tahap penandatanganan dan pengukuran latensi per tahap.
- `POST /api/v1/process/trace-verify`: Dekomposisi 5-tahap verifikasi dan isolasi kegagalan manipulasi.
- `POST /api/v1/benchmarks`: Menjalankan pengujian performa multi-iterasi.
- `GET /api/v1/benchmarks/export`: Mengunduh hasil benchmark dalam format CSV.
- `GET /api/v1/fips204-compliance`: Laporan kepatuhan spesifikasi FIPS 204.
- `GET /api/v1/audit`: Daftar riwayat operasi sistem (KF-30).
