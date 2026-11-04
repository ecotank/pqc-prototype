# Panduan Kolaborasi Tim ARSign (Untuk Rekan Pengembang)

Selamat datang di proyek **ARSign**! Panduan ini dirancang agar kamu dapat langsung mulai coding bersama menggunakan **Claude Code** atau editor favoritmu tanpa hambatan.

---

## 1. Persiapan Awal (Hanya 1 Kali)
1. **Clone Repository**:
   ```bash
   git clone https://github.com/ecotank/pqc-prototype.git
   cd pqc-prototype
   ```
2. **Jalankan Aplikasi**:
   - Pengguna Windows: Dobel klik file `setup-dev.bat` (atau ketik `go run .`)
   - Pengguna Linux/Mac: Jalankan `bash setup-dev.sh` (atau `go run .`)
3. Buka di browser: `http://localhost:8080` (Aplikasi langsung siap pakai dengan database SQLite otomatis).

---

## 2. Menggunakan Claude Code (CLI & GUI)

### A. Jika Menggunakan Claude Code GUI (Aplikasi Desktop / VS Code / Cursor):
1. Buka aplikasi Claude GUI kamu.
2. Klik **Open Folder** / **Pilih Folder Proyek** -> pilih folder `pqc-prototype` hasil clone.
3. Claude GUI akan **secara otomatis membaca file `CLAUDE.md`** sebagai konteks utama proyek.
4. Kamu bisa langsung chatting santai, contoh:
   > *"Tolong buatkan fitur X di `web/prod.js`"*
5. Setelah Claude selesai mengedit, kamu bisa cek visual perubahannya langsung di tab **Source Control (Git)** pada aplikasi GUI kamu, lalu klik **Commit & Push**.

### B. Jika Menggunakan Claude Code Terminal (CLI):
Jalankan perintah:
```bash
claude
```

---

## 3. Alur Kerja Git & Kolaborasi
Agar pekerjaan tidak saling menimpa (*conflict*):
1. **Buat Branch Fitur Baru**:
   ```bash
   git checkout -b feature/nama-fitur-kamu
   ```
2. **Coding bersama Claude Code di branch tersebut.**
3. **Commit dan Push**:
   ```bash
   git add .
   git commit -m "feat: deskripsi perubahan kamu"
   git push origin feature/nama-fitur-kamu
   ```
4. **Buka Pull Request (PR) di GitHub**.
   Sistem bot Telegram akan otomatis memberi tahu tim bahwa ada kodingan baru untuk di-merge ke branch `main`.

---

## 4. Testing & Verifikasi Kode
Sebelum push, selalu pastikan fitur berjalan dengan script pengujian otomatis:
```bash
node scratch/test_live_functional.js
```
Jika seluruh indikator menunjukkan `[PASS]`, kode kamu aman dan siap digabungkan.

