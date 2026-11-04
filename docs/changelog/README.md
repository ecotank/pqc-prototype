# Changelog Kontributor ARSign

Folder ini menyimpan catatan perubahan **rinci** per kontributor. Commit message hanya
merangkum; changelog menjelaskan *mengapa*, *apa dampaknya*, dan *bagaimana diuji*,
sehingga rekan tim (dan agen AI mereka) bisa memahami setiap perubahan tanpa membaca diff.

## Aturan
1. Satu file per kontributor: `docs/changelog/<github-login>.md` (contoh: `EzrDH.md`).
   Karena tiap orang menulis di file sendiri, changelog tidak saling konflik saat merge.
2. Entri **terbaru di paling atas**.
3. Entri ditulis **di commit/PR yang sama** dengan perubahan yang dicatat.
4. Setiap perubahan wajib dicatat, termasuk perubahan kecil, dokumentasi, dan konfigurasi.
5. Jangan menulis rahasia (password, API key, isi kunci privat, data pribadi) di changelog.
6. Kolom "Commit/PR" boleh diisi `(belum di-commit)` lalu diperbarui setelah PR dibuat.

## Template Entri

```markdown
## [YYYY-MM-DD] <judul singkat perubahan>

- **Branch**: `feature/nama-fitur`
- **Commit/PR**: `<hash pendek>` / <link PR>
- **Agen AI**: Claude Code | Codex | Cursor | (tanpa agen)
- **Jenis**: feat | fix | docs | refactor | test | chore

### Ringkasan
Satu sampai tiga kalimat tentang apa yang berubah.

### Alasan
Masalah atau kebutuhan yang mendorong perubahan (tautkan issue/temuan bila ada).

### Rincian Perubahan
| File | Perubahan |
|---|---|
| `crypto/pades.go` | Penjelasan perubahan di file ini |

### Dampak
- Perilaku yang berubah bagi pengguna/API.
- Perubahan skema DB, konfigurasi `.env`, atau dependensi (jika ada).

### Pengujian
- Perintah yang dijalankan dan hasilnya (mis. `go test ./...` lulus).
- Uji manual yang dilakukan.

### Risiko & Catatan Lanjutan
- Hal yang belum selesai, asumsi, atau hal yang perlu ditinjau rekan.
```
