# CLAUDE.md — Panduan Pengembangan ARSign untuk Claude Code

Aturan bersama untuk semua agen AI (Claude Code maupun agen lain milik rekan tim) ada di
`AGENTS.md` dan diimpor di bawah ini. Ubah aturan bersama di `AGENTS.md`, bukan di sini.

@AGENTS.md

## Tambahan Khusus Claude Code
1. **Changelog dulu, baru selesai.** Sebelum melaporkan tugas selesai, tulis entri baru di
   `docs/changelog/<github-login>.md` sesuai template di `docs/changelog/README.md`.
   Login GitHub pengguna Claude Code di mesin ini: `EzrDH`.
2. **Konfirmasi sebelum push.** Commit lokal boleh, tetapi `git push` ke remote bersama
   (`origin`) dan pembuatan PR hanya setelah pengguna menyetujui.
3. **Branch baru per tugas** sesuai bagian 5 `AGENTS.md`; jangan bekerja langsung di `main`.
4. **Bersihkan efek samping test.** Setelah `go test ./...`, cek `git status`; pulihkan
   `crypto/ARSIGN_*` jika berubah tanpa disengaja.
5. **Bahasa.** Dokumentasi, changelog, dan komentar baru ditulis dalam Bahasa Indonesia.
