# AGENTS.md: Instruksi untuk coding agent di repo PatchSense

File ini untuk Cursor, Codex, Claude Code, Kodi, dan agent lain yang bekerja di repo ini. Salin ke root repo (Claude Code juga membaca `CLAUDE.md`; buat `CLAUDE.md` berisi satu baris `@AGENTS.md` atau salinan file ini).

## 1. Konteks proyek

PatchSense adalah CLI Rust open source untuk triage CVE: membaca lockfile (npm, pnpm, yarn, PyPI, Composer, Go, Maven, Cargo), mencocokkan dengan OSV, memperkaya dengan EPSS, CISA KEV, dan CVSS, lalu memberi skor prioritas 0–100 (Kritis ≥ 70, Perlu dicek 40–69, Bisa ditunda < 40). Output: tabel, JSON, SARIF, markdown, laporan GitLab, komentar PR/MR. AI opsional lewat agent milik user (`patchsense mcp`, `scan --explain`, `init --agent`), tanpa API key milik PatchSense. Lisensi `MIT OR Apache-2.0`.

- Spesifikasi lengkap: `docs/PRD.md`. Daftar tugas: `docs/TASKS.md`.
- Keputusan di PRD §1.2 **sudah dikunci**. Jangan mengubahnya (misalnya menambah web app, mengganti bahasa, memanggil API model langsung, atau menambah ekosistem yang ditunda). Bila menurutmu ada keputusan yang perlu diubah, tulis usulan di deskripsi PR dan berhenti.
- Non-tujuan (PRD §4.2) tidak boleh dibangun di MVP.

## 2. Struktur repo

```
crates/patchsense-core/   library: model, config, discovery, lockfile/*, http, osv, enrich/*, cache, score, scan, report/*
crates/patchsense/        biner: cli, table, progress, comment/*, mcp, agent/*, init
tests/fixtures/          fixture nyata per ekosistem + respon API
templates/gitlab/        template GitLab CI
action.yml               GitHub Action
schemas/                 JSON Schema report
```

Aturan lapisan: `patchsense-core` tidak boleh bergantung pada `clap`, `comfy-table`, `indicatif`, atau `rmcp`, dan tidak mencetak ke stdout/stderr. Semua jaringan lewat trait `HttpClient`.

## 3. Konvensi kode Rust

- Format: `cargo fmt --all`. CI menjalankan `cargo fmt --all --check`.
- Lint: `cargo clippy --workspace --all-targets --all-features -- -D warnings`. Jangan menambah `#[allow(...)]` tanpa komentar alasan.
- Error handling:
  - `patchsense-core`: tipe error eksplisit dengan `thiserror` (`CoreError` dan varian per modul). Tidak ada `anyhow` di core.
  - `patchsense` (biner): `anyhow::Result` dengan `.context("...")` yang menyebut file/URL terkait.
  - Dilarang `unwrap()`/`expect()` di kode non-tes, kecuali invarian yang terbukti dan diberi komentar `// INVARIANT: ...`. Tidak boleh `panic!` karena input user.
- Async: `tokio` hanya untuk I/O jaringan dan orkestrasi. Parser lockfile adalah fungsi sinkron murni (`&str` → struct).
- Serde: `#[serde(deny_unknown_fields)]` untuk config; untuk respon API **jangan** pakai `deny_unknown_fields` (API bisa menambah field).
- Output deterministik: urutkan koleksi sebelum ditampilkan atau di-serialize (`BTreeMap` atau sort eksplisit), supaya snapshot stabil.
- Nama identifier, perintah, flag, dan field JSON dalam Bahasa Inggris. Teks yang tampil ke user (label tier, pesan) boleh Bahasa Indonesia sesuai PRD; label tier wajib "Kritis", "Perlu dicek", "Bisa ditunda".
- Dependency: hanya dari daftar PRD §10.3. Tambahkan dengan `cargo add` (versi stabil terbaru), jangan menulis nomor versi karangan. Dependency baru di luar daftar wajib dijelaskan di PR.
- `reqwest` wajib memakai rustls (`default-features = false`, fitur rustls). `rusqlite` wajib fitur `bundled`.
- Jangan pernah mencetak token (`GITHUB_TOKEN`, `GITLAB_TOKEN`) ke log.

## 4. Menjalankan tes

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo insta test --review        # bila snapshot berubah (butuh cargo-insta)
```

Tes end-to-end opsional yang menyentuh jaringan atau agent sungguhan hanya boleh jalan di balik env var dan `#[ignore]`:
- `PATCHSENSE_E2E_NETWORK=1 cargo test -- --ignored` (memanggil OSV/EPSS/KEV asli)
- `PATCHSENSE_E2E_AGENT=1 cargo test -- --ignored` (memanggil codex/claude/agent asli)

## 5. Aturan tes

### 5.1 Tanpa jaringan di unit test dan integration test default
- Unit test **tidak boleh** memanggil API jaringan (OSV, EPSS, KEV, GitHub, GitLab). Pakai `FakeHttp` dari `core/http.rs` yang membaca fixture JSON di `tests/fixtures/{osv,epss,kev}/`.
- Integration test CLI boleh memakai server HTTP lokal (mis. `wiremock`) dengan base URL dari env `PATCHSENSE_OSV_URL`, `PATCHSENSE_EPSS_URL`, `PATCHSENSE_KEV_URL`. Tidak boleh keluar ke internet.
- Tes `--offline` wajib memakai `FakeHttp::forbid()` yang gagal bila dipanggil.
- Tes agent memakai skrip palsu di `PATH` sementara, bukan agent sungguhan.

### 5.2 Fixture lockfile nyata
- Fixture lockfile harus **berasal dari proyek open source nyata** (bukan ditulis tangan), kecuali fixture khusus untuk kasus error/batas yang diberi nama `synthetic_*.`.
- Lokasi: `tests/fixtures/<ecosystem>/<nama-proyek>/<lockfile>` plus `SOURCE.md` berisi URL repo, commit/tag, tanggal diambil, dan lisensi proyek sumber. Pastikan lisensinya mengizinkan redistribusi (MIT, Apache, BSD, dan sejenisnya).
- Fixture besar boleh dipangkas, tapi struktur aslinya dipertahankan dan pemangkasan dicatat di `SOURCE.md`.
- Setiap parser minimal 2 fixture nyata, mencakup versi format berbeda bila ada (npm v1/v3, pnpm v6/v9, yarn classic/Berry).
- Fixture respon API diambil dari respon asli (sekali, manual), dipangkas, dan dicatat sumber serta tanggalnya.

### 5.3 Snapshot `insta`
- Gunakan `insta::assert_yaml_snapshot!` atau `assert_json_snapshot!` untuk hasil parser, report JSON, SARIF, markdown, tabel (tanpa warna), dan argumen adapter agent.
- Redaksi nilai yang berubah-ubah (`generated_at`, `fetched_at`, path absolut, versi tool) dengan redaction `insta`.
- File snapshot (`snapshots/*.snap`) di-commit. Jangan pernah commit `*.snap.new`.
- Perubahan snapshot harus disengaja dan dijelaskan di PR. Jangan menerima snapshot baru secara massal tanpa membacanya.

## 6. Alur kerja per tugas (`docs/TASKS.md`)

1. Ambil tugas berikutnya yang belum dicentang dan semua dependensinya (`Dep`) sudah selesai. Kerjakan **satu tugas per sesi/PR**.
2. Baca bagian PRD yang dirujuk dan file yang disebut di "File".
3. Buat branch `w<minggu>-t<nomor>-<slug>`, mis. `w1-t6-npm-parser`.
4. Tulis tes dulu bila memungkinkan (fixture + snapshot), lalu implementasi.
5. Jalankan perintah di §4 sampai semuanya lolos.
6. Centang tugas di `docs/TASKS.md` dalam PR yang sama, dan tambahkan catatan singkat bila ada penyimpangan dari PRD.
7. Commit dengan pesan berformat Conventional Commits, mis. `feat(lockfile): parse package-lock v3 (W1-T6)`.
8. Deskripsi PR: ID tugas, ringkasan, cara menguji, asumsi atau keputusan kecil yang diambil, dan sisa pekerjaan.

Bila tugas ternyata terlalu besar, pecah menjadi sub-tugas `W1-T6a`, `W1-T6b` di `docs/TASKS.md` dan kerjakan yang pertama saja. Bila spesifikasi ambigu, pilih opsi paling sederhana yang konsisten dengan PRD, tulis asumsinya di PR, dan lanjutkan; tanya Widya hanya untuk hal yang menyentuh keputusan terkunci, nama publik, atau rilis.

## 7. Batasan tindakan

- Jangan push tag, publish ke npm/PyPI/crates.io/Homebrew, membuat rilis GitHub, atau membuat/meminta token dan secret. Itu dilakukan Widya.
- Jangan menulis ke konfigurasi global user (`~/.codex`, `~/.cursor`, `~/.claude`) dari kode PatchSense; `init --print-mcp-config` hanya mencetak.
- Adapter agent tidak boleh memakai flag yang memberi izin tulis atau melewati izin (`--force`, `--yolo`, `danger-full-access`, `bypassPermissions`, `--dangerously-skip-permissions`).
- Jangan menambah telemetri.

## 8. Definisi selesai (Definition of Done)

Sebuah tugas selesai bila:
- [ ] Semua kriteria "Selesai bila" di `docs/TASKS.md` terpenuhi.
- [ ] `cargo fmt --all --check`, `cargo clippy ... -D warnings`, dan `cargo test --workspace` lolos di lokal (dan CI bila sudah ada).
- [ ] Tidak ada tes yang memanggil jaringan atau agent sungguhan tanpa `#[ignore]` + env var.
- [ ] Fixture baru punya `SOURCE.md`; snapshot baru sudah direview.
- [ ] Tidak ada `unwrap()`/`expect()` baru di kode non-tes tanpa komentar `INVARIANT`.
- [ ] Perilaku yang terlihat user (flag, output, exit code, field JSON) sesuai PRD, atau penyimpangannya tertulis di PR dan di PRD.
- [ ] Dokumentasi terkait (help `clap`, README bila relevan) ikut diperbarui.
- [ ] Tugas dicentang di `docs/TASKS.md`.

## Alur Git (wajib, ditetapkan Widya)

1. Untuk setiap tugas atau kelompok tugas kecil dari `docs/TASKS.md`, buat **issue** GitHub dulu. Judulnya pakai ID tugas, misal `W1-T1: ...`, dan isinya kriteria selesai.
2. Kerjakan di branch terpisah, lalu buka **PR** yang menautkan issue tersebut (`Closes #<nomor>`).
3. Merge ke branch default `master` hanya setelah PR dibuka dan CI hijau. Jangan pernah commit langsung ke `master`.
