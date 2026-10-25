# PatchSense: Pembagian Tugas MVP (6 minggu)

Cara memakai:
- Kerjakan tugas **berurutan sesuai ID**, satu tugas = satu branch = satu PR (atau satu commit besar bila kerja solo).
- Jangan mulai tugas yang dependensinya belum selesai.
- Centang `[x]` hanya bila semua kriteria selesai terpenuhi dan `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, dan `cargo test --workspace` lolos.
- Rujukan spesifikasi: [`PRD.md`](PRD.md) (nomor bagian ditulis sebagai §). Aturan kerja: [`AGENTS.md`](../AGENTS.md).
- Path modul mengikuti PRD §10.2. `core/` = `crates/patchsense-core/src/`, `cli/` = `crates/patchsense/src/`.

Legenda: **File** = file/modul yang disentuh. **Selesai bila** = kriteria selesai. **Dep** = dependensi.

---

## Minggu 1: Fondasi (workspace, model, parser npm dan PyPI, klien OSV)

- [x] **W1-T1 Inisialisasi workspace dan lisensi**
  - Deskripsi: buat workspace Cargo dengan crate `patchsense-core` (lib) dan `patchsense` (bin), edisi 2021, `license = "MIT OR Apache-2.0"`, `rust-version` diisi. Tambahkan `LICENSE-MIT`, `LICENSE-APACHE`, `.gitignore`, `rustfmt.toml` (boleh kosong), README placeholder, dan salin `AGENTS.md` dari paket handoff.
  - File: `Cargo.toml`, `crates/*/Cargo.toml`, `crates/*/src/lib.rs|main.rs`, `LICENSE-*`, `AGENTS.md`
  - Selesai bila: `cargo build --workspace` sukses; `cargo run -p patchsense -- --version` mencetak versi.
  - Dep: –

- [x] **W1-T2 CI dasar**
  - Deskripsi: workflow GitHub Actions `ci.yml` dengan job fmt, clippy (`-D warnings`), dan test pada matrix ubuntu, macos, windows.
  - File: `.github/workflows/ci.yml`
  - Selesai bila: workflow valid (lolos `actionlint` bila tersedia) dan hijau di PR pertama.
  - Dep: W1-T1

- [ ] **W1-T3 Model domain dan error**
  - Deskripsi: definisikan `Ecosystem` (npm, PyPI, Packagist, Go, Maven, crates.io, dengan `as_osv_str()` dan parsing nama config), `Package`, `ParsedLockfile` (packages + warnings), `Advisory`, `Finding`, `Tier` (`Critical`, `Review`, `Defer`, dengan `label_id()` → "Kritis"/"Perlu dicek"/"Bisa ditunda"), `Report`. Buat `CoreError` dengan `thiserror`.
  - File: `core/model.rs`, `core/error.rs`, `core/lib.rs`
  - Selesai bila: semua tipe `Serialize`/`Deserialize`; unit test pemetaan nama ekosistem config → OSV (PRD §7) lolos.
  - Dep: W1-T1

- [x] **W1-T4 Trait parser dan registry**
  - Deskripsi: trait `LockfileParser` (PRD §10.2) dan fungsi `parser_for(path) -> Option<&dyn LockfileParser>` berdasarkan nama file. Normalisasi nama PyPI (PEP 503) sebagai helper.
  - File: `core/lockfile/mod.rs`
  - Selesai bila: unit test pemetaan nama file → parser untuk 9 nama file di PRD §5.1 (parser belum ada boleh `todo` di balik feature internal, atau registry diisi bertahap).
  - Dep: W1-T3

- [x] **W1-T5 Discovery lockfile**
  - Deskripsi: telusuri direktori rekursif, lewati `node_modules`, `vendor`, `target`, `.git`, `.venv`, `venv`, dan glob `--exclude`. Bila `PATH` adalah file, kembalikan file itu saja.
  - File: `core/discovery.rs`, `tests/fixtures/discovery/`
  - Selesai bila: tes dengan `tempfile` membuktikan direktori default dilewati, exclude bekerja, dan urutan hasil deterministik (diurutkan).
  - Dep: W1-T4

- [x] **W1-T6 Parser `package-lock.json`**
  - Deskripsi: dukung lockfileVersion 2/3 (`packages`) dan v1 (`dependencies`) best effort. Ambil nama dari key `node_modules/<nama>` (termasuk scoped dan nested), tandai `dev`, tentukan `direct` dari `packages[""]`. Lewati entri `link: true`.
  - File: `core/lockfile/npm.rs`, `tests/fixtures/npm/<proyek>/package-lock.json` (+ `SOURCE.md`)
  - Selesai bila: ≥2 fixture nyata (satu v3, satu v1 atau v2), snapshot `insta` daftar paket, tes lockfile rusak memberi `CoreError` dengan nama file.
  - Dep: W1-T4

- [x] **W1-T7 Parser `requirements.txt`**
  - Deskripsi: hanya `name==version` (dengan extras dan marker diabaikan); lewati komentar, `-r`, `-e`, URL, dan baris tanpa pin dengan warning berisi nomor baris.
  - File: `core/lockfile/requirements.rs`, `tests/fixtures/pypi/`
  - Selesai bila: ≥2 fixture nyata, snapshot paket dan warning, nama dinormalisasi PEP 503.
  - Dep: W1-T4

- [x] **W1-T8 Parser `poetry.lock`**
  - Deskripsi: parse `[[package]]` (name, version, category/groups bila ada). `direct` dari `pyproject.toml` di direktori yang sama bila ada (`[tool.poetry.dependencies]` atau `[project].dependencies`), kalau tidak `None`.
  - File: `core/lockfile/poetry.rs`, `tests/fixtures/pypi/`
  - Selesai bila: ≥2 fixture nyata (satu dengan `pyproject.toml`), snapshot lolos.
  - Dep: W1-T4

- [x] **W1-T9 Abstraksi HTTP dan fake**
  - Deskripsi: trait `HttpClient` dengan impl `ReqwestClient` (rustls, user-agent `patchsense/<versi>`, timeout, retry 429/5xx dengan backoff maksimal 3 kali) dan `FakeHttp` (respon dari fixture, merekam request, opsi "panic bila dipanggil" untuk tes offline). Base URL bisa diganti via env (PRD §6.7).
  - File: `core/http.rs`
  - Selesai bila: unit test retry memakai `FakeHttp` (tanpa jaringan) dan tes bahwa `FakeHttp::forbid()` gagal bila dipanggil.
  - Dep: W1-T3

- [x] **W1-T10 Klien OSV: querybatch**
  - Deskripsi: kirim `POST /v1/querybatch` per chunk `OSV_BATCH_SIZE` (1000), petakan hasil kembali ke paket sesuai urutan, tangani `next_page_token`.
  - File: `core/osv.rs`, `tests/fixtures/osv/querybatch_*.json`
  - Selesai bila: tes dengan `FakeHttp` untuk chunking (mis. 2500 paket → 3 request), pagination 2 halaman, dan urutan hasil.
  - Dep: W1-T9

- [x] **W1-T11 Klien OSV: detail advisory**
  - Deskripsi: `GET /v1/vulns/{id}` paralel (konkurensi 8, `tokio` + semaphore), parse `aliases`, `summary`, `severity`, `database_specific.severity`, `affected[].ranges[].events`, `references`. Tentukan `fixed_versions` yang relevan untuk paket@versi terpasang (cocokkan `affected[].package.name`/ekosistem).
  - File: `core/osv.rs`, `tests/fixtures/osv/vulns/*.json`
  - Selesai bila: fixture asli (mis. GHSA-35jh-r3h4-6jhm untuk lodash) diparse benar: alias CVE-2021-23337, vector CVSS_V3, fixed 4.17.21; snapshot `Advisory`.
  - Dep: W1-T10

- [x] **W1-T12 Perintah `scan` minimal (end-to-end mentah)**
  - Deskripsi: `clap` dengan subcommand `scan [PATH]`, orkestrasi discovery → parse → OSV, cetak daftar sementara (tanpa skor) ke stdout. `main` memakai `anyhow` dan exit code 2 untuk error.
  - File: `cli/main.rs`, `cli/cli.rs`, `core/scan.rs`
  - Selesai bila: integration test `assert_cmd` dengan base URL OSV diarahkan ke fake (atau `wiremock` lokal) mencetak advisory lodash untuk fixture npm; tanpa lockfile → exit 2 dengan pesan jelas.
  - Dep: W1-T5, W1-T6, W1-T11

## Minggu 2: Parser lainnya

- [x] **W2-T1 Parser `pnpm-lock.yaml`**
  - Deskripsi: dukung lockfile v6 (key `/name@version` atau `/name/version`) dan v9 (`packages` + `snapshots`, key `name@version`). `direct` dari `importers`. Abaikan suffix peer (`(...)`).
  - File: `core/lockfile/pnpm.rs`, `tests/fixtures/pnpm/`
  - Selesai bila: fixture nyata v6 dan v9, snapshot lolos.
  - Dep: W1-T4

- [x] **W2-T2 Parser `yarn.lock` classic (v1)**
  - Deskripsi: parser manual format yarn v1 (blok `"spec", spec:` + `version "x"`). `direct` dari `package.json` sebelahnya bila ada.
  - File: `core/lockfile/yarn.rs`, `tests/fixtures/yarn/`
  - Selesai bila: ≥2 fixture nyata, scoped package benar, snapshot lolos.
  - Dep: W1-T4

- [ ] **W2-T3 Parser `yarn.lock` Berry (v2+)**
  - Deskripsi: deteksi `__metadata` (YAML), parse dengan `serde_yaml`, ambil `version` dan nama dari `resolution`. Lewati `workspace:` dan `patch:` lokal.
  - File: `core/lockfile/yarn.rs`, `tests/fixtures/yarn/`
  - Selesai bila: fixture nyata Berry, snapshot lolos, file yang sama tidak salah dideteksi sebagai classic.
  - Dep: W2-T2

- [ ] **W2-T4 Parser `composer.lock`**
  - Deskripsi: `packages` (direct/transitif dari `composer.json` `require`) dan `packages-dev` (dev). Versi tanpa prefix `v` untuk OSV Packagist (normalisasi, catat di kode).
  - File: `core/lockfile/composer.rs`, `tests/fixtures/composer/`
  - Selesai bila: ≥2 fixture nyata, satu fixture demo PHP2Shell disiapkan di `examples/php2shell-demo/` (versi PHP/paket rentan sesuai advisory), snapshot lolos.
  - Dep: W1-T4

- [ ] **W2-T5 Parser `go.sum` (+ `go.mod`)**
  - Deskripsi: ambil `module version` dari baris non-`/go.mod`, dedupe. Bila `go.mod` ada, tandai `// indirect` sebagai transitif dan sisanya direct; tanpa `go.mod` → `None`. Abaikan versi `+incompatible` suffix sesuai kebutuhan OSV (pertahankan prefix `v`).
  - File: `core/lockfile/gosum.rs`, `tests/fixtures/go/`
  - Selesai bila: ≥2 fixture nyata, snapshot lolos.
  - Dep: W1-T4

- [ ] **W2-T6 Parser `pom.xml`**
  - Deskripsi: `quick-xml`, ambil `dependencies/dependency` (groupId, artifactId, version, scope), resolve `${prop}` dari `<properties>` dan `${project.version}`. Versi yang tak bisa di-resolve (parent BOM, dependencyManagement eksternal) dilewati dengan warning. Nama = `groupId:artifactId`. Scope `test` = dev.
  - File: `core/lockfile/maven.rs`, `tests/fixtures/maven/`
  - Selesai bila: ≥2 fixture nyata (satu memakai properties), snapshot paket dan warning lolos.
  - Dep: W1-T4

- [ ] **W2-T7 Parser `Cargo.lock`**
  - Deskripsi: `[[package]]` dengan `source` dari registry crates.io; lewati path/git. `direct` dari `Cargo.toml` (termasuk workspace members) bila ada.
  - File: `core/lockfile/cargo.rs`, `tests/fixtures/cargo/`
  - Selesai bila: ≥2 fixture nyata (salah satunya boleh `Cargo.lock` repo ini sendiri), snapshot lolos.
  - Dep: W1-T4

- [ ] **W2-T8 Dedupe, `--keep-going`, filter ekosistem dan dev**
  - Deskripsi: dedupe paket lintas lockfile (ekosistem+nama+versi, pertahankan semua `source_file`), kumpulkan warning per file, file gagal tidak menghentikan scan kecuali semuanya gagal (exit 2). Terapkan `--ecosystem` dan `--no-dev`.
  - File: `core/scan.rs`, `cli/cli.rs`
  - Selesai bila: tes: satu file rusak + satu valid → scan jalan dengan warning; semua rusak → exit 2; filter bekerja.
  - Dep: W2-T1 s/d W2-T7, W1-T12

- [ ] **W2-T9 Tes properti parser (robustness)**
  - Deskripsi: tes bahwa setiap parser tidak panic untuk input acak/terpotong (pakai potongan fixture yang dipotong di berbagai titik; tanpa dependency fuzzing baru).
  - File: `crates/patchsense-core/tests/parser_robustness.rs`
  - Selesai bila: tes lolos untuk 9 parser.
  - Dep: W2-T8

## Minggu 3: Data dan skor (EPSS, KEV, CVSS, skor, cache)

- [ ] **W3-T1 Cache SQLite**
  - Deskripsi: `rusqlite` (bundled), tabel `meta(schema_version)`, `osv_vuln(id, modified, json, fetched_at)`, `epss(cve, score, percentile, date, fetched_at)`, `kev(catalog_version, json, fetched_at)`. API get/put dengan TTL. Lokasi sesuai PRD F5. Versi skema berbeda → buat ulang.
  - File: `core/cache.rs`
  - Selesai bila: tes dengan DB di `tempfile` untuk TTL kedaluwarsa, invalidasi `modified`, dan reset skema.
  - Dep: W1-T3

- [ ] **W3-T2 Integrasi cache ke klien OSV**
  - Deskripsi: detail advisory dibaca dari cache bila `modified` sama dan TTL belum lewat. Mode `--offline`, `--no-cache`, `--cache-dir`, dan `patchsense cache clear|info`.
  - File: `core/osv.rs`, `core/scan.rs`, `cli/cli.rs`
  - Selesai bila: tes: scan kedua tidak memanggil `/v1/vulns` (dihitung via `FakeHttp`); `--offline` dengan `FakeHttp::forbid()` lolos.
  - Dep: W3-T1, W1-T11

- [ ] **W3-T3 Enricher EPSS**
  - Deskripsi: `GET /data/v1/epss?cve=...` per chunk 100 CVE, parse string desimal → `f64`, simpan di cache.
  - File: `core/enrich/epss.rs`, `tests/fixtures/epss/*.json`
  - Selesai bila: tes chunking (250 CVE → 3 request), parsing, dan cache hit.
  - Dep: W3-T1, W1-T9

- [ ] **W3-T4 Enricher KEV**
  - Deskripsi: unduh feed KEV JSON, simpan per `catalogVersion`, bangun `HashMap<cve, KevEntry>`. Refresh maksimal sekali per 24 jam.
  - File: `core/enrich/kev.rs`, `tests/fixtures/kev/kev_small.json` (potongan feed asli, beberapa entri)
  - Selesai bila: tes lookup, TTL, dan field `knownRansomwareCampaignUse`.
  - Dep: W3-T1, W1-T9

- [ ] **W3-T5 CVSS**
  - Deskripsi: hitung base score dari vector CVSS v3.x (crate `cvss` atau implementasi sendiri dengan tes resmi), CVSS v4 bila didukung, fallback `database_specific.severity` (PRD F3 AC3.3).
  - File: `core/enrich/cvss.rs`
  - Selesai bila: unit test untuk ≥5 vector dengan skor yang dibandingkan dengan kalkulator resmi FIRST, plus fallback dan `None`.
  - Dep: W1-T11

- [ ] **W3-T6 Penggabungan alias dan enrichment**
  - Deskripsi: per advisory: kumpulkan CVE dari `id`/`aliases`, KEV any, EPSS max, CVSS tertinggi. Dedupe advisory yang saling alias untuk paket yang sama (pakai ID GHSA/OSV utama, simpan semua alias).
  - File: `core/enrich/mod.rs`
  - Selesai bila: tes untuk advisory dengan 2 CVE, tanpa CVE, dan dua advisory yang saling alias.
  - Dep: W3-T3, W3-T4, W3-T5

- [ ] **W3-T7 Konfigurasi `patchsense.toml`**
  - Deskripsi: struct `Config` sesuai PRD §7 (`deny_unknown_fields`), default, pencarian file naik sampai root git, merge dengan env dan flag (prioritas PRD AC9.3), validasi `ignore` (wajib `reason`, `expires` opsional).
  - File: `core/config.rs`, `cli/cli.rs`
  - Selesai bila: tes parse contoh PRD §7 persis, field asing → error, urutan prioritas, ignore kedaluwarsa memberi warning.
  - Dep: W1-T3

- [ ] **W3-T8 Mesin skor**
  - Deskripsi: implementasi formula PRD §9 termasuk normalisasi bobot, mode EPSS, `unknown_direct`, pembulatan, tier, `score_breakdown`, dan pengurutan deterministik (PRD AC4.4).
  - File: `core/score.rs`
  - Selesai bila: unit test kasus A–E di PRD §9 menghasilkan skor dan tier persis, plus tes batas 69.5/70/39.9/40 dan bobot non-100.
  - Dep: W3-T6, W3-T7

- [ ] **W3-T9 Pipeline scan lengkap dan `--fail-on`**
  - Deskripsi: sambungkan enrichment + skor + ignore ke `scan`, hitung `summary`, terapkan `--fail-on` dan exit code PRD §6.6.
  - File: `core/scan.rs`, `cli/main.rs`
  - Selesai bila: integration test: fixture dengan advisory KEV → exit 1 untuk `--fail-on critical`, exit 0 untuk `never`; error konfigurasi → exit 2.
  - Dep: W3-T2, W3-T8

## Minggu 4: Output (tabel, JSON, SARIF, markdown, GitLab)

- [ ] **W4-T1 Output JSON dan JSON Schema**
  - Deskripsi: serialisasi `Report` sesuai PRD §8, tulis `schemas/report.v1.json`, dan validasi output terhadap schema di tes (boleh dengan dev-dependency validator JSON Schema, atau tes struktur manual bila ingin menghindari dependency).
  - File: `core/report/json.rs`, `schemas/report.v1.json`
  - Selesai bila: snapshot `insta` JSON (redaksi `generated_at`, `fetched_at`) lolos dan valid terhadap schema.
  - Dep: W3-T9

- [ ] **W4-T2 Tabel terminal**
  - Deskripsi: `comfy-table` dengan kolom PRD AC6.1, warna per tier hanya di TTY, `--no-color`/`NO_COLOR`, ringkasan jumlah per tier di bawah tabel, `--min-score`. Progress `indicatif` di stderr hanya bila TTY.
  - File: `cli/table.rs`, `cli/progress.rs`
  - Selesai bila: snapshot tabel tanpa warna lolos; tes bahwa non-TTY tidak mencetak escape code.
  - Dep: W3-T9

- [ ] **W4-T3 Output SARIF 2.1.0**
  - Deskripsi: rules per advisory, results per temuan, level per tier, `security-severity`, lokasi lockfile (baris paket bila parser menyimpan offset; kalau tidak baris 1), `partialFingerprints` stabil.
  - File: `core/report/sarif.rs`
  - Selesai bila: snapshot lolos dan valid terhadap skema SARIF 2.1.0 (simpan salinan skema di `tests/schemas/`).
  - Dep: W4-T1

- [ ] **W4-T4 Output markdown**
  - Deskripsi: marker `<!-- patchsense-report -->`, ringkasan per tier, tabel top-N, `<details>` per temuan dengan breakdown skor dan link, pesan "Tidak ada kerentanan" bila kosong.
  - File: `core/report/markdown.rs`
  - Selesai bila: snapshot untuk laporan dengan temuan dan kosong.
  - Dep: W4-T1

- [ ] **W4-T5 Output GitLab Dependency Scanning**
  - Deskripsi: cek versi skema terbaru di repo `security-report-schemas` GitLab, implementasi laporan `gl-dependency-scanning-report.json`, simpan versi sebagai konstanta.
  - File: `core/report/gitlab.rs`, `tests/schemas/`
  - Selesai bila: snapshot valid terhadap skema GitLab versi yang dipilih.
  - Dep: W4-T1

- [ ] **W4-T6 Multi-format dan `--output` berpasangan**
  - Deskripsi: `--format` dan `--output` bisa diulang dan dipasangkan sesuai urutan; default `table` di TTY dan `json` di non-TTY; error bila jumlah tidak cocok (lebih dari satu format ke stdout).
  - File: `cli/cli.rs`, `cli/main.rs`
  - Selesai bila: integration test satu kali scan menghasilkan 3 file sekaligus dan request OSV hanya terjadi sekali.
  - Dep: W4-T2, W4-T3, W4-T4, W4-T5

- [ ] **W4-T7 `patchsense init` (config)**
  - Deskripsi: tulis `patchsense.toml` contoh (PRD §7) bila belum ada; `--force` untuk menimpa.
  - File: `cli/init.rs`
  - Selesai bila: tes di `tempfile`: file dibuat, tidak ditimpa tanpa `--force`, dan hasilnya bisa diparse `Config`.
  - Dep: W3-T7

## Minggu 5: Integrasi (komentar PR/MR, GitHub Action, GitLab CI, MCP, agent)

- [ ] **W5-T1 `patchsense comment` untuk GitHub**
  - Deskripsi: baca env GitHub, ambil nomor PR dari `GITHUB_EVENT_PATH`, upsert komentar via REST API berdasarkan marker, `--dry-run`. PR dari fork (403) → warning, exit 0.
  - File: `cli/comment/mod.rs`, `cli/comment/github.rs`
  - Selesai bila: tes dengan HTTP palsu: buat baru, edit yang ada, dan tidak duplikat.
  - Dep: W4-T4

- [ ] **W5-T2 `patchsense comment` untuk GitLab**
  - Deskripsi: Notes API MR dengan `GITLAB_TOKEN`, `CI_API_V4_URL`, `CI_PROJECT_ID`, `CI_MERGE_REQUEST_IID`; upsert berdasarkan marker.
  - File: `cli/comment/gitlab.rs`
  - Selesai bila: tes HTTP palsu untuk buat dan edit; token kosong → pesan jelas dan exit 2.
  - Dep: W5-T1

- [ ] **W5-T3 GitHub Action**
  - Deskripsi: `action.yml` composite sesuai PRD §13 (install biner sesuai OS/arch, scan sekali multi-format, upload SARIF, komentar, exit code akhir) dan workflow contoh `.github/workflows/self-test.yml` yang menjalankan action terhadap `examples/`.
  - File: `action.yml`, `.github/workflows/self-test.yml`, `examples/`
  - Selesai bila: self-test hijau di PR repo sendiri (sebelum ada rilis, boleh memakai biner hasil `cargo build` lewat input tersembunyi `binary-path`).
  - Dep: W4-T6, W5-T1

- [ ] **W5-T4 Template GitLab CI**
  - Deskripsi: `templates/gitlab/patchsense.gitlab-ci.yml` sesuai PRD §14 plus dokumentasi `include`.
  - File: `templates/gitlab/patchsense.gitlab-ci.yml`, `docs/gitlab.md`
  - Selesai bila: YAML valid (lolos linter YAML) dan diuji manual sekali di proyek GitLab uji (catat hasilnya di PR). Uji manual dilakukan Widya bila agent tidak punya akses GitLab.
  - Dep: W4-T5, W5-T2

- [ ] **W5-T5 Server MCP: kerangka dan `list_supported_lockfiles`**
  - Deskripsi: `patchsense mcp` dengan `rmcp` transport stdio, log hanya ke stderr, tool `list_supported_lockfiles`.
  - File: `cli/mcp.rs`, `cli/cli.rs`
  - Selesai bila: integration test menjalankan proses, mengirim `initialize` dan `tools/list`, dan menerima daftar tool.
  - Dep: W3-T9

- [ ] **W5-T6 Tool MCP `scan_project`, `get_finding`, `get_fix_plan`, `explain_score`**
  - Deskripsi: implementasi sesuai PRD §11, memakai `patchsense-core` dengan base URL yang bisa diarahkan ke fake untuk tes. `get_fix_plan` menghitung versi fix minimum yang menutup semua advisory per paket.
  - File: `cli/mcp.rs`, `core/scan.rs` (helper fix plan)
  - Selesai bila: tes `tools/call` untuk tiap tool dengan fixture; output `scan_project` dibatasi 50 temuan.
  - Dep: W5-T5

- [ ] **W5-T7 Prompt builder untuk agent**
  - Deskripsi: bangun prompt dari top-N temuan (PRD §12), bahasa `id`/`en`, batas panjang aman lintas OS.
  - File: `cli/agent/prompt.rs`
  - Selesai bila: snapshot prompt `id` dan `en`; tes pemotongan untuk input besar.
  - Dep: W3-T9

- [ ] **W5-T8 Adapter agent: codex, claude, cursor**
  - Deskripsi: trait `AgentAdapter` dan tiga adapter (PRD §12) dengan deteksi PATH (`agent` lalu `cursor-agent` untuk Cursor), timeout, read-only. Cek ulang flag di dokumentasi resmi saat mengerjakan.
  - File: `cli/agent/mod.rs`, `cli/agent/codex.rs`, `cli/agent/claude.rs`, `cli/agent/cursor.rs`, `tests/fixtures/agent/`
  - Selesai bila: snapshot argumen `build_command` dan tes `parse_output` dari fixture stdout untuk tiap adapter; tidak ada flag izin tulis.
  - Dep: W5-T7

- [ ] **W5-T9 `scan --explain`**
  - Deskripsi: hubungkan adapter ke scan: deteksi `auto`, jalankan, sisipkan `explanation` ke temuan, tampilkan di tabel/markdown dengan label "Penjelasan AI, bisa keliru". Gagal/timeout/tak ada agent → warning, exit code tidak berubah.
  - File: `cli/main.rs`, `cli/agent/mod.rs`, `core/report/markdown.rs`
  - Selesai bila: tes memakai skrip agent palsu di PATH sementara (skrip shell/bat yang mencetak fixture) untuk sukses, timeout, dan tidak ada agent.
  - Dep: W5-T8, W4-T6

- [ ] **W5-T10 `init --agent` dan `--print-mcp-config`**
  - Deskripsi: tulis blok instruksi dengan marker idempoten ke `AGENTS.md`, `CLAUDE.md`, `.cursor/rules/patchsense.mdc` (PRD §12.1); cetak potongan konfigurasi MCP (PRD §11).
  - File: `cli/init.rs`
  - Selesai bila: tes: jalankan dua kali → satu blok saja; konten di luar marker tetap; output `--print-mcp-config` di-snapshot.
  - Dep: W4-T7, W5-T5

## Minggu 6: Rilis (cargo-dist, npm, pip, Homebrew, README, v0.1.0)

- [ ] **W6-T1 Finalisasi nama dan owner**
  - Deskripsi: minta keputusan Widya soal nama paket npm/PyPI (PRD §15, §17). Jangan lanjut ke W6-T3/W6-T4 sebelum ada keputusan. Update semua placeholder `patchsense`, `patchsense`, `Widyasa`.
  - File: `Cargo.toml`, `pyproject.toml`, `action.yml`, docs
  - Selesai bila: nama tertulis di PRD/README dan tidak ada placeholder tersisa (`rg 'Widyasa'` kosong).
  - Dep: –  (boleh diminta sejak awal)

- [ ] **W6-T2 cargo-dist**
  - Deskripsi: `dist init` dengan target PRD §15, installer shell, powershell, npm, homebrew; workflow `release.yml` dihasilkan tool. Uji dengan `dist plan` dan `dist build` lokal.
  - File: `Cargo.toml` (`[workspace.metadata.dist]` atau `dist-workspace.toml`), `.github/workflows/release.yml`
  - Selesai bila: `dist plan` sukses; tag pra-rilis (mis. `v0.1.0-rc.1`) di repo menghasilkan artifact untuk semua target (dijalankan Widya bila butuh izin push tag).
  - Dep: W6-T1

- [ ] **W6-T3 Paket pip dengan maturin**
  - Deskripsi: `pyproject.toml` dengan `bindings = "bin"` yang menunjuk crate `patchsense`, workflow `pypi.yml` membangun wheel Linux/macOS/Windows dan publish via trusted publishing hanya pada tag.
  - File: `pyproject.toml`, `.github/workflows/pypi.yml`
  - Selesai bila: `maturin build --release` lokal menghasilkan wheel dan `pip install` wheel itu memberi perintah `patchsense` yang jalan.
  - Dep: W6-T1

- [ ] **W6-T4 Persiapan publish crates.io**
  - Deskripsi: metadata (`description`, `repository`, `keywords`, `categories`, `readme`), `cargo publish --dry-run` untuk `patchsense-core` lalu `patchsense`.
  - File: `crates/*/Cargo.toml`
  - Selesai bila: kedua dry-run sukses.
  - Dep: W6-T1

- [ ] **W6-T5 Demo PHP2Shell dan GIF**
  - Deskripsi: rapikan `examples/php2shell-demo/`, skrip `vhs` (`demo.tape`) yang menjalankan `patchsense scan examples/php2shell-demo`, hasilkan GIF.
  - File: `examples/`, `docs/demo.tape`, `docs/demo.gif`
  - Selesai bila: GIF menunjukkan temuan PHP2Shell bertingkat Kritis. Bila advisory PHP2Shell belum ada di OSV/KEV saat itu, pakai CVE KEV lain yang nyata dan catat di PR.
  - Dep: W5-T9

- [ ] **W6-T6 README dan dokumentasi**
  - Deskripsi: README (instalasi 4 kanal, quick start, cara kerja skor dengan tabel bobot, contoh CI GitHub dan GitLab, MCP dan `--explain`, exit code, konfigurasi, lisensi ganda), `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`.
  - File: `README.md`, `docs/*.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`
  - Selesai bila: semua contoh perintah di README diuji jalan (atau ditandai bergantung rilis), link tidak rusak.
  - Dep: W6-T2, W6-T3, W6-T5

- [ ] **W6-T7 Rilis v0.1.0**
  - Deskripsi: bump versi, isi `CHANGELOG.md`, siapkan tag `v0.1.0`. Tag, publish ke npm/PyPI/crates.io, dan rilis Homebrew dijalankan oleh Widya (butuh secret dan keputusan publik); agent menyiapkan checklist dan perintahnya.
  - File: `Cargo.toml`, `CHANGELOG.md`, `docs/release-checklist.md`
  - Selesai bila: checklist rilis lengkap; setelah Widya menjalankan rilis, `npx`, `pip install`, `brew install`, dan `cargo install` dicek memberi `patchsense --version` = 0.1.0.
  - Dep: W6-T4, W6-T6

---

## Ringkasan

| Minggu | Fokus | Jumlah tugas |
|---|---|---|
| 1 | Fondasi | 12 |
| 2 | Parser lain | 9 |
| 3 | Data dan skor | 9 |
| 4 | Output | 7 |
| 5 | Integrasi | 10 |
| 6 | Rilis | 7 |
| **Total** | | **54** |

Jalur kritis: W1-T1 → T3 → T4 → T6 → T9 → T10 → T11 → T12 → W2-T8 → W3-T6 → T8 → T9 → W4-T1 → T6 → W5-T3 → W6-T2 → T6 → T7. Tugas parser di minggu 2 (W2-T1 s/d W2-T7) saling independen dan bisa dikerjakan paralel oleh beberapa agent.
