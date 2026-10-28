# PatchSense: Product Requirements Document (PRD) v1

> Sumber kebenaran: Page "PatchSense: Rancangan Produk" v1 (canvas `1ad7ef7c-990b-433b-b8cb-7e50eebb6ab7`). Kalau dokumen ini bertentangan dengan Page itu, Page yang menang. Tanyakan ke Widya sebelum mengubah keputusan yang sudah dikunci (bagian 1.2).

Pemilik produk: Widya Yasa. Status: siap dibangun. Target MVP: 6 minggu (v0.1.0).

---

## 1. Ringkasan

PatchSense adalah CLI open source berbasis Rust untuk triage CVE. PatchSense membaca lockfile di repo (bahasa backend apa pun), mencocokkan dependency dengan OSV, memperkaya hasilnya dengan EPSS, CISA KEV, dan CVSS, lalu memberi **skor prioritas 0–100** supaya developer tahu kerentanan mana yang benar-benar perlu diurus hari ini.

Hasilnya tampil sebagai tabel terminal, JSON, SARIF, laporan GitLab Dependency Scanning, dan komentar di PR/MR. Penjelasan AI bersifat opsional dan **menumpang AI coding agent milik user** (Cursor, Claude Code, Codex) lewat server MCP atau CLI agent yang sudah terpasang. PatchSense sendiri tidak pernah meminta atau menyimpan API key model.

Output language is English only. Tier labels are Critical, Review, and Defer. There is no `--lang` flag. An existing `explain.lang` key is ignored and produces a warning.

### 1.1 Satu kalimat
"`patchsense scan .` memberi tahu dalam hitungan detik CVE mana yang Kritis, mana yang Perlu dicek, dan mana yang Bisa ditunda, lengkap dengan alasan dan versi perbaikannya."

### 1.2 Keputusan yang sudah dikunci

| Keputusan | Isi |
|---|---|
| Bentuk produk | CLI plus GitHub Action dan template GitLab CI. **Tanpa web app.** |
| Bahasa | Rust (edisi 2021, async dengan tokio) |
| Cakupan backend | Semua backend lewat lockfile, tidak terikat satu bahasa |
| Ekosistem MVP | npm (`package-lock.json`), pnpm (`pnpm-lock.yaml`), yarn (`yarn.lock`), PyPI (`poetry.lock`, `requirements.txt`), Composer (`composer.lock`), Go (`go.sum`), Maven (`pom.xml`), Cargo (`Cargo.lock`) |
| Distribusi | cargo-dist (biner Linux/macOS/Windows, installer npm, Homebrew), maturin untuk pip, `cargo install` |
| AI | Opsional, tanpa API key milik PatchSense: `patchsense mcp` (jalur utama), `patchsense scan --explain`, `patchsense init --agent` |
| Lisensi | `MIT OR Apache-2.0` (file `LICENSE-MIT` dan `LICENSE-APACHE`) |
| Nama paket | `patchsense` di npm, PyPI, crates.io, Homebrew, dan nama biner. Tanpa scope npm, supaya `npx patchsense` jalan |
| Owner | Akun GitHub `Widyasa` (`github.com/Widyasa/patchsense`). Tap Homebrew `Widyasa/homebrew-tap` |
| Target MVP | 6 minggu |

---

## 2. Masalah

Scanner seperti Dependabot atau `npm audit` sering mengeluarkan puluhan alert sekaligus tanpa urutan yang jelas. Developer jadi kebal alert dan mengabaikan semuanya, termasuk yang kritis (contoh terbaru: advisory PHP2Shell, Oktober 2026). Masalah utamanya:

1. **Tidak ada prioritas yang masuk akal.** Severity CVSS saja tidak menunjukkan apakah sebuah celah benar-benar sedang dieksploitasi.
2. **Data tersebar.** OSV, EPSS, dan KEV harus dicek manual satu per satu.
3. **Upload ke chatbot umum tidak akurat.** LLM sering salah mencocokkan versi paket dan datanya basi. PatchSense memakai data deterministik yang selalu terbaru, berjalan otomatis di CI, dan kode tidak perlu diunggah ke mana pun.

## 3. Target pengguna

| Persona | Kebutuhan |
|---|---|
| Developer solo dan maintainer open source | Jawaban cepat: apa yang harus diperbaiki hari ini? |
| Tim kecil dan startup | Tidak punya tim security, butuh prioritas otomatis di PR/MR |
| Komunitas developer Indonesia | Ringkasan dampak dan cara perbaikan dalam Bahasa Indonesia (lewat AI agent milik mereka) |

---

## 4. Tujuan dan non-tujuan

### 4.1 Tujuan (MVP v0.1.0)
- G1. Satu perintah (`patchsense scan .`) mendeteksi lockfile dari 8 ekosistem dan menghasilkan daftar temuan berprioritas.
- G2. Skor prioritas transparan: tiap komponen skor ditampilkan dan bobotnya bisa diatur lewat `patchsense.toml`.
- G3. Siap CI: exit code yang jelas, output JSON/SARIF/GitLab, komentar PR/MR yang selalu diperbarui (bukan spam).
- G4. Scan ulang cepat berkat cache SQLite, dan bisa jalan offline dari cache.
- G5. Integrasi AI tanpa API key: server MCP, `--explain` via CLI agent, dan `init --agent`.
- G6. Mudah dipasang: `npx`, `pip`, Homebrew, `cargo install`, dan biner prebuilt.

### 4.2 Non-tujuan (ditunda, jangan dibangun di MVP)
- Reachability analysis (apakah fungsi rentan benar-benar dipanggil).
- Dashboard web. Sengaja tidak dibuat.
- PR perbaikan otomatis (auto-fix).
- Notifikasi (Telegram, Discord, Slack, email).
- Ekosistem lain: Gradle, RubyGems, NuGet, Pub.
- Library Node.js lewat napi-rs (`import { scan } from "patchsense"`).
- Memanggil API model AI langsung atau menyimpan API key apa pun.
- Scan container image atau SBOM sebagai input (bisa jadi ide pasca-MVP).

---

## 5. Fitur MVP dan acceptance criteria

Setiap kriteria (AC) harus bisa diuji otomatis. Tes tidak boleh memanggil jaringan (lihat [`AGENTS.md`](../AGENTS.md)).

### F1. Deteksi dan parsing lockfile
- AC1.1 `patchsense scan <path>` menelusuri direktori secara rekursif dan menemukan semua file yang namanya cocok dengan tabel 5.1. Direktori `node_modules`, `vendor`, `target`, `.git`, `.venv`, dan `venv` dilewati secara default.
- AC1.2 Setiap parser menghasilkan `Vec<Package>` dengan `ecosystem`, `name`, `version`, `direct` (`Some(true)`, `Some(false)`, atau `None` bila tidak diketahui), dan `source_file`.
- AC1.3 Setiap parser punya minimal 2 fixture lockfile nyata (dari proyek open source publik, sebutkan sumbernya) dan satu snapshot test `insta` yang lolos.
- AC1.4 Lockfile yang rusak menghasilkan error yang menyebut nama file dan baris/posisi bila tersedia, dan tidak membuat panic. Dengan `--keep-going` (default), file lain tetap di-scan dan peringatannya muncul di output.
- AC1.5 Paket duplikat (nama, versi, dan ekosistem sama) di-dedupe sebelum query OSV.

#### 5.1 Tabel ekosistem

| Ekosistem OSV | File | Catatan parsing | Info `direct` |
|---|---|---|---|
| `npm` | `package-lock.json` | lockfileVersion 2 dan 3 (key `packages`); v1 (key `dependencies`) best effort | Dari `packages[""].dependencies`/`devDependencies` |
| `npm` | `pnpm-lock.yaml` | lockfile v6 dan v9 (format key paket berbeda) | Dari `importers` |
| `npm` | `yarn.lock` | Yarn classic (v1, format khusus) dan Berry (YAML) | Butuh `package.json` di sebelahnya; bila tidak ada, `None` |
| `PyPI` | `poetry.lock` | TOML `[[package]]` | Dari `pyproject.toml` bila ada |
| `PyPI` | `requirements.txt` | Hanya baris `name==version` yang dipin; baris lain dilewati dengan peringatan; abaikan komentar, `-r`, `-e`, marker | Semua dianggap `Some(true)` |
| `Packagist` | `composer.lock` | `packages` dan `packages-dev` | Dari `composer.json` bila ada |
| `Go` | `go.sum` | Abaikan baris `/go.mod`; versi `v` dipertahankan | Dari `go.mod` (`// indirect`) bila ada |
| `Maven` | `pom.xml` | `dependencies/dependency` dengan versi literal; properti `${...}` di-resolve dari `<properties>` pom yang sama; selain itu dilewati dengan peringatan | Semua di pom dianggap `Some(true)` (tanpa resolusi transitif) |
| `crates.io` | `Cargo.lock` | `[[package]]` yang punya `source` registry; path/git dependency dilewati | Dari `Cargo.toml` workspace bila ada |

Nama ekosistem harus persis sesuai daftar ekosistem OSV (`npm`, `PyPI`, `Packagist`, `Go`, `Maven`, `crates.io`). Untuk Maven, nama paket berformat `groupId:artifactId`. Untuk PyPI, nama dinormalisasi sesuai PEP 503 (huruf kecil, `_`/`.` jadi `-`).

### F2. Klien OSV
- AC2.1 Query dikirim lewat `POST https://api.osv.dev/v1/querybatch` dengan body `{"queries":[{"package":{"ecosystem":..., "name":...},"version":...}]}` (diverifikasi 25 Okt 2026). Urutan hasil sama dengan urutan query.
- AC2.2 Query dipecah per batch maksimal 1000 item (konstanta `OSV_BATCH_SIZE`, bisa disetel).
- AC2.3 Pagination: hasil yang punya `next_page_token` di-query ulang hanya untuk item tersebut dengan `page_token`, sampai habis.
- AC2.4 `querybatch` hanya mengembalikan `id` dan `modified`. Detail diambil lewat `GET https://api.osv.dev/v1/vulns/{id}` secara paralel (default konkurensi 8) dan disimpan di cache dengan kunci `id` + `modified`.
- AC2.5 Dari detail, yang diambil adalah `id`, `aliases` (untuk menemukan CVE), `summary`, `severity[]` (`type` `CVSS_V3`/`CVSS_V4` dengan `score` berupa vector string), `database_specific.severity` (fallback), `affected[].ranges[].events` (`introduced`/`fixed`), dan `references`.
- AC2.6 Retry dengan backoff eksponensial untuk HTTP 429 dan 5xx (maksimal 3 kali); error jaringan lain menjadi exit code 2, kecuali `--offline`.

### F3. Enrichment (EPSS, KEV, CVSS)
- AC3.1 EPSS: `GET https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B,...` (diverifikasi 25 Okt 2026). Parameter `cve` maksimal 2000 karakter, jadi dipecah per 100 CVE (juga sama dengan `limit` default 100). Field `epss` dan `percentile` berupa string desimal dan harus di-parse ke `f64`.
- AC3.2 KEV: unduh `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (diverifikasi 25 Okt 2026) maksimal sekali per 24 jam, simpan di cache. Field yang dipakai: `cveID`, `dateAdded`, `dueDate`, `knownRansomwareCampaignUse`, `vulnerabilityName`, `requiredAction`.
- AC3.3 CVSS: base score dihitung dari vector string OSV. CVSS v3.x wajib didukung; CVSS v4 didukung bila crate `cvss` (RustSec) atau implementasi sendiri sanggup. Bila tidak ada vector, pakai fallback `database_specific.severity`: `CRITICAL`=9.5, `HIGH`=7.5, `MODERATE`/`MEDIUM`=5.0, `LOW`=2.5. Bila tidak ada sama sekali, CVSS = `null` dan komponennya bernilai 0.
- AC3.4 Satu advisory bisa punya banyak alias CVE: KEV = true bila salah satu alias ada di KEV; EPSS = nilai maksimum dari semua alias; advisory tanpa CVE mendapat EPSS 0 dan KEV false.

### F4. Mesin skor
- AC4.1 Formula persis seperti bagian 9, dengan unit test untuk setiap komponen dan kasus batas (69.5, 70, 39.9, 40).
- AC4.2 Bobot dibaca dari `patchsense.toml`; bila total bobot bukan 100, skor dinormalisasi ke 0–100 dan muncul peringatan.
- AC4.3 Setiap temuan menyimpan `score_breakdown` per komponen supaya skor bisa dijelaskan.
- AC4.4 Hasil diurutkan menurun berdasarkan skor, lalu `kev` true dulu, lalu nama paket (deterministik).

### F5. Cache SQLite
- AC5.1 Lokasi default: direktori cache OS (`$XDG_CACHE_HOME/patchsense/cache.db` di Linux, padanannya di macOS/Windows), bisa diganti dengan `PATCHSENSE_CACHE_DIR` atau `--cache-dir`.
- AC5.2 TTL default: detail OSV 24 jam (dan invalid bila `modified` berubah), EPSS 24 jam, KEV 24 jam. Bisa diatur di `[cache]`.
- AC5.3 `--offline` hanya memakai cache. Item yang tidak ada di cache ditandai `"stale": true` atau dilewati dengan peringatan, dan tidak ada request jaringan sama sekali (diuji dengan klien HTTP palsu yang gagal bila dipanggil).
- AC5.4 `--no-cache` mengabaikan dan tidak menulis cache. `patchsense cache clear` menghapus database.
- AC5.5 Skema cache punya `schema_version`; versi berbeda berarti cache dibuat ulang.

### F6. Output
- AC6.1 `table` (default di TTY): kolom Skor, Tingkat, Paket, Versi, Advisory/CVE, KEV, EPSS, CVSS, Fix. Warna hanya di TTY dan bisa dimatikan lewat `--no-color` atau `NO_COLOR`. Progress bar `indicatif` hanya di stderr dan hanya di TTY.
- AC6.2 `json`: sesuai skema bagian 8, dengan `schema_version`. Snapshot test dengan `insta` (dengan redaksi timestamp).
- AC6.3 `sarif`: SARIF 2.1.0 valid (divalidasi terhadap skema resmi di tes), satu `rule` per advisory, `result.level` dipetakan: Kritis→`error`, Perlu dicek→`warning`, Bisa ditunda→`note`. Lokasi menunjuk ke lockfile (baris paket bila diketahui, kalau tidak baris 1). Properti `security-severity` diisi `skor/10` supaya GitHub code scanning bisa mengurutkan.
- AC6.4 `markdown`: dipakai untuk komentar PR/MR. Berisi ringkasan jumlah per tingkat, tabel top-N (default 20), dan detail yang bisa dilipat (`<details>`). Diawali marker tersembunyi `<!-- patchsense-report -->`.
- AC6.5 `gitlab`: laporan Dependency Scanning GitLab (`gl-dependency-scanning-report.json`). Versi skema yang dipakai harus dicek di repo `security-report-schemas` GitLab saat implementasi dan ditulis di kode sebagai konstanta.
- AC6.6 `--output <file>` menulis ke file; tanpa itu ke stdout. `--format` bisa diulang dengan `--output` berpasangan, misalnya `--format json --output report.json --format sarif --output report.sarif`, supaya cukup satu kali scan untuk semua format di CI.

### F7. Komentar PR/MR
- AC7.1 `patchsense comment --report report.json` mendeteksi provider dari environment (`GITHUB_ACTIONS` atau `GITLAB_CI`) atau dari `--provider github|gitlab`.
- AC7.2 Upsert: cari komentar yang mengandung marker `<!-- patchsense-report -->`. Bila ada, edit; bila tidak, buat baru. Tidak boleh ada komentar ganda.
- AC7.3 GitHub memakai REST API issues comments dengan `GITHUB_TOKEN`. GitLab memakai Notes API MR dengan `GITLAB_TOKEN` (project access token; `CI_JOB_TOKEN` umumnya tidak cukup untuk menulis note).
- AC7.4 Bila tidak ada temuan, komentar lama diperbarui menjadi "Tidak ada kerentanan" (bukan dihapus).
- AC7.5 Diuji dengan klien HTTP palsu yang merekam request.

### F8. AI lewat agent milik user (opsional)
- AC8.1 `patchsense mcp` menjalankan server MCP lewat stdio dengan tool di bagian 11 dan lolos uji `initialize` dan `tools/list` dalam integration test (tanpa jaringan, memakai fixture).
- AC8.2 `patchsense scan --explain` mendeteksi CLI agent di `PATH` sesuai bagian 12. Bila tidak ada agent, laporan tetap keluar, ada satu baris peringatan di stderr, dan exit code tidak berubah.
- AC8.3 Kegagalan atau timeout agent tidak pernah mengubah exit code scan.
- AC8.4 Penjelasan AI selalu ditampilkan berdampingan dengan link sumber resmi (OSV/NVD/KEV), dan diberi label "Penjelasan AI, bisa keliru".
- AC8.5 `patchsense init --agent` menulis blok instruksi di antara marker `<!-- patchsense:start -->` dan `<!-- patchsense:end -->`. Bila dijalankan ulang, blok diganti, bukan diduplikasi (idempoten). Konten file di luar marker tidak disentuh.
- AC8.6 PatchSense tidak membaca, meminta, atau menyimpan API key model apa pun.

### F9. Konfigurasi
- AC9.1 `patchsense.toml` dicari di direktori scan lalu naik ke parent sampai root git; bisa diganti dengan `--config`.
- AC9.2 Field yang tidak dikenal menyebabkan error yang jelas (`deny_unknown_fields`).
- AC9.3 Urutan prioritas: flag CLI > env var > `patchsense.toml` > default.
- AC9.4 `ignore` per advisory wajib punya `reason`; `expires` opsional. Ignore yang sudah kedaluwarsa tidak berlaku lagi dan memunculkan peringatan.

### F10. Integrasi CI dan distribusi
- AC10.1 `action.yml` di root repo bisa dipakai sebagai `uses: Widyasa/patchsense@v0`, mengunggah SARIF, dan berkomentar di PR (bagian 13).
- AC10.2 `templates/gitlab/patchsense.gitlab-ci.yml` bisa di-`include` dan menghasilkan artifact Dependency Scanning dan note di MR (bagian 14).
- AC10.3 Rilis dengan tag `v*` menghasilkan biner untuk Linux x86_64/aarch64, macOS x86_64/aarch64, dan Windows x86_64, plus installer npm, formula Homebrew, dan wheel pip (bagian 15).

---

## 6. Spesifikasi CLI

Nama biner: `patchsense`. Dibangun dengan `clap` (derive).

```
patchsense <COMMAND>

Commands:
  scan      Scan lockfile dan tampilkan temuan berprioritas
  comment   Kirim/perbarui komentar laporan di PR (GitHub) atau MR (GitLab)
  mcp       Jalankan server MCP (stdio) untuk Cursor, Claude Code, Codex
  init      Buat patchsense.toml dan/atau instruksi untuk AI agent
  cache     Kelola cache lokal (clear, info)
  help      Bantuan
```

### 6.1 `patchsense scan [PATH]`

`PATH` default `.`. Bisa berupa direktori atau satu lockfile.

| Flag | Default | Keterangan |
|---|---|---|
| `-f, --format <table\|json\|sarif\|markdown\|gitlab>` | `table` di TTY, `json` di non-TTY | Bisa diulang |
| `-o, --output <FILE>` | stdout | Berpasangan dengan `--format` sesuai urutan |
| `--fail-on <critical\|review\|any\|never\|SKOR>` | `critical` | Ambang exit code 1. `critical` berarti skor ≥ 70, `review` ≥ 40, `any` berarti ada temuan apa pun, `never` selalu 0, atau angka 0–100 |
| `--config <FILE>` | auto | Path `patchsense.toml` |
| `--ecosystem <LIST>` | semua | Filter, misal `npm,pypi` |
| `--exclude <GLOB>` | – | Bisa diulang, menambah daftar dilewati |
| `--no-dev` | false | Abaikan dev dependency bila parser tahu |
| `--min-score <N>` | 0 | Sembunyikan temuan di bawah skor N dari output (tidak memengaruhi `--fail-on`) |
| `--offline` | false | Hanya cache, tanpa jaringan |
| `--strict-cache` | false | Bersama `--offline`, exit 2 bila baris EPSS atau katalog KEV hilang atau melewati TTL. Tanpa flag, data kedaluwarsa tetap dipakai dan ada peringatan. `strict_cache = true` di config memakai pesan yang sama |
| `--no-cache` | false | Abaikan cache |
| `--cache-dir <DIR>` | OS cache | |
| `--explain` | false | Minta penjelasan dari CLI agent terpasang |
| `--agent <auto\|codex\|claude\|cursor>` | `auto` | Pilih agent untuk `--explain` |
| `--explain-top <N>` | 10 | Jumlah temuan teratas yang dikirim ke agent |
| `--lang <id\|en>` | `id` | Bahasa penjelasan AI |
| `--no-color` | false | Juga menghormati `NO_COLOR` |
| `-q, --quiet` / `-v, --verbose` | – | Level log (`tracing` opsional; boleh `eprintln!` sederhana dulu) |

### 6.2 `patchsense comment`

| Flag | Default | Keterangan |
|---|---|---|
| `--report <FILE>` | wajib | File JSON hasil `scan` |
| `--provider <auto\|github\|gitlab>` | `auto` | |
| `--top <N>` | 20 | Baris di tabel komentar |
| `--dry-run` | false | Cetak markdown tanpa memanggil API |

Env yang dibaca: GitHub `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, `GITHUB_EVENT_PATH` (nomor PR), `GITHUB_API_URL`. GitLab `GITLAB_TOKEN`, `CI_API_V4_URL`, `CI_PROJECT_ID`, `CI_MERGE_REQUEST_IID`.

### 6.3 `patchsense mcp`
Tanpa flag wajib. `--config` opsional. Transport stdio. Log hanya ke stderr (stdout khusus protokol MCP).

### 6.4 `patchsense init`

| Flag | Keterangan |
|---|---|
| (tanpa flag) | Tulis `patchsense.toml` contoh bila belum ada |
| `--agent [all\|codex\|claude\|cursor]` | Tulis instruksi agent: `codex` → `AGENTS.md`, `claude` → `CLAUDE.md`, `cursor` → `.cursor/rules/patchsense.mdc`. Tanpa nilai berarti `all` |
| `--print-mcp-config` | Cetak potongan konfigurasi MCP untuk Cursor, Claude Code, dan Codex (tidak menulis file konfigurasi global user) |
| `--force` | Timpa `patchsense.toml` yang sudah ada |

### 6.5 `patchsense cache <clear|info>`
`info` menampilkan path, ukuran, jumlah entri, dan waktu update KEV/EPSS terakhir.

### 6.6 Exit code

| Kode | Arti |
|---|---|
| `0` | Scan berhasil dan tidak ada temuan di atas ambang `--fail-on` |
| `1` | Scan berhasil dan ada minimal satu temuan dengan skor ≥ ambang `--fail-on` |
| `2` | Error: konfigurasi tidak valid, tidak ada lockfile, semua lockfile gagal di-parse, jaringan gagal (tanpa `--offline`), atau gagal menulis output |

Catatan: kegagalan `--explain` tidak pernah mengubah exit code. Parse gagal di sebagian file (dengan file lain berhasil) tetap memberi 0/1 dengan peringatan. `comment` memberi 0 bila sukses dan 2 bila gagal.

### 6.7 Environment variables
`PATCHSENSE_CONFIG`, `PATCHSENSE_CACHE_DIR`, `PATCHSENSE_FAIL_ON`, `PATCHSENSE_AGENT`, `PATCHSENSE_OSV_URL`, `PATCHSENSE_EPSS_URL`, `PATCHSENSE_KEV_URL` (tiga terakhir untuk mirror dan tes), `NO_COLOR`.

---

## 7. Konfigurasi `patchsense.toml`

```toml
# patchsense.toml
schema_version = 1

[scan]
ecosystems = ["npm", "pypi", "packagist", "go", "maven", "cargo"]  # default: semua
exclude = ["examples/**", "fixtures/**"]
include_dev = true
fail_on = "critical"          # critical | review | any | never | angka 0-100

[score.weights]               # total ideal = 100
kev = 35
epss = 25
cvss = 20
direct = 10
fix_available = 10

[score.epss]
mode = "probability"          # probability | percentile
saturation = 0.10             # mode probability: EPSS >= 0.10 dapat bobot penuh

[score.thresholds]
critical = 70                 # >= 70  -> Kritis
review = 40                   # 40-69  -> Perlu dicek, < 40 -> Bisa ditunda

[score.unknown_direct]
weight_fraction = 1.0         # direct tidak diketahui: dianggap direct (konservatif)

[cache]
ttl_hours_osv = 24
ttl_hours_epss = 24
ttl_hours_kev = 24
strict_cache = false          # offline: expired EPSS/KEV is an error when true

[output]
top = 20                      # baris di markdown/komentar

[explain]
agent = "auto"                # auto | codex | claude | cursor
top = 10
lang = "id"
timeout_secs = 120

[[ignore]]
id = "GHSA-xxxx-xxxx-xxxx"    # ID OSV atau CVE
reason = "Hanya dipakai di script build, tidak terekspos"
expires = "2027-01-31"        # opsional
```

Nama ekosistem di config tidak peka huruf besar-kecil dan dipetakan ke nama OSV: `npm`→`npm` (mencakup npm, pnpm, yarn), `pypi`→`PyPI`, `packagist`/`composer`→`Packagist`, `go`→`Go`, `maven`→`Maven`, `cargo`/`crates.io`→`crates.io`.

---

## 8. Skema output JSON (`schema_version` 1)

```json
{
  "schema_version": 1,
  "tool": { "name": "patchsense", "version": "0.1.0" },
  "generated_at": "2026-10-25T08:00:00Z",
  "target": ".",
  "lockfiles": [
    { "path": "package-lock.json", "ecosystem": "npm", "packages": 412, "status": "ok" },
    { "path": "api/requirements.txt", "ecosystem": "PyPI", "packages": 18, "status": "ok", "warnings": ["baris 12 tidak dipin, dilewati"] }
  ],
  "data_sources": {
    "osv": { "fetched_at": "2026-10-25T08:00:00Z", "from_cache": false },
    "epss": { "date": "2026-10-24", "from_cache": true },
    "kev": { "catalog_version": "2026.10.23", "from_cache": true }
  },
  "config": {
    "weights": { "kev": 35, "epss": 25, "cvss": 20, "direct": 10, "fix_available": 10 },
    "thresholds": { "critical": 70, "review": 40 },
    "fail_on": "critical"
  },
  "summary": {
    "packages_scanned": 430,
    "findings": 3,
    "by_tier": { "critical": 1, "review": 1, "defer": 1 },
    "max_score": 100,
    "failed": true
  },
  "findings": [
    {
      "id": "GHSA-35jh-r3h4-6jhm",
      "aliases": ["CVE-2021-23337"],
      "cves": ["CVE-2021-23337"],
      "summary": "Command Injection in lodash",
      "package": { "ecosystem": "npm", "name": "lodash", "version": "4.17.15", "direct": true, "dev": false },
      "source_file": "package-lock.json",
      "fixed_versions": ["4.17.21"],
      "cvss": { "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "base_score": 7.2, "source": "osv" },
      "epss": { "score": 0.0123, "percentile": 0.78, "date": "2026-10-24" },
      "kev": null,
      "score": 37,
      "tier": "defer",
      "tier_label": "Bisa ditunda",
      "score_breakdown": { "kev": 0.0, "epss": 3.08, "cvss": 14.4, "direct": 10.0, "fix_available": 10.0, "total_weight": 100 },
      "references": [
        "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"
      ],
      "ignored": false,
      "explanation": null
    }
  ],
  "ignored": [
    { "id": "GHSA-xxxx-xxxx-xxxx", "package": "minimist@1.2.5", "reason": "Hanya di script build", "expires": "2027-01-31" }
  ],
  "explain": { "agent": null, "status": "not_requested" },
  "warnings": []
}
```

Catatan skema:
- Nilai EPSS dan skor pada contoh hanyalah ilustrasi. Snapshot tes memakai fixture tetap.
- `kev` berisi `null` atau `{ "date_added": "...", "due_date": "...", "ransomware": "Known|Unknown", "name": "..." }`.
- `tier` memakai identifier Inggris (`critical`, `review`, `defer`); label Indonesia ada di `tier_label`.
- `explain.status`: `not_requested`, `ok`, `no_agent_found`, `failed`, atau `timeout`. Bila `ok`, setiap temuan yang dijelaskan berisi `explanation: { "agent": "codex", "text": "...", "disclaimer": "Penjelasan AI, bisa keliru" }`.
- A Go finding may include optional `import_note` with the value `imported package not seen`. The field is omitted when the advisory has no import paths or when one of those paths was imported. The score and tier are unchanged. See `docs/go-import-reachability.md`.
- Perubahan yang tidak kompatibel wajib menaikkan `schema_version`. Sediakan juga JSON Schema di `schemas/report.v1.json`.

---

## 9. Formula skor prioritas

Untuk setiap temuan (pasangan paket@versi × advisory OSV):

```
kev_c    = W_kev    × (1 jika salah satu alias CVE ada di KEV, selain itu 0)
epss_c   = W_epss   × e
           e = min(1, epss_max / saturation)     (mode "probability", default saturation 0.10)
           e = percentile_max                    (mode "percentile")
           e = 0 bila tidak ada CVE atau data EPSS
cvss_c   = W_cvss   × (cvss_base / 10)           (0 bila CVSS tidak diketahui; fallback severity lihat F3)
direct_c = W_direct × d
           d = 1 jika direct, 0 jika transitif, unknown_direct.weight_fraction (default 1.0) jika tidak diketahui
fix_c    = W_fix    × (1 jika ada minimal satu event "fixed" di range yang memuat versi terpasang, selain itu 0)

raw   = kev_c + epss_c + cvss_c + direct_c + fix_c
total = W_kev + W_epss + W_cvss + W_direct + W_fix
score = round(clamp(raw / total × 100, 0, 100))        (pembulatan half-away-from-zero)

tier  = critical ("Kritis")       jika score >= thresholds.critical (70)
        review   ("Perlu dicek")  jika score >= thresholds.review   (40)
        defer    ("Bisa ditunda") selain itu
```

Default bobot: KEV 35, EPSS 25, CVSS 20, direct 10, fix 10 (total 100, jadi `raw` = `score` sebelum dibulatkan).

Contoh perhitungan (wajib jadi unit test):

| Kasus | KEV | EPSS | CVSS | Direct | Fix | Skor | Tingkat |
|---|---|---|---|---|---|---|---|
| A: dieksploitasi aktif | ya (35) | 0.94 → 25 | 9.8 → 19.6 | ya (10) | ya (10) | 100 | Kritis |
| B: parah tapi jarang dieksploitasi | tidak | 0.0123 → 3.08 | 7.2 → 14.4 | ya (10) | ya (10) | 37 | Bisa ditunda |
| C: KEV transitif tanpa fix | ya (35) | 0.05 → 12.5 | 8.1 → 16.2 | tidak | tidak | 64 | Perlu dicek |
| D: tanpa CVE | tidak | – → 0 | 5.0 → 10 | ya (10) | ya (10) | 30 | Bisa ditunda |
| E: batas | ya (35) | 0.02 → 5 | 10 → 20 | ya (10) | tidak | 70 | Kritis |

Temuan yang ditampilkan di contoh JSON bagian 8 adalah kasus B. Snapshot JSON di tes dibuat dari fixture dan formula ini, bukan disalin dari contoh dokumen.

Rasional pilihan mode EPSS `probability` dengan saturation 0.10: probabilitas EPSS kebanyakan sangat kecil, sedangkan percentile cenderung mendongkrak CVE yang sebenarnya jarang dieksploitasi. Ini asumsi desain yang bisa diubah user lewat config.

---

## 10. Arsitektur dan struktur crate

### 10.1 Alur data

```
Repo user
  └─► discovery (cari lockfile)
        └─► parser per ekosistem ──► Vec<Package>
              └─► osv client (querybatch + vulns/{id}) ──► Vec<Advisory>
                    └─► enricher (EPSS, KEV, CVSS) ◄──► cache SQLite
                          └─► score engine ──► Report
                                ├─► output (table | json | sarif | markdown | gitlab)
                                ├─► comment (GitHub / GitLab API)
                                └─► agent bridge (opsional: MCP server / CLI agent)
```

### 10.2 Workspace Cargo

```
patchsense/
├── Cargo.toml                    # [workspace], license = "MIT OR Apache-2.0", edition 2021
├── LICENSE-MIT
├── LICENSE-APACHE
├── README.md
├── AGENTS.md                     # dari paket handoff ini
├── action.yml                    # GitHub Action (composite)
├── templates/gitlab/patchsense.gitlab-ci.yml
├── schemas/report.v1.json
├── pyproject.toml                # maturin, bindings = "bin"
├── crates/
│   ├── patchsense-core/           # library: semua logika, tanpa I/O terminal
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── error.rs          # CoreError (thiserror)
│   │       ├── model.rs          # Package, Ecosystem, Advisory, Finding, Report, Tier
│   │       ├── config.rs         # Config (serde, deny_unknown_fields), defaults, merge
│   │       ├── discovery.rs      # cari lockfile, exclude glob
│   │       ├── lockfile/
│   │       │   ├── mod.rs        # trait LockfileParser, registry parser
│   │       │   ├── npm.rs        # package-lock.json
│   │       │   ├── pnpm.rs
│   │       │   ├── yarn.rs
│   │       │   ├── poetry.rs
│   │       │   ├── requirements.rs
│   │       │   ├── composer.rs
│   │       │   ├── gosum.rs
│   │       │   ├── maven.rs
│   │       │   └── cargo.rs
│   │       ├── http.rs           # trait HttpClient + impl reqwest (rustls) + FakeHttp untuk tes
│   │       ├── osv.rs            # querybatch, pagination, vulns/{id}, parsing ranges
│   │       ├── enrich/
│   │       │   ├── mod.rs
│   │       │   ├── epss.rs
│   │       │   ├── kev.rs
│   │       │   └── cvss.rs
│   │       ├── cache.rs          # rusqlite (bundled), TTL, schema_version
│   │       ├── score.rs          # formula bagian 9
│   │       ├── scan.rs           # orkestrasi: discovery → parse → osv → enrich → score
│   │       └── report/
│   │           ├── mod.rs
│   │           ├── json.rs
│   │           ├── sarif.rs
│   │           ├── markdown.rs
│   │           └── gitlab.rs
│   └── patchsense/                # biner "patchsense"
│       └── src/
│           ├── main.rs           # tokio main, anyhow, exit code
│           ├── cli.rs            # clap derive
│           ├── table.rs          # comfy-table + warna
│           ├── progress.rs       # indicatif
│           ├── comment/{mod.rs,github.rs,gitlab.rs}
│           ├── mcp.rs            # server MCP (rmcp)
│           ├── agent/{mod.rs,codex.rs,claude.rs,cursor.rs,prompt.rs}
│           └── init.rs           # patchsense.toml + instruksi agent
├── tests/fixtures/<ecosystem>/<nama-proyek>/<lockfile>   # fixture nyata + SOURCE.md
└── .github/workflows/{ci.yml,release.yml,pypi.yml}
```

Prinsip:
- `patchsense-core` tidak tahu soal terminal, clap, atau MCP. Semua I/O jaringan lewat trait `HttpClient` supaya tes bisa memakai fake.
- Trait inti (usulan):

```rust
pub trait LockfileParser: Send + Sync {
    fn ecosystem(&self) -> Ecosystem;
    fn matches(&self, path: &Path) -> bool;           // berdasarkan nama file
    fn parse(&self, path: &Path, content: &str) -> Result<ParsedLockfile, CoreError>;
}

#[async_trait::async_trait] // atau async fn in trait bila MSRV mengizinkan
pub trait HttpClient: Send + Sync {
    async fn get(&self, url: &str) -> Result<HttpResponse, CoreError>;
    async fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<HttpResponse, CoreError>;
}
```

- Error: `thiserror` di `patchsense-core`, `anyhow` hanya di biner.
- Versi crate tidak ditetapkan di dokumen ini. Agent memakai versi stabil terbaru saat menambahkan dependency (`cargo add`) dan mencatatnya di `Cargo.lock`.

### 10.3 Dependency yang disetujui
Wajib (keputusan): `tokio`, `clap`, `comfy-table`, `indicatif`, `serde`, `serde_json`, `toml`, `serde_yaml`, `quick-xml`, `reqwest` (fitur rustls, tanpa native-tls), `rusqlite` (fitur `bundled`), `insta` (dev), `rmcp` (MCP), `thiserror`, `anyhow`.

Boleh ditambahkan bila perlu (usulan, catat di PR): `cvss` (RustSec, parsing vector), `globset` atau `ignore` (discovery), `directories` atau `dirs` (lokasi cache), `which` (deteksi CLI agent), `semver`, `chrono` atau `time`, `async-trait`, `tempfile` (dev), `assert_cmd` (dev), `wiremock` (dev, integration test HTTP lokal). Dependency lain harus didiskusikan dulu.

---

## 11. Desain MCP (`patchsense mcp`)

Dibangun dengan `rmcp` (SDK MCP resmi untuk Rust, https://github.com/modelcontextprotocol/rust-sdk). Transport: stdio. Semua tool read-only dan tidak menulis file.

| Tool | Input (JSON Schema ringkas) | Output |
|---|---|---|
| `scan_project` | `{ "path": string (default "."), "ecosystems"?: string[], "min_score"?: number, "include_dev"?: boolean, "offline"?: boolean }` | Report JSON (bagian 8) tanpa `explanation`, dibatasi 50 temuan teratas plus `summary` lengkap. Juga dikirim sebagai teks ringkas markdown di `content` |
| `get_finding` | `{ "id": string (GHSA/CVE/OSV id), "path"?: string }` | Detail satu advisory: summary, details, range versi, `fixed_versions`, CVSS, EPSS, KEV, `score_breakdown`, references |
| `get_fix_plan` | `{ "path": string (default "."), "tier"?: "critical"\|"review"\|"defer" }` | Daftar upgrade per paket: `{ ecosystem, name, current, recommended (versi fix minimum yang menutup semua advisory), advisories[], manifest_hint }`. `manifest_hint` berisi saran perintah (mis. `npm install lodash@4.17.21`), tanpa dieksekusi |
| `explain_score` | `{ "id": string, "path"?: string }` | Penjelasan deterministik (tanpa AI) kenapa skornya sekian: tiap komponen, bobot, dan ambang |
| `list_supported_lockfiles` | `{}` | Tabel ekosistem dan nama file yang didukung |

Prompt MCP (opsional bila `rmcp` mendukung `prompts`): `triage_report` dengan argumen `lang` (`id`/`en`) yang menyuruh agent memanggil `scan_project` lalu menjelaskan top 5 temuan, dampak, dan langkah perbaikan, dengan link sumber.

Contoh konfigurasi (dicetak oleh `patchsense init --print-mcp-config`; format persis harus dicek di dokumentasi masing-masing tool saat implementasi):

```json
// Cursor: .cursor/mcp.json
{ "mcpServers": { "patchsense": { "command": "patchsense", "args": ["mcp"] } } }
```
```bash
# Claude Code
claude mcp add patchsense -- patchsense mcp
```
```toml
# Codex: ~/.codex/config.toml
[mcp_servers.patchsense]
command = "patchsense"
args = ["mcp"]
```

---

## 12. Adapter CLI agent (`scan --explain`)

```rust
pub trait AgentAdapter {
    fn name(&self) -> &'static str;                  // "codex" | "claude" | "cursor"
    fn binary_candidates(&self) -> &[&'static str];  // nama biner yang dicari di PATH
    fn build_command(&self, prompt_file: &Path, workdir: &Path) -> std::process::Command;
    fn parse_output(&self, stdout: &str) -> Result<String, AgentError>; // teks penjelasan akhir
}
```

| Adapter | Biner yang dicari | Perintah (non-interaktif, read-only) | Parsing |
|---|---|---|---|
| `codex` | `codex` | `codex exec --sandbox read-only -o <tmp>/last.md "<prompt>"` | Baca file `last.md` (`--output-last-message`) |
| `claude` | `claude` | `claude -p --output-format json "<prompt>"` | Ambil field `result` dari JSON |
| `cursor` | `agent`, lalu `cursor-agent` | `agent -p --output-format json "<prompt>"` (tanpa `--force`, jadi tidak mengubah file) | Ambil field `result` dari JSON |

Referensi (dicek 25 Okt 2026): Codex non-interactive https://developers.openai.com/codex/noninteractive, Claude Code CLI reference https://code.claude.com/docs/en/cli-reference, Cursor headless CLI https://cursor.com/docs/cli/headless. Dokumentasi Cursor sekarang memakai nama biner `agent`; `cursor-agent` dipertahankan sebagai fallback.

Aturan:
- Urutan `auto`: `PATCHSENSE_AGENT` → `[explain].agent` di config → codex → claude → cursor (yang pertama ditemukan di PATH).
- Prompt dibangun di `agent/prompt.rs` dari top-N temuan (JSON ringkas: id, paket, versi, fix, skor, breakdown, KEV, EPSS, references), plus instruksi: jawab dalam bahasa `--lang`, satu paragraf dampak dan satu langkah perbaikan per temuan, jangan mengarang versi, wajib mengutip link dari data. Prompt panjang ditulis ke file sementara bila perlu; argumen tidak boleh melewati batas panjang argumen OS (Windows sekitar 32K karakter), jadi potong top-N bila perlu.
- Timeout default 120 detik (`[explain].timeout_secs`), proses dibunuh bila lewat.
- Jalankan dengan `workdir` = root scan. Jangan pernah meneruskan flag yang memberi izin tulis (`--force`, `--yolo`, `danger-full-access`, `bypassPermissions`).
- Setiap adapter punya unit test untuk `build_command` (snapshot argumen) dan `parse_output` (fixture stdout). Tidak ada tes yang menjalankan agent sungguhan; sediakan tes manual opsional di belakang env `PATCHSENSE_E2E_AGENT=1`.
- Flag CLI agent bisa berubah, jadi setiap adapter terisolasi di satu file dan MCP tetap jalur utama.

### 12.1 `init --agent`: isi instruksi
Blok yang ditulis (contoh untuk `AGENTS.md`):

```markdown
<!-- patchsense:start -->
## Keamanan dependency (PatchSense)
- Sebelum menambah atau meng-upgrade dependency, jalankan `patchsense scan . --format json` atau panggil tool MCP `scan_project`.
- Prioritaskan temuan bertingkat `critical` (Kritis), lalu `review`. Gunakan `get_fix_plan` untuk versi perbaikan.
- Selalu sertakan link advisory dari hasil scan. Jangan mengarang versi perbaikan.
<!-- patchsense:end -->
```

Untuk Cursor, file `.cursor/rules/patchsense.mdc` diberi frontmatter (`description`, `alwaysApply: false`) sesuai format Cursor rules yang berlaku saat implementasi.

---

## 13. GitHub Action (`action.yml`)

Composite action di root repo. Memasang biner rilis (via installer shell cargo-dist atau unduh asset GitHub Release sesuai OS/arch runner), menjalankan scan sekali untuk semua format, mengunggah SARIF, lalu berkomentar di PR.

```yaml
name: PatchSense
description: Triage CVE berprioritas dari lockfile (OSV + EPSS + KEV + CVSS)
branding: { icon: shield, color: red }
inputs:
  path:            { description: "Direktori atau lockfile yang di-scan", default: "." }
  version:         { description: "Versi PatchSense (mis. 0.1.0) atau latest", default: "latest" }
  fail-on:         { description: "critical | review | any | never | angka 0-100", default: "critical" }
  config:          { description: "Path patchsense.toml", default: "" }
  sarif:           { description: "Unggah SARIF ke code scanning", default: "true" }
  comment:         { description: "Komentar ringkasan di PR", default: "true" }
  explain:         { description: "Jalankan --explain bila CLI agent tersedia di runner", default: "false" }
  github-token:    { description: "Token untuk komentar PR", default: "${{ github.token }}" }
outputs:
  report-path:     { description: "Path report JSON" }
  sarif-path:      { description: "Path SARIF" }
  max-score:       { description: "Skor tertinggi" }
  critical-count:  { description: "Jumlah temuan Kritis" }
runs:
  using: composite
  steps: [ ... install, scan (continue-on-error untuk menyimpan exit code), upload SARIF via github/codeql-action/upload-sarif, comment, lalu exit dengan kode scan ]
```

Contoh pemakaian:

```yaml
# .github/workflows/patchsense.yml
on: [pull_request]
permissions:
  contents: read
  security-events: write     # upload SARIF
  pull-requests: write       # komentar PR
jobs:
  patchsense:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Widyasa/patchsense@v0
        with:
          fail-on: critical
```

Catatan: exit code scan disimpan dulu, SARIF dan komentar tetap dikirim walaupun ada temuan, baru step terakhir gagal bila kode = 1. Untuk PR dari fork, token read-only, jadi komentar akan gagal; tangani dengan peringatan dan jangan membuat job error. Penjelasan AI di CI hanya jalan bila user sendiri sudah memasang action agent resmi (Codex atau Claude Code) dengan secret mereka; bila tidak, laporan tetap keluar tanpa AI.

Referensi upload SARIF: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github

---

## 14. Template GitLab CI

File: `templates/gitlab/patchsense.gitlab-ci.yml`. Dipakai dengan `include: remote:` (URL raw dari rilis) atau disalin.

```yaml
variables:
  PATCHSENSE_VERSION: "latest"
  PATCHSENSE_FAIL_ON: "critical"
  PATCHSENSE_PATH: "."

patchsense:
  stage: test
  image: debian:stable-slim          # atau image resmi bila nanti dibuat
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  before_script:
    - apt-get update && apt-get install -y --no-install-recommends curl ca-certificates
    - # pasang biner PatchSense via installer shell cargo-dist sesuai $PATCHSENSE_VERSION
  script:
    - set +e
    - patchsense scan "$PATCHSENSE_PATH" --fail-on "$PATCHSENSE_FAIL_ON"
        --format json --output patchsense-report.json
        --format gitlab --output gl-dependency-scanning-report.json
        --format markdown --output patchsense-report.md
    - code=$?
    - if [ -n "$CI_MERGE_REQUEST_IID" ] && [ -n "$GITLAB_TOKEN" ]; then patchsense comment --provider gitlab --report patchsense-report.json || true; fi
    - exit $code
  artifacts:
    when: always
    paths: [patchsense-report.json, patchsense-report.md]
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
```

Catatan: tampilan laporan Dependency Scanning di UI MR butuh GitLab Ultimate; di tier lain artifact tetap tersimpan dan komentar MR tetap jalan. `GITLAB_TOKEN` adalah project access token (scope `api`) yang disimpan user sebagai CI/CD variable masked. Referensi: https://docs.gitlab.com/ci/yaml/artifacts_reports/

---

## 15. Distribusi

| Kanal | Alat | Detail |
|---|---|---|
| Biner prebuilt | cargo-dist (`dist`, https://github.com/axodotdev/cargo-dist) | Target: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-musl` (opsional, untuk Alpine), `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`. Installer shell dan PowerShell |
| npm | cargo-dist installer npm | `npx patchsense scan .` |
| Homebrew | cargo-dist installer homebrew | Tap `Widyasa/homebrew-tap` |
| pip | maturin dengan `bindings = "bin"` (https://www.maturin.rs/bindings.html) | Workflow terpisah `pypi.yml` membangun wheel untuk OS yang sama dan publish via trusted publishing |
| cargo | `cargo install patchsense` | Publish `patchsense-core` dulu, lalu `patchsense` |

**Nama paket:** nama `patchsense` dipakai seragam di npm, PyPI, crates.io, Homebrew, dan nama biner, tanpa scope npm. Keputusan ini dikunci di W6-T1 (bagian 1.2 dan 17). Per 25 Okt 2026 nama itu masih kosong di keempat registry. Cek ulang tepat sebelum publish.

Rilis dipicu tag `v*`. `release.yml` dihasilkan `dist init` (jangan ditulis manual kecuali perlu). Publish ke registry butuh secret (`NPM_TOKEN`, `CARGO_REGISTRY_TOKEN`, trusted publishing PyPI) yang disiapkan Widya sendiri; agent tidak boleh membuat atau meminta token.

---

## 16. Risiko dan mitigasi

| Risiko | Mitigasi |
|---|---|
| Format lockfile beragam dan sering berubah | Banyak fixture nyata per versi format, snapshot `insta`, parser terisolasi per file |
| Kurva belajar Rust (ownership, async) | Parser dibuat sinkron dan murni (`&str` → struct); async hanya di klien HTTP dan orkestrasi |
| Build lintas platform untuk npm dan pip | cargo-dist untuk biner dan npm; maturin terpisah untuk pip; uji di matrix CI |
| Rate limit API publik | Batch query, konkurensi terbatas, retry dengan backoff, cache SQLite 24 jam, `--offline` |
| Bobot skor terasa subjektif | `score_breakdown` selalu ditampilkan, tool `explain_score`, bobot bisa diatur |
| Penjelasan AI bisa keliru | Label "bisa keliru", selalu dengan link sumber resmi, data deterministik tetap jadi sumber kebenaran |
| Flag CLI agent berubah | Adapter terpisah per agent, MCP jadi jalur utama, gagal = peringatan saja |
| Tidak ada agent di CI | Laporan tetap keluar tanpa AI; dokumentasikan cara memakai action agent resmi |
| `pom.xml` tanpa resolusi transitif dan properti parent | Dokumentasikan keterbatasannya; Gradle dan resolusi penuh ditunda |
| `requirements.txt` tidak dipin | Lewati dengan peringatan dan sarankan `pip freeze` atau `poetry.lock` |
| Bentrok nama "PatchSense" di npm/PyPI | Nama dikunci `patchsense` di W6-T1. Cek ulang registry tepat sebelum publish |
| URL dokumentasi EPSS lama (`www.first.org/epss/api`) sekarang 404 | Pakai https://api.first.org/epss/ dan https://www.first.org/epss/data.html |

---

## 17. Keputusan terbuka dan asumsi

Keputusan yang belum ada di rancangan dan perlu konfirmasi Widya (agent memakai default di bawah sampai diputuskan):

1. **Nama paket**: dikunci di W6-T1, yaitu `patchsense` di semua registry, tanpa scope npm. Di draf awal produk ini bernama VulnRadar. String `Widyasa` di repo ini adalah owner, bukan placeholder.
2. **Owner GitHub repo**: dikunci di W6-T1, yaitu akun `Widyasa` (`github.com/Widyasa/patchsense`).
3. **Default `--fail-on`**: diasumsikan `critical`.
4. **Mode EPSS**: diasumsikan `probability` dengan saturation 0.10.
5. **Direct tidak diketahui**: diasumsikan dihitung penuh (konservatif).
6. **MSRV**: diasumsikan Rust stable terbaru saat proyek dimulai, dicatat di `rust-version` di `Cargo.toml`.

---

## 18. Ukuran sukses (portofolio)

- Demo: satu perintah mendeteksi PHP2Shell di repo contoh (`examples/php2shell-demo/composer.lock`) dan menandainya Kritis.
- README dengan GIF demo (dibuat dengan `vhs` atau `asciinema`) dan penjelasan cara kerja skor.
- CI hijau di Linux, macOS, Windows; cakupan tes core minimal 80% baris (`cargo llvm-cov`, opsional).
- Rilis v0.1.0 dengan biner untuk 3 OS dan bisa dipasang lewat npm, pip, Homebrew, dan cargo.
- Satu artikel blog yang membedah desain dan keputusan teknisnya.
- Waktu scan repo dengan sekitar 1000 paket: di bawah 10 detik dengan cache dingin dan di bawah 2 detik dengan cache hangat (target, bukan syarat rilis).

## 19. Referensi API (diverifikasi 25 Okt 2026)

- OSV querybatch: https://google.github.io/osv.dev/post-v1-querybatch/ (endpoint `POST https://api.osv.dev/v1/querybatch`)
- OSV vulns: https://google.github.io/osv.dev/get-v1-vulns/ (endpoint `GET https://api.osv.dev/v1/vulns/{id}`)
- EPSS API: https://api.first.org/epss/ (endpoint `GET https://api.first.org/data/v1/epss?cve=...`)
- EPSS data dan CSV harian: https://www.first.org/epss/data.html
- CISA KEV JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (skema: `.../known_exploited_vulnerabilities_schema.json`)
- GitLab artifacts reports: https://docs.gitlab.com/ci/yaml/artifacts_reports/
- SDK MCP Rust (rmcp): https://github.com/modelcontextprotocol/rust-sdk
