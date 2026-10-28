//! SQLite cache for OSV advisory bodies, EPSS rows, and the CISA KEV feed.
//!
//! The schema version lives in `meta`. A different version drops the tables
//! and creates them again. TTL is checked by the caller-supplied clock so
//! tests do not sleep. An OSV row is also a miss when `modified` changed.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// `meta.schema_version`. Bump this when the tables change shape.
pub const SCHEMA_VERSION: i64 = 2;

/// Default TTL from the product spec: 24 hours.
pub const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// One cached EPSS row.
#[derive(Debug, Clone, PartialEq)]
pub struct EpssEntry {
    /// CVE id.
    pub cve: String,
    /// EPSS probability, 0–1.
    pub score: f64,
    /// EPSS percentile, 0–1.
    pub percentile: f64,
    /// Score date (`YYYY-MM-DD`) from the FIRST response.
    pub date: String,
    /// Unix seconds when the row was stored.
    pub fetched_at: i64,
}

/// One OSV id returned for a package query, plus the document `modified` time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedOsvRef {
    /// OSV id.
    pub id: String,
    /// OSV `modified` timestamp.
    pub modified: String,
}

/// Row counts for `patchsense cache info`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheStats {
    /// `meta.schema_version`.
    pub schema_version: i64,
    /// Rows in `osv_vuln`.
    pub osv_vuln: i64,
    /// Rows in `epss`.
    pub epss: i64,
    /// Rows in `kev`.
    pub kev: i64,
    /// Rows in `osv_query`.
    pub osv_query: i64,
}

/// The cached KEV catalog document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KevEntry {
    /// CISA `catalogVersion`.
    pub catalog_version: String,
    /// Raw catalog JSON.
    pub json: String,
    /// Unix seconds when the catalog was stored.
    pub fetched_at: i64,
}

/// Opened `cache.db`. The connection is mutex-guarded so the cache can cross
/// `.await` points later.
#[derive(Debug)]
pub struct Cache {
    path: PathBuf,
    conn: Mutex<Connection>,
}

/// Inputs for [`resolve_cache_db`]. Environment variables are already read.
#[derive(Debug, Clone, Copy)]
pub struct CacheLocation<'a> {
    /// `--cache-dir`, when the CLI passed one.
    pub flag: Option<&'a Path>,
    /// `PATCHSENSE_CACHE_DIR`.
    pub env_cache_dir: Option<&'a Path>,
    /// `XDG_CACHE_HOME`.
    pub xdg_cache_home: Option<&'a Path>,
    /// Home directory.
    pub home: Option<&'a Path>,
    /// `LOCALAPPDATA` on Windows.
    pub local_app_data: Option<&'a Path>,
    /// `linux`, `macos`, or `windows`.
    pub os: &'a str,
}

impl Cache {
    /// Open or create `path`, migrating the schema when the version differs.
    pub fn open(path: &Path) -> Result<Self, CoreError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| CoreError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }
        let conn = Connection::open(path).map_err(|err| cache_err(path, err))?;
        ensure_schema(&conn).map_err(|err| cache_err(path, err))?;
        Ok(Self {
            path: path.to_path_buf(),
            conn: Mutex::new(conn),
        })
    }

    /// `schema_version` currently stored in `meta`.
    pub fn schema_version(&self) -> Result<i64, CoreError> {
        self.with_conn(|conn| {
            conn.query_row("SELECT schema_version FROM meta LIMIT 1", [], |row| {
                row.get(0)
            })
        })
    }

    /// Cached OSV document when `modified` matches and the row is inside `ttl`.
    ///
    /// Age is `now - fetched_at` in seconds. Age greater than or equal to the
    /// TTL is a miss.
    pub fn get_osv(
        &self,
        id: &str,
        modified: &str,
        now: i64,
        ttl: Duration,
    ) -> Result<Option<String>, CoreError> {
        Ok(self
            .get_osv_document(id, modified, now, ttl)?
            .map(|(json, _)| json))
    }

    /// Cached OSV document and the Unix time it was stored, inside `ttl`.
    pub fn get_osv_document(
        &self,
        id: &str,
        modified: &str,
        now: i64,
        ttl: Duration,
    ) -> Result<Option<(String, i64)>, CoreError> {
        let row = self.with_conn(|conn| {
            conn.query_row(
                "SELECT modified, json, fetched_at FROM osv_vuln WHERE id = ?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
        })?;
        Ok(row.and_then(|(stored_modified, json, fetched_at)| {
            if stored_modified == modified && fresh(fetched_at, now, ttl) {
                Some((json, fetched_at))
            } else {
                None
            }
        }))
    }

    /// Unix time of a stored advisory, ignoring TTL and `modified`.
    ///
    /// `None` means the id was never stored.
    pub fn osv_document_fetched_at(&self, id: &str) -> Result<Option<i64>, CoreError> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT fetched_at FROM osv_vuln WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .optional()
        })
    }

    /// Insert or replace an OSV document.
    pub fn put_osv(
        &self,
        id: &str,
        modified: &str,
        json: &str,
        fetched_at: i64,
    ) -> Result<(), CoreError> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO osv_vuln (id, modified, json, fetched_at) VALUES (?1, ?2, ?3, ?4)",
                (id, modified, json, fetched_at),
            )?;
            Ok(())
        })
    }

    /// Cached EPSS row inside `ttl`.
    pub fn get_epss(
        &self,
        cve: &str,
        now: i64,
        ttl: Duration,
    ) -> Result<Option<EpssEntry>, CoreError> {
        let row = self.with_conn(|conn| {
            conn.query_row(
                "SELECT cve, score, percentile, date, fetched_at FROM epss WHERE cve = ?1",
                [cve],
                |row| {
                    Ok(EpssEntry {
                        cve: row.get(0)?,
                        score: row.get(1)?,
                        percentile: row.get(2)?,
                        date: row.get(3)?,
                        fetched_at: row.get(4)?,
                    })
                },
            )
            .optional()
        })?;
        Ok(row.filter(|entry| fresh(entry.fetched_at, now, ttl)))
    }

    /// Cached EPSS row with no TTL check. `None` when the CVE was never stored.
    pub fn get_epss_stored(&self, cve: &str) -> Result<Option<EpssEntry>, CoreError> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT cve, score, percentile, date, fetched_at FROM epss WHERE cve = ?1",
                [cve],
                |row| {
                    Ok(EpssEntry {
                        cve: row.get(0)?,
                        score: row.get(1)?,
                        percentile: row.get(2)?,
                        date: row.get(3)?,
                        fetched_at: row.get(4)?,
                    })
                },
            )
            .optional()
        })
    }

    /// Insert or replace an EPSS row.
    pub fn put_epss(&self, entry: &EpssEntry) -> Result<(), CoreError> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO epss (cve, score, percentile, date, fetched_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    &entry.cve,
                    entry.score,
                    entry.percentile,
                    &entry.date,
                    entry.fetched_at,
                ),
            )?;
            Ok(())
        })
    }

    /// Newest KEV catalog inside `ttl`.
    pub fn get_kev(&self, now: i64, ttl: Duration) -> Result<Option<KevEntry>, CoreError> {
        let row = self.with_conn(|conn| {
            conn.query_row(
                "SELECT catalog_version, json, fetched_at FROM kev ORDER BY fetched_at DESC LIMIT 1",
                [],
                |row| {
                    Ok(KevEntry {
                        catalog_version: row.get(0)?,
                        json: row.get(1)?,
                        fetched_at: row.get(2)?,
                    })
                },
            )
            .optional()
        })?;
        Ok(row.filter(|entry| fresh(entry.fetched_at, now, ttl)))
    }

    /// Newest stored KEV catalog with no TTL check.
    pub fn get_kev_stored(&self) -> Result<Option<KevEntry>, CoreError> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT catalog_version, json, fetched_at FROM kev ORDER BY fetched_at DESC LIMIT 1",
                [],
                |row| {
                    Ok(KevEntry {
                        catalog_version: row.get(0)?,
                        json: row.get(1)?,
                        fetched_at: row.get(2)?,
                    })
                },
            )
            .optional()
        })
    }

    /// Cached `querybatch` ids for one package inside `ttl`.
    pub fn get_osv_query(
        &self,
        ecosystem: &str,
        name: &str,
        version: &str,
        now: i64,
        ttl: Duration,
    ) -> Result<Option<(Vec<CachedOsvRef>, i64)>, CoreError> {
        let row = self.with_conn(|conn| {
            conn.query_row(
                "SELECT ids_json, fetched_at FROM osv_query WHERE ecosystem = ?1 AND name = ?2 AND version = ?3",
                (ecosystem, name, version),
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
        })?;
        let Some((json, fetched_at)) = row.filter(|(_, fetched_at)| fresh(*fetched_at, now, ttl))
        else {
            return Ok(None);
        };
        let refs: Vec<CachedOsvRef> =
            serde_json::from_str(&json).map_err(|err| CoreError::Cache {
                path: self.path.clone(),
                message: format!(
                    "osv_query for {ecosystem} {name}@{version} is invalid JSON: {err}"
                ),
            })?;
        Ok(Some((refs, fetched_at)))
    }

    /// Unix time of a stored `querybatch` row, ignoring TTL.
    ///
    /// `None` means the package was never stored.
    pub fn osv_query_fetched_at(
        &self,
        ecosystem: &str,
        name: &str,
        version: &str,
    ) -> Result<Option<i64>, CoreError> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT fetched_at FROM osv_query WHERE ecosystem = ?1 AND name = ?2 AND version = ?3",
                (ecosystem, name, version),
                |row| row.get(0),
            )
            .optional()
        })
    }

    /// Insert or replace the `querybatch` ids for one package.
    pub fn put_osv_query(
        &self,
        ecosystem: &str,
        name: &str,
        version: &str,
        refs: &[CachedOsvRef],
        fetched_at: i64,
    ) -> Result<(), CoreError> {
        let json = serde_json::to_string(refs).map_err(|err| CoreError::Cache {
            path: self.path.clone(),
            message: err.to_string(),
        })?;
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO osv_query (ecosystem, name, version, ids_json, fetched_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                (ecosystem, name, version, json, fetched_at),
            )?;
            Ok(())
        })
    }

    /// Row counts. The caller has already opened a current schema.
    pub fn stats(&self) -> Result<CacheStats, CoreError> {
        self.with_conn(|conn| {
            Ok(CacheStats {
                schema_version: conn.query_row(
                    "SELECT schema_version FROM meta LIMIT 1",
                    [],
                    |row| row.get(0),
                )?,
                osv_vuln: count(conn, "osv_vuln")?,
                epss: count(conn, "epss")?,
                kev: count(conn, "kev")?,
                osv_query: count(conn, "osv_query")?,
            })
        })
    }

    /// Insert or replace a KEV catalog.
    pub fn put_kev(&self, entry: &KevEntry) -> Result<(), CoreError> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO kev (catalog_version, json, fetched_at) VALUES (?1, ?2, ?3)",
                (&entry.catalog_version, &entry.json, entry.fetched_at),
            )?;
            Ok(())
        })
    }

    fn with_conn<T>(
        &self,
        body: impl FnOnce(&Connection) -> Result<T, rusqlite::Error>,
    ) -> Result<T, CoreError> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        body(&conn).map_err(|err| cache_err(&self.path, err))
    }
}

/// Database path: flag, then `PATCHSENSE_CACHE_DIR`, then the OS cache directory.
pub fn resolve_cache_db(input: CacheLocation<'_>) -> PathBuf {
    let dir = if let Some(flag) = input.flag {
        flag.to_path_buf()
    } else if let Some(dir) = input.env_cache_dir {
        dir.to_path_buf()
    } else if input.os == "macos" && input.xdg_cache_home.is_none() {
        input
            .home
            .unwrap_or_else(|| Path::new("."))
            .join("Library/Caches/patchsense")
    } else if input.os == "windows" && input.xdg_cache_home.is_none() {
        input
            .local_app_data
            .unwrap_or_else(|| Path::new("."))
            .join("patchsense")
    } else {
        let base = input
            .xdg_cache_home
            .map(Path::to_path_buf)
            .or_else(|| input.home.map(|home| home.join(".cache")))
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("patchsense")
    };
    dir.join("cache.db")
}

pub(crate) fn fresh(fetched_at: i64, now: i64, ttl: Duration) -> bool {
    let ttl_secs = i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);
    now.saturating_sub(fetched_at) < ttl_secs
}

/// Seconds from `fetched_at` to `now`. Never negative.
pub(crate) fn row_age(fetched_at: i64, now: i64) -> i64 {
    now.saturating_sub(fetched_at).max(0)
}

/// `2h`, `1h 5m`, `5m`, or `12s`.
pub(crate) fn format_span(seconds: i64) -> String {
    let seconds = seconds.max(0);
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if hours > 0 && minutes > 0 {
        format!("{hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{seconds}s")
    }
}

/// [`format_span`] for a TTL duration.
pub(crate) fn format_ttl(ttl: Duration) -> String {
    format_span(i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX))
}

fn ensure_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    let version = read_schema_version(conn)?;
    if version == Some(SCHEMA_VERSION) {
        return Ok(());
    }
    conn.execute_batch(
        "
        DROP TABLE IF EXISTS meta;
        DROP TABLE IF EXISTS osv_vuln;
        DROP TABLE IF EXISTS epss;
        DROP TABLE IF EXISTS kev;
        DROP TABLE IF EXISTS osv_query;
        CREATE TABLE meta (schema_version INTEGER NOT NULL);
        CREATE TABLE osv_vuln (
            id TEXT PRIMARY KEY,
            modified TEXT NOT NULL,
            json TEXT NOT NULL,
            fetched_at INTEGER NOT NULL
        );
        CREATE TABLE epss (
            cve TEXT PRIMARY KEY,
            score REAL NOT NULL,
            percentile REAL NOT NULL,
            date TEXT NOT NULL,
            fetched_at INTEGER NOT NULL
        );
        CREATE TABLE kev (
            catalog_version TEXT PRIMARY KEY,
            json TEXT NOT NULL,
            fetched_at INTEGER NOT NULL
        );
        CREATE TABLE osv_query (
            ecosystem TEXT NOT NULL,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            ids_json TEXT NOT NULL,
            fetched_at INTEGER NOT NULL,
            PRIMARY KEY (ecosystem, name, version)
        );
        ",
    )?;
    conn.execute(
        "INSERT INTO meta (schema_version) VALUES (?1)",
        [SCHEMA_VERSION],
    )?;
    Ok(())
}

fn read_schema_version(conn: &Connection) -> Result<Option<i64>, rusqlite::Error> {
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
            [],
            |_| Ok(true),
        )
        .optional()?
        .unwrap_or(false);
    if !exists {
        return Ok(None);
    }
    conn.query_row("SELECT schema_version FROM meta LIMIT 1", [], |row| {
        row.get(0)
    })
    .optional()
}

fn count(conn: &Connection, table: &str) -> Result<i64, rusqlite::Error> {
    // Table names are fixed literals from `stats`. They are not user input.
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
}

/// Delete `path` when it exists. Missing files are success.
pub fn remove_cache_db(path: &Path) -> Result<bool, CoreError> {
    if !path.exists() {
        return Ok(false);
    }
    fs::remove_file(path).map_err(|source| CoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(true)
}

fn cache_err(path: &Path, err: impl std::fmt::Display) -> CoreError {
    CoreError::Cache {
        path: path.to_path_buf(),
        message: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_temp() -> (tempfile::TempDir, Cache) {
        let dir = tempfile::tempdir().expect("tempdir");
        let cache = Cache::open(&dir.path().join("cache.db")).expect("open");
        (dir, cache)
    }

    #[test]
    fn osv_ttl_and_modified_invalidation() {
        let (_dir, cache) = open_temp();
        let ttl = Duration::from_secs(100);
        cache
            .put_osv(
                "GHSA-1",
                "2026-01-01T00:00:00Z",
                "{\"id\":\"GHSA-1\"}",
                1_000,
            )
            .expect("put");
        let fresh = cache
            .get_osv("GHSA-1", "2026-01-01T00:00:00Z", 1_099, ttl)
            .expect("get");
        assert_eq!(fresh.as_deref(), Some("{\"id\":\"GHSA-1\"}"));
        let expired = cache
            .get_osv("GHSA-1", "2026-01-01T00:00:00Z", 1_100, ttl)
            .expect("expired");
        assert!(expired.is_none());
        let changed = cache
            .get_osv("GHSA-1", "2026-02-01T00:00:00Z", 1_050, ttl)
            .expect("modified");
        assert!(changed.is_none());
    }

    #[test]
    fn epss_and_kev_roundtrip_inside_ttl() {
        let (_dir, cache) = open_temp();
        let ttl = DEFAULT_TTL;
        cache
            .put_epss(&EpssEntry {
                cve: "CVE-2021-23337".to_string(),
                score: 0.0123,
                percentile: 0.78,
                date: "2026-10-24".to_string(),
                fetched_at: 50,
            })
            .expect("epss");
        let epss = cache
            .get_epss("CVE-2021-23337", 50, ttl)
            .expect("get epss")
            .expect("row");
        assert_eq!(epss.score, 0.0123);
        assert_eq!(epss.percentile, 0.78);
        cache
            .put_kev(&KevEntry {
                catalog_version: "2026.10.23".to_string(),
                json: "{\"vulnerabilities\":[]}".to_string(),
                fetched_at: 50,
            })
            .expect("kev");
        let kev = cache.get_kev(50, ttl).expect("get kev").expect("catalog");
        assert_eq!(kev.catalog_version, "2026.10.23");
        assert!(cache
            .get_kev(50 + DEFAULT_TTL.as_secs() as i64, ttl)
            .unwrap()
            .is_none());
    }

    #[test]
    fn different_schema_version_recreates_the_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested/cache.db");
        {
            let cache = Cache::open(&path).expect("open");
            cache.put_osv("GHSA-1", "m", "{}", 10).expect("put");
            assert_eq!(cache.schema_version().expect("version"), SCHEMA_VERSION);
        }
        {
            let conn = Connection::open(&path).expect("raw");
            conn.execute("UPDATE meta SET schema_version = 99", [])
                .expect("bump");
        }
        let cache = Cache::open(&path).expect("reopen");
        assert_eq!(cache.schema_version().expect("version"), SCHEMA_VERSION);
        let row = cache.get_osv("GHSA-1", "m", 10, DEFAULT_TTL).expect("get");
        assert!(row.is_none());
    }

    #[test]
    fn cache_path_prefers_flag_then_env_then_os_default() {
        let flag = Path::new("/tmp/flag");
        let env = Path::new("/tmp/env");
        let xdg = Path::new("/xdg");
        let home = Path::new("/home/dev");
        let local = Path::new("C:/Users/dev/AppData/Local");
        assert_eq!(
            resolve_cache_db(CacheLocation {
                flag: Some(flag),
                env_cache_dir: Some(env),
                xdg_cache_home: Some(xdg),
                home: Some(home),
                local_app_data: Some(local),
                os: "linux",
            }),
            PathBuf::from("/tmp/flag/cache.db")
        );
        assert_eq!(
            resolve_cache_db(CacheLocation {
                flag: None,
                env_cache_dir: Some(env),
                xdg_cache_home: Some(xdg),
                home: Some(home),
                local_app_data: None,
                os: "linux",
            }),
            PathBuf::from("/tmp/env/cache.db")
        );
        assert_eq!(
            resolve_cache_db(CacheLocation {
                flag: None,
                env_cache_dir: None,
                xdg_cache_home: Some(xdg),
                home: Some(home),
                local_app_data: None,
                os: "linux",
            }),
            PathBuf::from("/xdg/patchsense/cache.db")
        );
        assert_eq!(
            resolve_cache_db(CacheLocation {
                flag: None,
                env_cache_dir: None,
                xdg_cache_home: None,
                home: Some(home),
                local_app_data: None,
                os: "linux",
            }),
            PathBuf::from("/home/dev/.cache/patchsense/cache.db")
        );
        assert_eq!(
            resolve_cache_db(CacheLocation {
                flag: None,
                env_cache_dir: None,
                xdg_cache_home: None,
                home: Some(home),
                local_app_data: None,
                os: "macos",
            }),
            PathBuf::from("/home/dev/Library/Caches/patchsense/cache.db")
        );
        assert_eq!(
            resolve_cache_db(CacheLocation {
                flag: None,
                env_cache_dir: None,
                xdg_cache_home: None,
                home: Some(home),
                local_app_data: Some(local),
                os: "windows",
            }),
            PathBuf::from("C:/Users/dev/AppData/Local/patchsense/cache.db")
        );
    }
}
