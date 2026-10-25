//! `patchsense init` writes the example config from PRD §7.

use std::path::Path;

use anyhow::Context;

/// Example `patchsense.toml` printed by `patchsense init`.
pub const EXAMPLE_CONFIG: &str = r#"# patchsense.toml
schema_version = 1

[scan]
ecosystems = ["npm", "pypi", "packagist", "go", "maven", "cargo"]
exclude = ["examples/**", "fixtures/**"]
include_dev = true
fail_on = "critical"

[score.weights]
kev = 35
epss = 25
cvss = 20
direct = 10
fix_available = 10

[score.epss]
mode = "probability"
saturation = 0.10

[score.thresholds]
critical = 70
review = 40

[score.unknown_direct]
weight_fraction = 1.0

[cache]
ttl_hours_osv = 24
ttl_hours_epss = 24
ttl_hours_kev = 24

[output]
top = 20

[explain]
agent = "auto"
top = 10
lang = "id"
timeout_secs = 120

[[ignore]]
id = "GHSA-xxxx-xxxx-xxxx"
reason = "Hanya dipakai di script build, tidak terekspos"
expires = "2027-01-31"
"#;

/// What `write_example_config` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitStatus {
    /// The file was not there and was created.
    Created,
    /// The file was already there and `--force` was not set.
    Kept,
    /// `--force` replaced an existing file.
    Replaced,
}

/// Write `patchsense.toml` in `dir`.
pub fn write_example_config(dir: &Path, force: bool) -> anyhow::Result<InitStatus> {
    let path = dir.join("patchsense.toml");
    if path.is_file() && !force {
        return Ok(InitStatus::Kept);
    }
    let replaced = path.is_file();
    std::fs::write(&path, EXAMPLE_CONFIG)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(if replaced {
        InitStatus::Replaced
    } else {
        InitStatus::Created
    })
}
