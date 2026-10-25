//! Scan progress on stderr. The bar exists only when stderr is a terminal.

use std::io::IsTerminal;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressStyle};

/// Whether stderr is a terminal.
pub fn stderr_is_tty() -> bool {
    std::io::stderr().is_terminal()
}

/// Whether stdout is a terminal.
pub fn stdout_is_tty() -> bool {
    std::io::stdout().is_terminal()
}

/// Color is on only for a TTY, and off for `--no-color` or `NO_COLOR`.
pub fn colors_enabled(no_color_flag: bool, no_color_env: bool, stdout_tty: bool) -> bool {
    stdout_tty && !no_color_flag && !no_color_env
}

/// Progress is drawn only when stderr is a terminal.
pub fn show_progress(stderr_tty: bool) -> bool {
    stderr_tty
}

/// Spinner for the scan. `None` when progress must stay off.
pub fn start_scan_progress(stderr_tty: bool) -> Option<ProgressBar> {
    if !show_progress(stderr_tty) {
        return None;
    }
    let bar = ProgressBar::new_spinner();
    if let Ok(style) = ProgressStyle::with_template("{spinner} {msg}") {
        bar.set_style(style);
    }
    bar.set_message("memindai lockfile");
    bar.enable_steady_tick(Duration::from_millis(120));
    Some(bar)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_and_color_stay_off_without_a_tty() {
        assert!(!show_progress(false));
        assert!(show_progress(true));
        assert!(!colors_enabled(false, false, false));
        assert!(!colors_enabled(true, false, true));
        assert!(!colors_enabled(false, true, true));
        assert!(colors_enabled(false, false, true));
        assert!(start_scan_progress(false).is_none());
    }
}
