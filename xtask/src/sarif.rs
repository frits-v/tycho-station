//! SARIF 2.1.0 files under `target/sarif`, and the findings the checks report.

use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

pub const SARIF_DIR: &str = "target/sarif";

/// One finding at a file, line and column, all one-based.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub rule: String,
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}: {}: {}",
            self.path, self.line, self.column, self.rule, self.message
        )
    }
}

/// `target/sarif/<name>.sarif`.
pub fn path_for(name: &str) -> PathBuf {
    Path::new(SARIF_DIR).join(format!("{name}.sarif"))
}

pub fn ensure_directory() -> Result<(), String> {
    for directory in ["target", SARIF_DIR] {
        match fs::create_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("cannot create {directory}: {error}")),
        }
    }
    Ok(())
}
