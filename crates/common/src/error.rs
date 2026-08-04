//! Error type shared by the foundational crates.

use std::path::PathBuf;

/// Convenience alias for fallible operations in this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors raised while loading configuration, resolving sensor identity, or
/// writing events.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An I/O operation against a named path failed.
    #[error("i/o error on {path}: {source}")]
    Io {
        /// Path involved in the failed operation.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// `config.yaml` could not be parsed.
    #[error("failed to parse config {path}: {source}")]
    ConfigParse {
        /// Path of the offending config file.
        path: PathBuf,
        /// Underlying YAML error.
        #[source]
        source: serde_yaml::Error,
    },

    /// The config parsed but holds a value the sensor cannot act on.
    #[error("invalid configuration: {0}")]
    ConfigInvalid(String),

    /// An event could not be serialized to CyberSentinel event JSON.
    #[error("failed to serialize event: {0}")]
    Serialize(#[from] serde_json::Error),
}

impl Error {
    /// Attach a path to a bare [`std::io::Error`].
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
