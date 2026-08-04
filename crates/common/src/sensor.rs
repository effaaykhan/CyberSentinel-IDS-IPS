//! Sensor identity: a stable per-install id plus the host name.
//!
//! The id is a UUIDv4 generated on first run and persisted under
//! `paths.data-dir`, so events from one install stay correlatable across
//! restarts, host renames, and address changes.

use std::path::Path;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::event::SensorInfo;

/// Resolve the sensor identity for a config, creating the id file if needed.
///
/// # Errors
/// [`Error::Io`] if the id file cannot be read or created.
pub fn resolve(config: &Config) -> Result<SensorInfo> {
    let name = config.sensor.name.clone().unwrap_or_else(host_name);
    let id = load_or_create_id(&config.sensor_id_path())?;
    Ok(SensorInfo {
        name,
        id,
        version: crate::VERSION.to_string(),
    })
}

/// The host name, or `"unknown-host"` if the OS will not tell us.
///
/// A missing host name degrades event attribution but must not stop the sensor.
#[must_use]
pub fn host_name() -> String {
    let raw = gethostname::gethostname();
    let name = raw.to_string_lossy().trim().to_string();
    if name.is_empty() {
        tracing::warn!("could not determine the host name; using \"unknown-host\"");
        "unknown-host".to_string()
    } else {
        name
    }
}

/// Read the persisted sensor id, generating and storing one on first run.
///
/// A file that exists but holds something other than a UUID is replaced, and
/// the replacement is logged — a corrupted id file must not wedge startup.
///
/// # Errors
/// [`Error::Io`] if the file cannot be created or written.
pub fn load_or_create_id(path: &Path) -> Result<String> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let trimmed = existing.trim();
        if uuid::Uuid::parse_str(trimmed).is_ok() {
            return Ok(trimmed.to_string());
        }
        tracing::warn!(
            path = %path.display(),
            "sensor id file does not contain a UUID; generating a new sensor id"
        );
    }

    let id = uuid::Uuid::new_v4().to_string();
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|source| Error::io(parent, source))?;
        }
    }
    std::fs::write(path, format!("{id}\n")).map_err(|source| Error::io(path, source))?;
    tracing::info!(path = %path.display(), sensor_id = %id, "generated a new sensor id");
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal scratch directory helper: the workspace has no dev-dependency on
    /// a temp-dir crate yet, and this is the only place that needs one.
    struct ScratchDir(std::path::PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let unique = std::process::id();
            let path = std::env::temp_dir().join(format!("cybersentinel-test-{tag}-{unique}"));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn join(&self, name: &str) -> std::path::PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn id_is_generated_once_and_reused() {
        let dir = ScratchDir::new("sensor-id");
        let path = dir.join("sensor-id");
        let first = load_or_create_id(&path).unwrap();
        assert!(uuid::Uuid::parse_str(&first).is_ok());
        assert_eq!(
            load_or_create_id(&path).unwrap(),
            first,
            "the id must be stable"
        );
    }

    #[test]
    fn nested_data_dir_is_created() {
        let dir = ScratchDir::new("nested");
        let path = dir.join("a").join("b").join("sensor-id");
        assert!(load_or_create_id(&path).is_ok());
        assert!(path.exists());
    }

    #[test]
    fn a_corrupt_id_file_is_replaced_rather_than_fatal() {
        let dir = ScratchDir::new("corrupt");
        let path = dir.join("sensor-id");
        std::fs::write(&path, "not-a-uuid").unwrap();
        let id = load_or_create_id(&path).unwrap();
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn host_name_is_never_empty() {
        assert!(!host_name().is_empty());
    }
}
