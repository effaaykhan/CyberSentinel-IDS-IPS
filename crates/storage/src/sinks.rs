//! Event-log sinks.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use cybersentinel_common::eventlog::EventSink;

/// Writes newline-delimited event JSON to stdout.
///
/// Diagnostic logging goes to stderr, so stdout stays a clean event stream that
/// can be piped straight into a consumer.
#[derive(Debug)]
pub struct StdoutEventSink {
    out: BufWriter<io::Stdout>,
}

impl StdoutEventSink {
    /// Create the sink.
    #[must_use]
    pub fn new() -> Self {
        Self {
            out: BufWriter::new(io::stdout()),
        }
    }
}

impl Default for StdoutEventSink {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSink for StdoutEventSink {
    fn name(&self) -> &str {
        "stdout"
    }

    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        self.out.write_all(line)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Appends newline-delimited event JSON to a file.
///
/// Opened in append mode so a restart never truncates history, and buffered so
/// a burst of events costs one write rather than one per event. The pipeline
/// flushes whenever the queue drains, which bounds how long an event can sit in
/// the buffer to "until the sensor is idle for an instant".
///
/// Rotation and retention are deliberately not handled here: captured data is
/// PII (guide §6), and retention policy belongs with the packaging layer, which
/// already installs a logrotate/`newsyslog` policy alongside the service.
#[derive(Debug)]
pub struct FileEventSink {
    path: PathBuf,
    name: String,
    out: BufWriter<File>,
}

impl FileEventSink {
    /// Open `path` for appending, creating parent directories as needed.
    ///
    /// # Errors
    /// Any I/O error creating the directory or opening the file.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            name: format!("file:{}", path.display()),
            out: BufWriter::new(file),
            path,
        })
    }

    /// The file being written.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl EventSink for FileEventSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        self.out.write_all(line)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("cybersentinel-sink-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn creates_missing_parent_directories() {
        let dir = scratch("mkdir");
        let path = dir.join("nested").join("events.json");
        let mut sink = FileEventSink::open(&path).unwrap();
        sink.write_line(b"{\"a\":1}\n").unwrap();
        sink.flush().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"a\":1}\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn appends_across_reopens() {
        let dir = scratch("append");
        let path = dir.join("events.json");

        let mut sink = FileEventSink::open(&path).unwrap();
        sink.write_line(b"first\n").unwrap();
        sink.flush().unwrap();
        drop(sink);

        let mut sink = FileEventSink::open(&path).unwrap();
        sink.write_line(b"second\n").unwrap();
        sink.flush().unwrap();
        drop(sink);

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "first\nsecond\n",
            "reopening must not truncate the event history"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn name_identifies_the_target_file() {
        let dir = scratch("name");
        let path = dir.join("events.json");
        let sink = FileEventSink::open(&path).unwrap();
        assert!(sink.name().starts_with("file:"));
        assert_eq!(sink.path(), path);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
