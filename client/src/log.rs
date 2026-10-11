//! Line-oriented log file next to the ASI (`[log] file` in the ini).
//!
//! Each line is `<unix seconds>.<millis> <LEVEL> <message>` and is flushed immediately, so the file is
//! complete up to the moment the game dies. Any failure to log (write/flush error, clock before the Unix
//! epoch, poisoned lock) is handed to the `on_failure` callback the logger was built with — in the shipped
//! ASI that callback shows the reason and ends the process. Logging never fails silently.

use std::fmt::Display;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Level::Info => "INFO ",
            Level::Warn => "WARN ",
            Level::Error => "ERROR",
        }
    }
}

/// Called with a description of the failure when a line cannot be logged. Must not log through the same
/// [`Logger`].
pub type OnFailure = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Clone)]
pub struct Logger {
    sink: Arc<Mutex<Box<dyn Write + Send>>>,
    on_failure: OnFailure,
}

impl Logger {
    pub fn new(sink: Box<dyn Write + Send>, on_failure: OnFailure) -> Self {
        Logger { sink: Arc::new(Mutex::new(sink)), on_failure }
    }

    /// Open (append) the log file.
    pub fn open(path: &std::path::Path, on_failure: OnFailure) -> std::io::Result<Self> {
        let f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self::new(Box::new(f), on_failure))
    }

    pub fn log(&self, level: Level, msg: impl Display) {
        if let Err(reason) = self.try_log(level, &msg) {
            (self.on_failure)(&format!("cannot write the log ({reason}); dropped line: {} {msg}", level.tag()));
        }
    }

    fn try_log(&self, level: Level, msg: &dyn Display) -> Result<(), String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| format!("system clock: {e}"))?;
        let line = format!("{}.{:03} {} {msg}\n", now.as_secs(), now.subsec_millis(), level.tag());
        let mut sink = self.sink.lock().map_err(|_| "log lock poisoned".to_string())?;
        sink.write_all(line.as_bytes()).and_then(|_| sink.flush()).map_err(|e| e.to_string())
    }

    pub fn info(&self, msg: impl Display) {
        self.log(Level::Info, msg)
    }
    pub fn warn(&self, msg: impl Display) {
        self.log(Level::Warn, msg)
    }
    pub fn error(&self, msg: impl Display) {
        self.log(Level::Error, msg)
    }
}

#[cfg(test)]
pub mod capture {
    use super::{Level, Logger};
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    pub struct Captured(Arc<Mutex<Vec<u8>>>);

    impl Write for Captured {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        pub fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    pub fn logger() -> (Logger, Captured) {
        let c = Captured::default();
        (Logger::new(Box::new(c.clone()), Arc::new(|reason: &str| panic!("log failure in test: {reason}"))), c)
    }

    struct Broken;

    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk full"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_failure_reaches_on_failure() {
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = seen.clone();
        let l = Logger::new(Box::new(Broken), Arc::new(move |r: &str| sink.lock().unwrap().push(r.to_string())));
        l.log(Level::Warn, "hello");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].contains("disk full") && seen[0].contains("hello"), "{seen:?}");
    }

    #[test]
    fn lines_have_level_and_message() {
        let (l, c) = logger();
        l.error("boom");
        let t = c.text();
        assert!(t.ends_with(" ERROR boom\n"), "{t:?}");
    }
}
