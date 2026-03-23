use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Info => write!(formatter, "*"),
            LogLevel::Success => write!(formatter, "+"),
            LogLevel::Warning => write!(formatter, "!"),
            LogLevel::Error => write!(formatter, "-"),
        }
    }
}

pub trait UnloadLogger {
    fn log(&mut self, level: LogLevel, message: &str);
}

pub struct BufferLogger {
    entries: Vec<String>,
}

impl BufferLogger {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn into_output(self) -> String {
        self.entries.join("")
    }
}

impl UnloadLogger for BufferLogger {
    fn log(&mut self, level: LogLevel, message: &str) {
        self.entries.push(format!("[{}] {}\n", level, message));
    }
}
