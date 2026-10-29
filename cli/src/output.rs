use colored::Colorize;
use serde::Serialize;
use serde_json::json;

/// Stable exit codes so a script or agent can branch on outcome without
/// parsing human text.
pub const EXIT_DAEMON_ERROR: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_PRO_REQUIRED: i32 = 3;
pub const EXIT_NOT_WIRED: i32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

pub struct CliOutput {
    format: OutputFormat,
}

pub enum ErrorKind {
    Daemon,
    Local,
    Usage,
    Pro,
}

pub struct CliError {
    pub kind: ErrorKind,
    pub message: String,
}

impl CliError {
    /// A failure talking to vandamd (connection, malformed response, 4xx/5xx).
    pub fn daemon(message: impl Into<String>) -> Self {
        Self { kind: ErrorKind::Daemon, message: message.into() }
    }
    /// A failure that has nothing to do with vandamd (local file I/O, validation).
    pub fn local(message: impl Into<String>) -> Self {
        Self { kind: ErrorKind::Local, message: message.into() }
    }
    pub fn usage(message: impl Into<String>) -> Self {
        Self { kind: ErrorKind::Usage, message: message.into() }
    }
    pub fn pro(message: impl Into<String>) -> Self {
        Self { kind: ErrorKind::Pro, message: message.into() }
    }

    fn exit_code(&self) -> i32 {
        match self.kind {
            ErrorKind::Daemon | ErrorKind::Local => EXIT_DAEMON_ERROR,
            ErrorKind::Usage => EXIT_USAGE,
            ErrorKind::Pro => EXIT_PRO_REQUIRED,
        }
    }

    fn kind_str(&self) -> &'static str {
        match self.kind {
            ErrorKind::Daemon => "daemon_error",
            ErrorKind::Local => "local_error",
            ErrorKind::Usage => "usage_error",
            ErrorKind::Pro => "pro_required",
        }
    }
}

impl CliOutput {
    pub fn from_flag(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "human" => Ok(Self { format: OutputFormat::Human }),
            "json" => Ok(Self { format: OutputFormat::Json }),
            other => Err(format!(
                "Invalid --output value '{}': expected 'human' or 'json'",
                other
            )),
        }
    }

    pub fn is_json(&self) -> bool {
        matches!(self.format, OutputFormat::Json)
    }

    /// Render a successful result. `human` is only invoked in human mode, so
    /// callers don't pay for building colored strings in JSON mode.
    pub fn emit_ok<T: Serialize>(&self, data: &T, human: impl FnOnce(&T)) {
        match self.format {
            OutputFormat::Human => human(data),
            OutputFormat::Json => {
                let wrapped = json!({ "data": data });
                println!("{}", wrapped);
            }
        }
    }

    /// Render an error uniformly and exit with a stable, error-kind-specific code.
    pub fn emit_err(&self, err: CliError) -> ! {
        match self.format {
            OutputFormat::Human => {
                eprintln!("{} {}", "Error:".red().bold(), err.message.red());
            }
            OutputFormat::Json => {
                let wrapped = json!({
                    "error": {
                        "kind": err.kind_str(),
                        "message": err.message,
                    }
                });
                println!("{}", wrapped);
            }
        }
        std::process::exit(err.exit_code());
    }

    /// Shared "not wired yet" stub, used by every command whose backend
    /// doesn't exist yet (either because vandamd never had it, or because
    /// wiring it is deliberately deferred to a future comms-layer rework).
    /// This is a phasing decision, not a permanent limitation — the wording
    /// and exit code both reflect that.
    pub fn emit_not_implemented(&self, cmd_path: &str, reason: &str) -> ! {
        match self.format {
            OutputFormat::Human => {
                println!(
                    "{} '{}' is not wired yet: {} {}",
                    "[vandam]".yellow(),
                    cmd_path,
                    reason,
                    "(planned for a future release)".bright_black()
                );
            }
            OutputFormat::Json => {
                let wrapped = json!({
                    "status": "not_implemented",
                    "command": cmd_path,
                    "reason": reason,
                });
                println!("{}", wrapped);
            }
        }
        std::process::exit(EXIT_NOT_WIRED);
    }
}
