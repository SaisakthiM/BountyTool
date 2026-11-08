//! Error type shared by the CLI, TUI and engine.

use std::path::PathBuf;

/// Every recoverable failure in BountyTool funnels through this enum so the
/// binary can map it onto a stable exit code (scripts depend on those).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("scope violation: {0}")]
    Scope(String),

    #[error("authorization gate: {0}")]
    Authorization(String),

    #[error(
        "missing required tool `{tool}`; install it with `bountytool doctor --install` (package: {package})"
    )]
    MissingTool {
        tool: &'static str,
        package: &'static str,
    },

    #[error("tool `{tool}` failed: {message}")]
    Tool { tool: &'static str, message: String },

    #[error("unsupported target `{0}`")]
    BadTarget(String),

    #[error("no session found at {0}")]
    NoSession(PathBuf),

    #[error("i/o error ({path}): {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("i/o error: {0}")]
    PlainIo(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("url error: {0}")]
    Url(#[from] url::ParseError),

    #[error("scan cancelled")]
    Cancelled,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Stable process exit codes.
    ///
    /// * `0` success
    /// * `1` generic failure
    /// * `2` missing required external tool
    /// * `3` scope or authorization refusal
    /// * `4` bad configuration
    /// * `130` interrupted
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Scope(_) | Error::Authorization(_) | Error::BadTarget(_) => 3,
            Error::MissingTool { .. } => 2,
            Error::Config(_) => 4,
            Error::Cancelled => 130,
            _ => 1,
        }
    }

    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}
