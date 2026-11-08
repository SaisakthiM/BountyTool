//! BountyTool engine library.
//!
//! The binary (`src/main.rs`) is a thin shell: it parses CLI arguments, then
//! drives the same [`pipeline`] that the TUI drives. Everything that touches
//! the network lives behind [`scope::Scope`].

pub mod cli;
pub mod config;
pub mod doctor;
pub mod error;
pub mod events;
pub mod findings;
pub mod models;
pub mod pipeline;
pub mod probes;
pub mod report;
pub mod scope;
pub mod session;
pub mod tools;
pub mod tui;
pub mod util;

/// Tool name, version and repository, used by `--version` output.
pub const APP_NAME: &str = "bountytool";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const APP_REPO: &str = env!("CARGO_PKG_REPOSITORY");
