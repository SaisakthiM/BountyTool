//! External tool layer: registry metadata, process execution and parsers.

pub mod parsers;
pub mod registry;
pub mod runner;

pub use registry::{Group, TOOLS, ToolSpec, ToolStatus, detect, detect_all, spec, which};
pub use runner::{ToolOutput, ToolRunner};

/// Convenience: `Vec<String>` from `&[&str]`.
pub fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}
