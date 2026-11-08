//! Filesystem helpers for writing scan artifacts.

use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};

/// Write one item per line, creating the parent directory.
pub fn write_lines<P: AsRef<Path>, I: IntoIterator<Item = String>>(
    path: P,
    lines: I,
) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let mut buffer = String::new();
    for line in lines {
        buffer.push_str(&line);
        buffer.push('\n');
    }
    std::fs::write(path, buffer).map_err(|e| Error::io(path, e))
}

/// Write a JSON array pretty-printed.
pub fn write_json<P: AsRef<Path>, T: Serialize>(path: P, value: &T) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let text = serde_json::to_string_pretty(value)?;
    std::fs::write(path, text).map_err(|e| Error::io(path, e))
}

/// Write newline-delimited JSON.
pub fn write_jsonl<P: AsRef<Path>, T: Serialize>(path: P, items: &[T]) -> Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let mut buffer = String::new();
    for item in items {
        buffer.push_str(&serde_json::to_string(item)?);
        buffer.push('\n');
    }
    std::fs::write(path, buffer).map_err(|e| Error::io(path, e))
}

pub fn read_lines<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect())
}

pub fn read_jsonl<P: AsRef<Path>, T: DeserializeOwned>(path: P) -> Result<Vec<T>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(path).map_err(|e| Error::io(path, e))?;
    let mut items = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(item) = serde_json::from_str::<T>(line) {
            items.push(item);
        }
    }
    Ok(items)
}
