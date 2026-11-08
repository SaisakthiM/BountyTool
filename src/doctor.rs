//! `bountytool doctor`: dependency detection, reporting and installation.
//!
//! Arch has no official package for the ProjectDiscovery suite, so a bare
//! `pacman -S` can never install everything. The doctor splits packages by
//! origin (repo vs AUR) and drives the right package manager for each group.

use std::path::PathBuf;
use std::process::Command;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::events::Events;
use crate::models::Profile;
use crate::tools::{Group, ToolStatus, detect_all, registry};

pub struct DoctorReport {
    pub statuses: Vec<ToolStatus>,
    pub wordlist: Option<PathBuf>,
    pub param_wordlist: Option<PathBuf>,
    pub seclists_present: bool,
}

impl DoctorReport {
    pub fn missing_required(&self) -> Vec<&ToolStatus> {
        self.statuses
            .iter()
            .filter(|status| status.required && !status.usable())
            .collect()
    }

    pub fn missing_optional(&self) -> Vec<&ToolStatus> {
        self.statuses
            .iter()
            .filter(|status| !status.required && !status.usable())
            .collect()
    }

    /// Required tools for the profile, minus what is installed.
    pub fn blocking_for(&self, profile: Profile) -> Vec<&ToolStatus> {
        self.statuses
            .iter()
            .filter(|status| {
                (status.required
                    || (profile == Profile::Deep && status.stage == crate::models::Stage::Ports))
                    && !status.usable()
            })
            .collect()
    }
}

pub async fn inspect(config: &Config) -> DoctorReport {
    let statuses = detect_all().await;
    let wordlist = config.directory_wordlist();
    let param_wordlist = config.param_wordlist();
    let seclists_present = std::path::Path::new(&config.seclists_dir).is_dir();
    DoctorReport {
        statuses,
        wordlist,
        param_wordlist,
        seclists_present,
    }
}

/// Human-readable table for the CLI.
pub fn render(report: &DoctorReport) -> String {
    let mut out = String::new();
    out.push_str("Dependency status\n");
    out.push_str("=================\n");

    for status in &report.statuses {
        let marker = if status.usable() {
            "ok  "
        } else if status.required {
            "FAIL"
        } else {
            "warn"
        };
        out.push_str(&format!(
            "[{marker}] {:<18} {:<10} {}\n",
            status.name,
            status.group.as_str(),
            registry::describe(status)
        ));
        out.push_str(&format!(
            "         stage: {} · {}\n",
            status.stage.key(),
            status.purpose
        ));
    }

    out.push_str("\nWordlists\n---------\n");
    match &report.wordlist {
        Some(path) => out.push_str(&format!("directory list : {}\n", path.display())),
        None => out.push_str(
            "directory list : embedded mini wordlist (install seclists for better coverage)\n",
        ),
    }
    match &report.param_wordlist {
        Some(path) => out.push_str(&format!("parameter names: {}\n", path.display())),
        None => out.push_str("parameter names: built-in heuristics\n"),
    }
    out.push_str(&format!(
        "seclists       : {}\n",
        if report.seclists_present {
            "installed"
        } else {
            "not installed"
        }
    ));

    let missing_core = report.missing_required();
    let missing_optional = report.missing_optional();
    out.push('\n');
    if missing_core.is_empty() {
        out.push_str("Core toolchain complete.\n");
    } else {
        out.push_str(&format!(
            "{} required tool(s) missing. Run `bountytool doctor --install`.\n",
            missing_core.len()
        ));
    }
    if !missing_optional.is_empty() {
        out.push_str(&format!(
            "{} optional tool(s) missing; those stages degrade gracefully.\n",
            missing_optional.len()
        ));
    }
    out
}

/// Package lists per group, split by package manager.
pub fn packages(group: Group) -> (Vec<&'static str>, Vec<&'static str>) {
    let include = |candidate: Group| match group {
        Group::Core => candidate == Group::Core,
        Group::Recommended => matches!(candidate, Group::Core | Group::Recommended),
        Group::Heavy => true,
    };

    let mut repo: Vec<&'static str> = Vec::new();
    let mut aur: Vec<&'static str> = Vec::new();

    for spec in registry::TOOLS {
        if !include(spec.group) {
            continue;
        }
        match spec.package.split_once('/') {
            Some(("aur", name)) => aur.push(name),
            Some((_, name)) => repo.push(name),
            None => repo.push(spec.package),
        }
    }

    // Wordlists are not tools but are needed for content discovery.
    if group != Group::Core {
        aur.push("seclists");
    }

    repo.sort();
    repo.dedup();
    aur.sort();
    aur.dedup();
    (repo, aur)
}

/// Shell commands a user (or [`install`]) would run for this group.
pub fn install_commands(group: Group) -> Vec<String> {
    let (repo, aur) = packages(group);
    let mut commands = Vec::new();
    if !repo.is_empty() {
        commands.push(format!(
            "sudo pacman -S --needed --noconfirm {}",
            repo.join(" ")
        ));
    }
    if !aur.is_empty() {
        commands.push(format!("yay -S --needed --noconfirm {}", aur.join(" ")));
    }
    commands
}

/// Run the install commands, inheriting stdio so sudo/yay can prompt.
pub fn install(group: Group, dry_run: bool, events: &Events) -> Result<()> {
    let commands = install_commands(group);
    if commands.is_empty() {
        events.info("nothing to install for this group");
        return Ok(());
    }

    for command in &commands {
        if dry_run {
            events.info(format!("would run: {command}"));
            continue;
        }
        events.info(format!("$ {command}"));

        let status = Command::new("sh")
            .arg("-c")
            .arg(command)
            .status()
            .map_err(|error| Error::io(PathBuf::from("sh"), error))?;

        if !status.success() {
            return Err(Error::Other(format!(
                "installation command failed (exit {:?}): {command}",
                status.code()
            )));
        }
    }

    if !dry_run {
        events.info("refreshing nuclei templates (first run downloads them)");
        let _ = Command::new("nuclei")
            .args(["-update-templates", "-silent"])
            .status();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_group_targets_repo_and_aur_separately() {
        let (repo, aur) = packages(Group::Core);
        assert!(aur.contains(&"nuclei"));
        assert!(aur.contains(&"subfinder"));
        assert!(aur.contains(&"httpx"));
        assert!(!repo.contains(&"nuclei"));
    }

    #[test]
    fn recommended_group_adds_wordlists() {
        let (_, aur) = packages(Group::Recommended);
        assert!(aur.contains(&"seclists"));
    }

    #[test]
    fn install_commands_use_the_right_package_manager() {
        let commands = install_commands(Group::Core);
        assert!(commands.iter().any(|c| c.starts_with("yay -S")));
        assert!(
            commands
                .iter()
                .filter(|c| c.starts_with("sudo pacman -S"))
                .all(|c| c.contains("--needed"))
        );
    }
}
