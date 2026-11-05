//! Options of `kasumid serve`. Each one is process-local: it changes no installed
//! configuration and, by itself, no stored data. Options may come in any order
//! after the configuration path, as `--name value` or `--name=value`.
use anyhow::{Context, Result, bail, ensure};
use kasumi_store::MaintenancePolicy;
use std::path::PathBuf;

pub const USAGE: &str = "\
usage: kasumid serve <configuration.json> [options]

Options:
  --storage-compaction-growth-percent <101-200>
      Start a storage compaction cycle once the retained files reach this
      percentage of the size the last cycle left (default 150). A lower value
      compacts earlier and needs less free disk at the peak of a cycle; a
      higher one rewrites less often.
  --local-snapshot-archive <reference|embedded>
      How a standalone group stores its own snapshots (default reference).
      reference: the snapshot names the tenant audit archive chain this node
        already keeps under tenant-audit-archives/ (format KASUMIL1), so each
        snapshot holds only the tenant's logical state.
      embedded: every snapshot carries a full copy of that archive chain
        (format KASUMID1), the only form releases before KASUMIL1 can reopen.
        Before installing such a release, serve once with embedded and wait
        until every tenant serves: each by-reference snapshot is rewritten.
  -h, --help
      Print this help.";

/// How a standalone group stores the snapshots it reopens from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalSnapshotArchive {
    /// KASUMIL1: the snapshot references this node's retained archive chain.
    Reference,
    /// KASUMID1: the snapshot embeds the whole archive chain.
    Embedded,
}

impl LocalSnapshotArchive {
    pub fn name(self) -> &'static str {
        match self {
            Self::Reference => "reference",
            Self::Embedded => "embedded",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServeOptions {
    pub configuration: PathBuf,
    pub storage_maintenance: MaintenancePolicy,
    pub local_snapshot_archive: LocalSnapshotArchive,
}

/// The daemon compacts at 150% rather than the storage library's 200%: at 200%
/// a cycle on a ~25 GB store needs ~25 GB of free disk at its peak.
pub const DEFAULT_GROWTH_PERCENT: u32 = 150;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServeCommand {
    Help,
    Serve(ServeOptions),
}

const GROWTH: &str = "--storage-compaction-growth-percent";
const ARCHIVE: &str = "--local-snapshot-archive";

/// Parse `serve ...`. Returns `None` for every other command.
pub fn parse(arguments: &[String]) -> Result<Option<ServeCommand>> {
    let Some((command, rest)) = arguments.split_first() else {
        return Ok(None);
    };
    if command != "serve" {
        return Ok(None);
    }
    let mut configuration = None;
    let mut growth = None;
    let mut archive = None;
    let mut rest = rest.iter();
    while let Some(argument) = rest.next() {
        if argument == "-h" || argument == "--help" {
            return Ok(Some(ServeCommand::Help));
        }
        if !argument.starts_with("--") {
            ensure!(
                configuration.is_none(),
                "kasumid serve takes one configuration path; unexpected argument {argument:?}\n\n{USAGE}"
            );
            configuration = Some(PathBuf::from(argument));
            continue;
        }
        let (name, inline) = match argument.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (argument.as_str(), None),
        };
        let mut value = || match &inline {
            Some(value) => Ok(value.clone()),
            None => rest
                .next()
                .cloned()
                .with_context(|| format!("{name} needs a value\n\n{USAGE}")),
        };
        match name {
            GROWTH => {
                ensure!(growth.is_none(), "{GROWTH} was given twice");
                growth = Some(growth_policy(&value()?)?);
            }
            ARCHIVE => {
                ensure!(archive.is_none(), "{ARCHIVE} was given twice");
                archive = Some(match value()?.as_str() {
                    "reference" => LocalSnapshotArchive::Reference,
                    "embedded" => LocalSnapshotArchive::Embedded,
                    other => bail!("{ARCHIVE} must be reference or embedded, not {other:?}"),
                });
            }
            _ => bail!("unknown kasumid serve option {name:?}\n\n{USAGE}"),
        }
    }
    let configuration = configuration
        .with_context(|| format!("kasumid serve needs a configuration path\n\n{USAGE}"))?;
    let storage_maintenance = match growth {
        Some(policy) => policy,
        None => growth_policy(&DEFAULT_GROWTH_PERCENT.to_string())?,
    };
    Ok(Some(ServeCommand::Serve(ServeOptions {
        configuration,
        storage_maintenance,
        local_snapshot_archive: archive.unwrap_or(LocalSnapshotArchive::Reference),
    })))
}

fn growth_policy(value: &str) -> Result<MaintenancePolicy> {
    ensure!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "{GROWTH} must be an integer from 101 to 200, not {value:?}"
    );
    let percent = value
        .parse::<u32>()
        .ok()
        .filter(|percent| (101..=200).contains(percent))
        .with_context(|| format!("{GROWTH} must be an integer from 101 to 200, not {value:?}"))?;
    // Only earlier scheduling is offered; the default growth cap is the maximum.
    let policy = MaintenancePolicy {
        growth_percent: percent,
        ..MaintenancePolicy::default()
    };
    policy.validate()?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    fn serve(values: &[&str]) -> ServeOptions {
        match parse(&args(values)).unwrap() {
            Some(ServeCommand::Serve(options)) => options,
            other => panic!("not a serve: {other:?}"),
        }
    }

    #[test]
    fn other_commands_are_not_serve() {
        for input in [
            args(&[]),
            args(&["check-config", "node.json"]),
            args(&["servex", "node.json"]),
            args(&[ARCHIVE, "reference"]),
        ] {
            assert_eq!(parse(&input).unwrap(), None, "{input:?}");
        }
    }

    #[test]
    fn plain_serve_uses_by_reference_snapshots_and_earlier_compaction() {
        assert_eq!(
            serve(&["serve", "node.json"]),
            ServeOptions {
                configuration: "node.json".into(),
                storage_maintenance: MaintenancePolicy {
                    growth_percent: 150,
                    ..MaintenancePolicy::default()
                },
                local_snapshot_archive: LocalSnapshotArchive::Reference,
            }
        );
    }

    #[test]
    fn options_are_accepted_in_any_order_and_either_spelling() {
        let expected = ServeOptions {
            configuration: "node.json".into(),
            storage_maintenance: MaintenancePolicy {
                growth_percent: 120,
                ..MaintenancePolicy::default()
            },
            local_snapshot_archive: LocalSnapshotArchive::Embedded,
        };
        for input in [
            &["serve", "node.json", GROWTH, "120", ARCHIVE, "embedded"][..],
            &["serve", "node.json", ARCHIVE, "embedded", GROWTH, "120"],
            &["serve", ARCHIVE, "embedded", "node.json", GROWTH, "120"],
            &[
                "serve",
                "--storage-compaction-growth-percent=120",
                "--local-snapshot-archive=embedded",
                "node.json",
            ],
        ] {
            assert_eq!(serve(input), expected, "{input:?}");
        }
        assert_eq!(
            serve(&["serve", "node.json", ARCHIVE, "reference"]).local_snapshot_archive,
            LocalSnapshotArchive::Reference
        );
    }

    #[test]
    fn help_is_available_with_or_without_a_configuration() {
        for input in [&["serve", "--help"][..], &["serve", "node.json", "-h"]] {
            assert_eq!(parse(&args(input)).unwrap(), Some(ServeCommand::Help));
        }
    }

    #[test]
    fn mistakes_are_refused_before_anything_opens_and_say_why() {
        for (input, message) in [
            (&["serve"][..], "needs a configuration path"),
            (&["serve", "a.json", "b.json"], "one configuration path"),
            (
                &["serve", "node.json", "--compaction", "150"],
                "unknown kasumid serve option",
            ),
            (&["serve", "node.json", GROWTH], "needs a value"),
            (
                &["serve", "node.json", GROWTH, "150", GROWTH, "150"],
                "given twice",
            ),
            (
                &["serve", "node.json", ARCHIVE, "Reference"],
                "reference or embedded",
            ),
            (
                &[
                    "serve",
                    "node.json",
                    ARCHIVE,
                    "reference",
                    ARCHIVE,
                    "embedded",
                ],
                "given twice",
            ),
        ] {
            let error = parse(&args(input)).unwrap_err().to_string();
            assert!(error.contains(message), "{input:?}: {error}");
        }
        for value in ["0", "100", "201", "-1", "+150", "150.0", "", "4294967296"] {
            let input = args(&["serve", "node.json", GROWTH, value]);
            let error = parse(&input).unwrap_err().to_string();
            assert!(error.contains("from 101 to 200"), "{value:?}: {error}");
        }
    }
}
