//! Explicit process-local choice of how a standalone group stores its own
//! snapshots. Without it this binary writes the transportable embedded form,
//! exactly as earlier releases do, so installing it changes no stored format.
//! `reference` (KASUMIL1) keeps the audit archive chain in this node's cache
//! instead of copying it into every snapshot. Releases before it cannot read that
//! form: to roll back, start once with `embedded` (or no flag), wait for every
//! tenant to serve, and only then install the older binary.
use anyhow::{Result, bail};

const FLAG: &str = "--local-snapshot-archive";

/// Strip a final `--local-snapshot-archive embedded|reference` pair from `serve`.
/// Every other form keeps its existing dispatch and usage handling, including
/// the earlier compaction flag, which must precede this one.
pub fn serve_arguments(arguments: &[String]) -> Result<(&[String], Option<bool>)> {
    let [command, .., flag, value] = arguments else {
        return Ok((arguments, None));
    };
    if command != "serve" || flag != FLAG || arguments.len() < 4 {
        return Ok((arguments, None));
    }
    let reference = match value.as_str() {
        "embedded" => false,
        "reference" => true,
        _ => bail!("local snapshot archive must be embedded or reference"),
    };
    Ok((&arguments[..arguments.len() - 2], Some(reference)))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).into()).collect()
    }
    #[test]
    fn ordinary_serve_and_other_commands_are_unchanged() {
        for input in [
            args(&["serve", "installed.json"]),
            args(&["serve", "installed.json", "--storage-compaction-growth-percent", "150"]),
            args(&["check-config", "x", FLAG, "reference"]),
            args(&[FLAG, "reference"]),
        ] {
            let (rest, choice) = serve_arguments(&input).unwrap();
            assert_eq!(rest, input);
            assert!(choice.is_none());
        }
    }
    #[test]
    fn a_final_choice_is_stripped_and_leaves_the_compaction_flag_for_its_parser() {
        let input = args(&["serve", "installed.json", FLAG, "reference"]);
        assert_eq!(serve_arguments(&input).unwrap(), (&input[..2], Some(true)));
        let input = args(&["serve", "installed.json", FLAG, "embedded"]);
        assert_eq!(serve_arguments(&input).unwrap(), (&input[..2], Some(false)));
        let input = args(&[
            "serve",
            "installed.json",
            "--storage-compaction-growth-percent",
            "150",
            FLAG,
            "reference",
        ]);
        let (rest, choice) = serve_arguments(&input).unwrap();
        assert_eq!(rest, &input[..4]);
        assert_eq!(choice, Some(true));
        let (rest, policy) = crate::storage_maintenance::serve_arguments(rest).unwrap();
        assert_eq!(rest, &input[..2]);
        assert_eq!(policy.unwrap().growth_percent, 150);
    }
    #[test]
    fn an_unknown_choice_is_refused_before_opening() {
        for value in ["", "Reference", "by-reference", "kasumil1"] {
            let input = args(&["serve", "installed.json", FLAG, value]);
            assert!(serve_arguments(&input).is_err(), "{value:?}");
        }
    }
}
