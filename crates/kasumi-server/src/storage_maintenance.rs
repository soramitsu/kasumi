//! Explicit process-local maintenance scheduling. No installed configuration,
//! custody/schema bytes or generic KV defaults change when this opt-in is used.
use anyhow::{Result, ensure};
use kasumi_store::MaintenancePolicy;

/// Parse only the exact optional serve flag; all other CLI forms retain their
/// existing dispatch/usage handling. Invalid explicit policies fail before opening.
pub fn serve_arguments(arguments: &[String]) -> Result<(&[String], Option<MaintenancePolicy>)> {
    if let [command, _, flag, value] = arguments
        && command == "serve"
        && flag == "--storage-compaction-growth-percent"
    {
        ensure!(
            !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
            "compaction growth percent must be an integer in 101..200"
        );
        let percent: u32 = value.parse()?;
        // This opt-in schedules earlier; it cannot weaken the existing growth cap.
        ensure!(
            (101..=200).contains(&percent),
            "compaction growth percent must be in 101..200"
        );
        let policy = MaintenancePolicy {
            growth_percent: percent,
            ..MaintenancePolicy::default()
        };
        policy.validate()?;
        return Ok((&arguments[..2], Some(policy)));
    }
    Ok((arguments, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).into()).collect()
    }
    #[test]
    fn ordinary_serve_and_generic_defaults_are_unchanged() {
        let input = args(&["serve", "installed.json"]);
        let (rest, policy) = serve_arguments(&input).unwrap();
        assert_eq!(rest, input);
        assert!(policy.is_none());
        assert_eq!(MaintenancePolicy::default().growth_percent, 200);
    }
    #[test]
    fn explicit_150_changes_only_growth_and_is_scoped_to_this_invocation() {
        let input = args(&[
            "serve",
            "installed.json",
            "--storage-compaction-growth-percent",
            "150",
        ]);
        let (rest, policy) = serve_arguments(&input).unwrap();
        assert_eq!(rest, &input[..2]);
        assert_eq!(
            policy.unwrap(),
            MaintenancePolicy {
                growth_percent: 150,
                ..MaintenancePolicy::default()
            }
        );
        let other = args(&["serve", "other.json"]);
        assert!(serve_arguments(&other).unwrap().1.is_none());
    }
    #[test]
    fn invalid_growth_is_refused_before_opening_or_any_external_effect() {
        for value in ["0", "100", "201", "-1", "+150", "150.0", "", "4294967296"] {
            let input = args(&[
                "serve",
                "installed.json",
                "--storage-compaction-growth-percent",
                value,
            ]);
            assert!(serve_arguments(&input).is_err(), "{value}");
        }
        let duplicate = args(&[
            "serve",
            "installed.json",
            "--storage-compaction-growth-percent",
            "150",
            "--storage-compaction-growth-percent",
            "150",
        ]);
        let (rest, policy) = serve_arguments(&duplicate).unwrap();
        assert_eq!(rest.len(), 6); // Ordinary dispatch refuses it; never truncated to serve.
        assert!(policy.is_none());
    }
}
