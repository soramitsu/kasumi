use crate::Config;

/// Shared v1 timing profile for replicated server groups.
///
/// Multiple tenant groups share a runtime and durable storage scheduler. These
/// timings allow more scheduling and persistence variance than OpenRaft's fast
/// defaults and reduce idle heartbeat traffic. They do not change quorum rules,
/// application deadlines, persistence, or membership. Embedded one-voter groups
/// retain their local startup settings.
pub fn server_config() -> Config {
    Config {
        heartbeat_interval: 250,
        election_timeout_min: 1_500,
        election_timeout_max: 3_000,
        install_snapshot_timeout: 30_000,
        ..Config::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replicated_timing_profile_satisfies_openraft_and_retains_safety_features() {
        let profile = server_config().validate().unwrap();
        assert!(profile.election_timeout_min >= profile.heartbeat_interval * 6);
        assert!(profile.election_timeout_max > profile.election_timeout_min);
        assert!(profile.install_snapshot_timeout > profile.election_timeout_max);
        assert!(profile.enable_tick && profile.enable_heartbeat && profile.enable_elect);
        assert_eq!(profile.snapshot_policy, Config::default().snapshot_policy);
        assert_eq!(
            profile.max_payload_entries,
            Config::default().max_payload_entries
        );
        assert_eq!(Config::default().heartbeat_interval, 50);
    }
}
