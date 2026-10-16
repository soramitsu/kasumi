use openraft::{
    BasicNode,
    error::{ClientWriteError, RaftError},
};

/// Recognize only the ordinary leadership redirect produced by application
/// client_write. Inspecting the typed source preserves both anyhow context and
/// the original opaque error for every other failure. A redirect is not proof
/// of rollback: an uncertain caller must resolve its original command identity.
pub fn is_application_write_redirect(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<RaftError<u64, ClientWriteError<u64, BasicNode>>>(),
        Some(RaftError::APIError(ClientWriteError::ForwardToLeader(_)))
    )
}

/// These exact errors are emitted before OpenRaft appends or dispatches the
/// proposed entry, or before the standalone writer's journal holds any of it.
/// Fatal construction errors and other failures remain opaque.
pub fn is_application_write_capacity_denied(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<RaftError<u64, ClientWriteError<u64, BasicNode>>>(),
        Some(RaftError::APIError(ClientWriteError::TaskCapacity(_)))
    ) || error.downcast_ref::<LocalAppendCapacityDenied>().is_some()
}

/// The standalone writer was refused capacity while appending this entry, and
/// the refusal proves nothing reached its journal: the entry was neither
/// committed nor applied, the writer keeps serving, and its next entry takes
/// the same position. A definite rejection, never an uncertain outcome.
#[derive(Debug)]
pub struct LocalAppendCapacityDenied;
impl std::fmt::Display for LocalAppendCapacityDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("standalone journal append refused for capacity; nothing was written")
    }
}
impl std::error::Error for LocalAppendCapacityDenied {}

/// OpenRaft committed and locally applied the entry, then this group lost
/// access before its result could be released. The effect may be durable:
/// callers resolve the original command identity; this is never a rollback.
#[derive(Debug)]
pub struct PostCommitAccessLost;
impl std::fmt::Display for PostCommitAccessLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("application entry committed before group access was lost")
    }
}

/// Recognize only the typed post-commit marker, through any added context.
pub fn is_post_commit_access_loss(error: &anyhow::Error) -> bool {
    error.downcast_ref::<PostCommitAccessLost>().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openraft::error::{ChangeMembershipError, EmptyMembership, Fatal, ForwardToLeader};

    #[test]
    fn post_commit_access_loss_is_typed_and_never_inferred_from_text() {
        let lost = anyhow::anyhow!("tenant is sealed")
            .context(PostCommitAccessLost)
            .context("application proposal");
        assert!(is_post_commit_access_loss(&lost));
        assert!(!is_application_write_redirect(&lost));
        assert!(!is_application_write_capacity_denied(&lost));
        assert!(!is_post_commit_access_loss(&anyhow::anyhow!(
            "application entry committed before group access was lost"
        )));
        let fatal: RaftError<u64, ClientWriteError<u64, BasicNode>> =
            RaftError::Fatal(Fatal::Panicked);
        assert!(!is_post_commit_access_loss(&anyhow::Error::new(fatal)));
    }

    #[test]
    fn application_redirect_recognizes_exact_type_through_anyhow_context() {
        let original: RaftError<u64, ClientWriteError<u64, BasicNode>> =
            RaftError::APIError(ClientWriteError::ForwardToLeader(ForwardToLeader::empty()));
        let error = anyhow::Error::new(original);
        assert!(is_application_write_redirect(&error));
        let wrapped = error
            .context("application write context")
            .context("proposal context");
        assert!(is_application_write_redirect(&wrapped));
    }

    #[test]
    fn application_redirect_never_reclassifies_fatal_or_other_api_errors() {
        let fatal: RaftError<u64, ClientWriteError<u64, BasicNode>> =
            RaftError::Fatal(Fatal::Panicked);
        let fatal = anyhow::Error::new(fatal).context("application write context");
        let original = fatal
            .downcast_ref::<RaftError<u64, ClientWriteError<u64, BasicNode>>>()
            .unwrap();
        assert!(!is_application_write_redirect(&fatal));
        assert!(std::ptr::eq(
            original,
            fatal
                .downcast_ref::<RaftError<u64, ClientWriteError<u64, BasicNode>>>()
                .unwrap()
        ));
        let membership: RaftError<u64, ClientWriteError<u64, BasicNode>> =
            RaftError::APIError(ClientWriteError::ChangeMembershipError(
                ChangeMembershipError::EmptyMembership(EmptyMembership {}),
            ));
        assert!(!is_application_write_redirect(&anyhow::Error::new(
            membership
        )));
        assert!(!is_application_write_redirect(&anyhow::anyhow!(
            "has to forward request to: None, None"
        )));
    }

    #[test]
    fn application_capacity_denial_recognizes_only_the_pre_log_api_error() {
        use openraft::error::TaskCapacity;
        let denied: RaftError<u64, ClientWriteError<u64, BasicNode>> =
            RaftError::APIError(ClientWriteError::TaskCapacity(TaskCapacity {
                limit: 4,
                needed: 2,
            }));
        let denied = anyhow::Error::new(denied).context("application proposal");
        assert!(is_application_write_capacity_denied(&denied));
        assert!(!is_application_write_redirect(&denied));
        let fatal: RaftError<u64, ClientWriteError<u64, BasicNode>> =
            RaftError::Fatal(Fatal::TaskCapacity(TaskCapacity {
                limit: 0,
                needed: 1,
            }));
        assert!(!is_application_write_capacity_denied(&anyhow::Error::new(
            fatal
        )));
        assert!(!is_application_write_capacity_denied(&anyhow::anyhow!(
            "retained task capacity exhausted (limit: 4, needed: 2)"
        )));
    }

    #[test]
    fn local_append_capacity_denial_is_typed_and_never_inferred_from_text() {
        let denied = anyhow::Error::new(LocalAppendCapacityDenied).context("local write");
        assert!(is_application_write_capacity_denied(&denied));
        assert!(!is_application_write_redirect(&denied));
        assert!(!is_post_commit_access_loss(&denied));
        assert!(!is_application_write_capacity_denied(&anyhow::anyhow!(
            "standalone journal append refused for capacity; nothing was written"
        )));
    }
}
