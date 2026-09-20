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

/// This exact API error is emitted before OpenRaft appends or dispatches the
/// proposed entry. Fatal construction errors and other failures remain opaque.
pub fn is_application_write_capacity_denied(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<RaftError<u64, ClientWriteError<u64, BasicNode>>>(),
        Some(RaftError::APIError(ClientWriteError::TaskCapacity(_)))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use openraft::error::{ChangeMembershipError, EmptyMembership, Fatal, ForwardToLeader};

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
}
