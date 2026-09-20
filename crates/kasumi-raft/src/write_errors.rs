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
}
