//! Store-origin access refusal with no owned resource payload.

/// The actual Store access gate refused its current lease. Construction is
/// private to Store; this fixed diagnostic owns no reader, writer or provider.
/// It does not itself attest the retirement of an enclosing native operation.
/// A native or point-retirement failure must keep its owning outer wrapper.
#[derive(Debug)]
pub struct KeyAccessDenied {
    _private: (),
}

impl KeyAccessDenied {
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

impl std::fmt::Display for KeyAccessDenied {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("tenant is sealed: key-access lease unavailable or expired")
    }
}

impl std::error::Error for KeyAccessDenied {}
