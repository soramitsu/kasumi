//! Canonical, closed consensus input. Remote operation bodies never provide the
//! credential context or trusted admission timestamp in this envelope.
use anyhow::{Result, ensure};
use kasumi_types::{CustodyRequest, RequestContext, validate_name};
use serde::{Deserialize, Serialize};

pub const MAX_CUSTODY_COMMAND_BYTES: usize = 256 << 10;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustodyCommand {
    pub context: RequestContext,
    pub admitted_at_ms: u64,
    pub request: CustodyRequest,
}
impl CustodyCommand {
    pub fn validate(&self) -> Result<()> {
        self.request.validate()?;
        ensure!(
            self.context.scopes.contains(&kasumi_types::Action::Admin),
            "custody command requires administrative credential scope"
        );
        for name in [
            &self.context.tenant,
            &self.context.principal,
            &self.context.request_id,
        ] {
            validate_name(name)?;
        }
        self.context
            .authorization
            .check_admitted_at(self.admitted_at_ms)?;
        Ok(())
    }
    pub fn encoded(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_CUSTODY_COMMAND_BYTES,
            "custody command quota exceeded"
        );
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_CUSTODY_COMMAND_BYTES,
            "custody command quota exceeded"
        );
        let command: Self = serde_json::from_slice(bytes)?;
        ensure!(
            command.encoded()? == bytes,
            "custody command is not canonical closed metadata"
        );
        Ok(command)
    }
}
