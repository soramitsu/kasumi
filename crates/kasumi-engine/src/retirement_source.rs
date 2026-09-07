//! Trusted installed routes. No wire deserializer or caller-controlled source
//! location can construct an administrative source route.
use crate::{
    CustodyResponseFence, Database, RetiredCustody, RetirementResponseFence,
    VerifiedRetirementReceipt, VerifiedRetirementResolution,
};
use kasumi_types::*;
use std::sync::Arc;

#[derive(Clone)]
pub enum InstalledRetirementSource {
    Serving(Arc<Database>),
    RetiredCustody(Arc<RetiredCustody>),
    RecoveringControl {
        tenant: String,
        source_incarnation: String,
    },
}
impl InstalledRetirementSource {
    pub fn identity(&self) -> Result<(String, String)> {
        match self {
            Self::Serving(database) => {
                let state = database.engine().generation()?;
                Ok((state.state.tenant.clone(), state.state.incarnation.clone()))
            }
            Self::RetiredCustody(custody) => custody.identity(),
            Self::RecoveringControl {
                tenant,
                source_incarnation,
            } => {
                validate_name(tenant)?;
                validate_name(source_incarnation)?;
                Ok((tenant.clone(), source_incarnation.clone()))
            }
        }
    }
    fn recovering() -> Error {
        Error::new(
            ErrorCode::Unavailable,
            "installed source control recovery is incomplete",
        )
    }
    pub fn response_fence(&self, context: &RequestContext) -> Result<RetirementResponseFence<'_>> {
        match self {
            Self::Serving(database) => {
                if database.engine().generation()?.state.retired {
                    database
                        .retired_custody()?
                        .response_fence(context)
                        .map(RetirementResponseFence::Custody)
                } else {
                    database.engine().authorize(context, None, Action::Admin)?;
                    database
                        .response_fence(context)
                        .map(RetirementResponseFence::Application)
                }
            }
            Self::RetiredCustody(custody) => custody
                .response_fence(context)
                .map(RetirementResponseFence::Custody),
            Self::RecoveringControl { .. } => Err(Self::recovering()),
        }
    }
    pub fn retired(&self) -> Result<Arc<RetiredCustody>> {
        match self {
            Self::Serving(database) => database.retired_custody(),
            Self::RetiredCustody(custody) => Ok(custody.clone()),
            Self::RecoveringControl { .. } => Err(Self::recovering()),
        }
    }
    pub async fn retire_source(
        &self,
        context: RequestContext,
        request: RetireSourceRequest,
    ) -> Result<VerifiedRetirementReceipt> {
        match self {
            Self::Serving(database) => database.retire_source(context, request).await,
            Self::RetiredCustody(custody) => {
                custody
                    .verify_retirement_receipt(context, &request.reference()?)
                    .await
            }
            Self::RecoveringControl { .. } => Err(Self::recovering()),
        }
    }
    pub async fn abort_retirement(
        &self,
        context: RequestContext,
        request: RetireSourceRequest,
    ) -> Result<VerifiedRetirementResolution> {
        match self {
            Self::Serving(database) => database.abort_retirement(context, request).await,
            Self::RetiredCustody(custody) => custody
                .verify_retirement_receipt(context, &request.reference()?)
                .await
                .map(VerifiedRetirementResolution::Retired),
            Self::RecoveringControl { .. } => Err(Self::recovering()),
        }
    }
    pub async fn retirement_status(
        &self,
        context: &RequestContext,
        reference: &RetirementRef,
    ) -> Result<Option<RetirementStatus>> {
        match self {
            Self::Serving(database) => database.retirement_status(context, reference).await,
            Self::RetiredCustody(custody) => custody.retirement_status(context, reference).await,
            Self::RecoveringControl { .. } => Err(Self::recovering()),
        }
    }
    pub async fn verify_retirement_receipt(
        &self,
        context: RequestContext,
        reference: &RetirementRef,
    ) -> Result<VerifiedRetirementReceipt> {
        match self {
            Self::Serving(database) => database.verify_retirement_receipt(context, reference).await,
            Self::RetiredCustody(custody) => {
                custody.verify_retirement_receipt(context, reference).await
            }
            Self::RecoveringControl { .. } => Err(Self::recovering()),
        }
    }
    pub fn retirement_response_fence(
        &self,
        context: &RequestContext,
        proof: &VerifiedRetirementReceipt,
    ) -> Result<CustodyResponseFence> {
        self.retired()?.retirement_response_fence(context, proof)
    }
    pub fn retirement_resolution_response_fence(
        &self,
        context: &RequestContext,
        proof: &VerifiedRetirementResolution,
    ) -> Result<RetirementResponseFence<'_>> {
        match self {
            Self::Serving(database) => {
                database.retirement_resolution_response_fence(context, proof)
            }
            Self::RetiredCustody(custody) => match proof {
                VerifiedRetirementResolution::Retired(proof) => custody
                    .retirement_response_fence(context, proof)
                    .map(RetirementResponseFence::Custody),
                VerifiedRetirementResolution::Stopped(_) => Err(Error::new(
                    ErrorCode::Conflict,
                    "retired source cannot release a nonretired stop",
                )),
            },
            Self::RecoveringControl { .. } => Err(Self::recovering()),
        }
    }
}
