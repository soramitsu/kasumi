//! Full future-batch shape validation without executing or retaining an intent.
use super::*;

pub(crate) fn admit_mutation_capacity(
    state: &TenantState,
    context: &RequestContext,
    request: &AdmitMutationCapacity,
) -> Result<MutationCapacityAdmission> {
    let batch = &request.batch;
    if request.expected_incarnation != state.incarnation || context.tenant != state.tenant {
        return Err(Error::new(
            ErrorCode::Conflict,
            "mutation admission identity differs",
        ));
    }
    validate_name(&context.principal)?;
    validate_name(&batch.idempotency_key)?;
    if batch.operations.is_empty()
        || batch.operations.len() > 256
        || batch.operations.len() > state.limits.max_batch_operations
        || batch.read_set.len() > 512
        || encoded_len(batch)? > state.limits.max_batch_bytes
    {
        return Err(Error::new(
            ErrorCode::ResourceExhausted,
            "future mutation exceeds current capacity",
        ));
    }
    let snapshot = ReadAssertion::Snapshot {
        incarnation: state.incarnation.clone(),
        policy_epoch: state.policy_epoch,
        schema_epoch: state.schema_epoch,
    };
    if !batch.read_set.contains(&snapshot)
        || batch
            .read_set
            .iter()
            .any(|a| matches!(a, ReadAssertion::Snapshot { .. }) && a != &snapshot)
    {
        return Err(Error::new(
            ErrorCode::Conflict,
            "future mutation lacks exact current epoch custody",
        ));
    }
    let mut targets = BTreeSet::new();
    for operation in &batch.operations {
        let (collection, id) = operation.target();
        validate_name(collection)?;
        validate_name(id)?;
        authorize_state(state, context, Some(collection), Action::Write)?;
        if !targets.insert((collection, id)) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "future mutation repeats a target",
            ));
        }
        match operation {
            Mutation::Put { body, .. } if encoded_len(body)? <= state.limits.max_document_bytes => {
            }
            Mutation::Delete { .. } => {}
            Mutation::Put { .. } => {
                return Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "future document exceeds current capacity",
                ));
            }
            // Patch expansion depends on its retained source. Capacity plans use
            // complete resulting originals; actual Mutate retains its patch API.
            Mutation::Patch { .. } => {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "capacity admission requires complete future documents",
                ));
            }
        }
    }
    let mut assertion_identities = BTreeSet::new();
    for assertion in &batch.read_set {
        let identity = match assertion {
            ReadAssertion::Snapshot { .. } => (0, "", ""),
            ReadAssertion::Document { collection, id, .. } => (1, collection.as_str(), id.as_str()),
            ReadAssertion::Collection { collection, .. } => (2, collection.as_str(), ""),
            ReadAssertion::Before { .. } => (3, "", ""),
            ReadAssertion::NotBefore { .. } => (4, "", ""),
        };
        if !assertion_identities.insert(identity) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "future mutation repeats a read identity",
            ));
        }
        if let ReadAssertion::Document { collection, id, .. } = assertion {
            validate_name(collection)?;
            validate_name(id)?;
            authorize_state(state, context, Some(collection), Action::Read)?;
        } else if let ReadAssertion::Collection { collection, .. } = assertion {
            validate_name(collection)?;
            authorize_state(state, context, Some(collection), Action::Read)?;
        }
    }
    Ok(MutationCapacityAdmission {
        tenant: state.tenant.clone(),
        incarnation: state.incarnation.clone(),
        revision: state.revision,
        policy_epoch: state.policy_epoch,
        schema_epoch: state.schema_epoch,
        batch_digest: batch.digest()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (TenantState, RequestContext, AdmitMutationCapacity) {
        let context = RequestContext {
            authorization: RequestAuthorization::service_identity(),
            principal: "fi-service".into(),
            tenant: "fi".into(),
            scopes: BTreeSet::from([Action::Read, Action::Write]),
            request_id: "data-admit".into(),
        };
        let engine = TenantEngine::new(
            "fi".into(),
            "incarnation".into(),
            Policy {
                grants: vec![
                    Grant {
                        principal: context.principal.clone(),
                        collection: Some("auth".into()),
                        actions: context.scopes.clone(),
                    },
                    // Native genesis requires a control-plane administrator.
                    // The tested FI service never receives this grant or scope.
                    Grant {
                        principal: "operator".into(),
                        collection: None,
                        actions: BTreeSet::from([Action::Admin]),
                    },
                ],
                strict_read_audit: false,
            },
            Limits::default(),
        )
        .unwrap();
        let state = engine.generation().unwrap().state.clone();
        let request = AdmitMutationCapacity {
            expected_incarnation: state.incarnation.clone(),
            batch: MutationBatch::with_key("future-security-effect")
                .read_set([ReadAssertion::Snapshot {
                    incarnation: state.incarnation.clone(),
                    policy_epoch: state.policy_epoch,
                    schema_epoch: state.schema_epoch,
                }])
                .insert("auth", "applied", json!({"phase":"applied"})),
        };
        (state, context, request)
    }

    #[test]
    fn security_phase_consumes_the_256th_operation() {
        let (state, context, mut request) = fixture();
        for index in 0..255 {
            request.batch =
                request
                    .batch
                    .insert("auth", format!("device-{index}"), json!({"retired":true}));
        }
        assert!(admit_mutation_capacity(&state, &context, &request).is_ok());
        request.batch = request
            .batch
            .insert("auth", "device-255", json!({"retired":true}));
        assert_eq!(
            admit_mutation_capacity(&state, &context, &request)
                .unwrap_err()
                .code,
            ErrorCode::ResourceExhausted
        );
    }

    #[test]
    fn current_tenant_byte_operation_and_document_limits_are_admitted() {
        let (mut state, context, mut request) = fixture();
        state.limits.max_batch_operations = 1;
        request.batch = request
            .batch
            .insert("auth", "device", json!({"retired":true}));
        assert!(admit_mutation_capacity(&state, &context, &request).is_err());
        state.limits.max_batch_operations = 256;
        state.limits.max_batch_bytes = encoded_len(&request.batch).unwrap() - 1;
        assert!(admit_mutation_capacity(&state, &context, &request).is_err());
        state.limits.max_batch_bytes += 1;
        assert!(admit_mutation_capacity(&state, &context, &request).is_ok());
        state.limits.max_document_bytes = 1;
        assert!(admit_mutation_capacity(&state, &context, &request).is_err());
    }

    #[test]
    fn snapshot_epoch_and_data_grants_cannot_be_substituted() {
        let (mut state, context, request) = fixture();
        assert!(admit_mutation_capacity(&state, &context, &request).is_ok());
        state.policy_epoch += 1;
        assert_eq!(
            admit_mutation_capacity(&state, &context, &request)
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        state.policy_epoch -= 1;
        let mut other = context.clone();
        other.principal = "other".into();
        assert_eq!(
            admit_mutation_capacity(&state, &other, &request)
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
        let mut other = request.clone();
        other.batch.operations[0] =
            Mutation::put("retail", "applied", json!({}), Precondition::Absent);
        assert_eq!(
            admit_mutation_capacity(&state, &context, &other)
                .unwrap_err()
                .code,
            ErrorCode::Forbidden
        );
    }

    #[test]
    fn read_assertion_capacity_and_full_document_requirement_are_checked() {
        let (state, context, mut request) = fixture();
        for index in 0..512 {
            request.batch.read_set.push(ReadAssertion::Document {
                collection: "auth".into(),
                id: format!("guard-{index}"),
                expected: ReadPrecondition::Absent,
            });
        }
        assert_eq!(
            admit_mutation_capacity(&state, &context, &request)
                .unwrap_err()
                .code,
            ErrorCode::ResourceExhausted
        );
        request.batch.read_set.pop();
        assert!(admit_mutation_capacity(&state, &context, &request).is_ok());
        request.batch.operations[0] = Mutation::Patch {
            collection: "auth".into(),
            id: "applied".into(),
            patch: json!({"phase":"applied"}),
            expected: Precondition::Any,
        };
        assert_eq!(
            admit_mutation_capacity(&state, &context, &request)
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn duplicate_native_read_identities_cannot_create_an_impossible_intent() {
        let (state, context, mut request) = fixture();
        request
            .batch
            .read_set
            .push(request.batch.read_set[0].clone());
        assert_eq!(
            admit_mutation_capacity(&state, &context, &request)
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
        request.batch.read_set.pop();
        for expected in [
            ReadPrecondition::Absent,
            ReadPrecondition::Version(u64::MAX),
        ] {
            request.batch.read_set.push(ReadAssertion::Document {
                collection: "auth".into(),
                id: "prepared".into(),
                expected,
            });
        }
        assert_eq!(
            admit_mutation_capacity(&state, &context, &request)
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
}
