//! Linearizable Data listener admission under the caller's existing data grants.
use super::*;

impl Database {
    /// Prove the complete future batch fits hard and current tenant shape limits
    /// before an application publishes a durable security intent or barrier.
    pub async fn admit_mutation_capacity(
        &self,
        context: &RequestContext,
        request: AdmitMutationCapacity,
    ) -> Result<AdmittedOutput<MutationCapacityAdmission>> {
        let result = self.admit_mutation_capacity_inner(context, request).await;
        self.audit_result(context, result).await
    }

    async fn admit_mutation_capacity_inner(
        &self,
        context: &RequestContext,
        request: AdmitMutationCapacity,
    ) -> Result<AdmittedOutput<MutationCapacityAdmission>> {
        self.access()?;
        let bytes = crate::accounting::encoded_len(&request)?;
        if bytes > 8 << 20 {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "mutation admission request exceeds hard bound",
            ));
        }
        let mut reservation = self.admission().reserve(
            (bytes as u64)
                .saturating_mul(3)
                .saturating_add(4096 + OUTPUT_CHARGE_BYTES),
            None,
        )?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        let admitted = crate::state::admit_mutation_capacity(&generation.state, context, &request)?;
        let mut strict = generation.state.policy.strict_read_audit;
        // Validate complete future originals under the installed schema, without
        // executing them. The current precondition/late-bound Prepared revision
        // is still the effect owner's responsibility at actual atomic dispatch.
        for operation in &request.batch.operations {
            let (name, id) = operation.target();
            let collection = generation.state.collections.get(name).ok_or_else(|| {
                Error::new(
                    ErrorCode::NotFound,
                    "future mutation collection is not installed",
                )
            })?;
            strict |= collection.definition.strict_read_audit;
            if collection.archived_documents.contains_key(id) {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "future mutation targets an archived original",
                ));
            }
            if collection.definition.write_mode == CollectionWriteMode::AppendOnly
                && !matches!(operation, Mutation::Put { expected: Precondition::Absent, .. } if !collection.documents.contains_key(id))
            {
                return Err(Error::new(
                    ErrorCode::Forbidden,
                    "future mutation cannot replace append-only history",
                ));
            }
            if let Mutation::Put { body, .. } = operation {
                generation
                    .indexes
                    .validate_document(&collection.definition, body)?;
            }
        }
        for assertion in &request.batch.read_set {
            if let ReadAssertion::Document { collection, .. }
            | ReadAssertion::Collection { collection, .. } = assertion
            {
                let retained = generation
                    .state
                    .collections
                    .get(collection)
                    .ok_or_else(|| {
                        Error::new(
                            ErrorCode::NotFound,
                            "future mutation read collection is not installed",
                        )
                    })?;
                strict |= retained.definition.strict_read_audit;
            }
        }
        let epoch = generation.state.policy_epoch;
        for operation in &request.batch.operations {
            self.engine.authorize_release(
                context,
                Some(operation.target().0),
                Action::Write,
                epoch,
            )?;
        }
        drop(generation);
        self.release_event(
            context,
            None,
            admitted.revision,
            strict,
            epoch,
            "mutation_capacity_admission",
        )
        .await?;
        self.access()?;
        reservation.retain_workspace();
        Ok(AdmittedOutput::new(admitted, Arc::new(reservation)))
    }
}
