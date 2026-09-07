use super::*;

impl Database {
    pub async fn activate_schema(
        &self,
        context: RequestContext,
        request: SchemaChangeSet,
    ) -> Result<WriteReceipt> {
        let result = async {
            let receipt = self
                .administer(context.clone(), Operation::ActivateSchema(request.clone()))
                .await?;
            let release = self
                .schema_activation_response_fence(&context, &request)
                .and_then(|fence| fence.check());
            self.audit_result(&context, release)
                .await
                .map_err(schema_acknowledgement)?;
            Ok(receipt)
        }
        .await;
        let receipt = self.audit_write_result(&context, result).await?;
        self.schema_activation_response_fence(&context, &request)
            .and_then(|fence| fence.check())
            .map_err(schema_acknowledgement)?;
        Ok(receipt)
    }

    /// Capture the acknowledgement epoch before rechecking current authority.
    /// Adapters retain this fence through serialization and authorized handoff.
    pub fn schema_activation_response_fence(
        &self,
        context: &RequestContext,
        request: &SchemaChangeSet,
    ) -> Result<ResponseFence<'_>> {
        let reference = request.reference()?;
        // Only the original deadline survives this transition. Its Snapshot
        // described pre-activation state, whose schema/policy epochs advanced.
        let deadlines = request
            .read_set
            .iter()
            .filter(|a| matches!(a, ReadAssertion::Before { .. }))
            .cloned()
            .collect::<Vec<_>>();
        let fence = self.schema_read_response_fence(context, &deadlines)?;
        crate::state::schema::lookup(&self.engine.generation()?.state, context, &reference)?;
        fence.check()?;
        Ok(fence)
    }

    fn schema_read_response_fence(
        &self,
        context: &RequestContext,
        assertions: &[ReadAssertion],
    ) -> Result<ResponseFence<'_>> {
        let mut fence = self.response_fence(context)?;
        if assertions.len() > MAX_SCHEMA_READ_ASSERTIONS
            || staged_digest(&assertions)?.1 > MAX_SCHEMA_CHANGESET_BYTES
        {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "schema admission exceeds bounds",
            ));
        }
        let charge = staged_digest(&assertions)?
            .1
            .saturating_mul(3)
            .saturating_add(assertions.len().saturating_mul(128)) as u64;
        let mut workspace = self
            .admission()
            .reserve(charge.max(1), Some(fence.cancellation.clone()))?;
        workspace.retain(charge.max(1));
        fence.schema_admission = Some((assertions.to_vec(), workspace));
        fence.check()?;
        Ok(fence)
    }

    /// Current lookup admission is independent of the historical effect and
    /// remains attached through the adapter's encoded response handoff.
    pub fn schema_status_response_fence(
        &self,
        context: &RequestContext,
        request: &ReadSchemaActivation,
    ) -> Result<ResponseFence<'_>> {
        self.schema_read_response_fence(context, &request.read_set)
    }

    pub async fn read_schema(
        &self,
        context: &RequestContext,
        request: ReadSchema,
    ) -> Result<SchemaSnapshot> {
        let result = self.read_schema_inner(context, request).await;
        self.audit_result(context, result).await
    }

    async fn read_schema_inner(
        &self,
        context: &RequestContext,
        request: ReadSchema,
    ) -> Result<SchemaSnapshot> {
        self.access()?;
        if request.collections.is_empty()
            || request.collections.len() > MAX_SCHEMA_CHANGESET_COLLECTIONS
        {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "schema snapshot targets outside bounds",
            ));
        }
        for name in &request.collections {
            validate_name(name)?;
            self.engine.authorize(context, Some(name), Action::Admin)?;
        }
        let mut reservation = self
            .admission()
            .reserve((MAX_SCHEMA_CHANGESET_BYTES * 3 + (1 << 20)) as u64, None)?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        let mut bytes = 0usize;
        for name in &request.collections {
            self.engine.authorize_release(
                context,
                Some(name),
                Action::Admin,
                generation.state.policy_epoch,
            )?;
            if let Some(collection) = generation.state.collections.get(name) {
                bytes =
                    bytes.saturating_add(crate::accounting::encoded_len(&collection.definition)?);
            }
        }
        if bytes > MAX_SCHEMA_CHANGESET_BYTES {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "schema snapshot metadata exceeds byte budget; request fewer names",
            ));
        }
        let snapshot = SchemaSnapshot {
            incarnation: generation.state.incarnation.clone(),
            revision: generation.state.revision,
            policy_epoch: generation.state.policy_epoch,
            schema_epoch: generation.state.schema_epoch,
            collections: request
                .collections
                .iter()
                .map(|name| {
                    (
                        name.clone(),
                        generation
                            .state
                            .collections
                            .get(name)
                            .map(|collection| SchemaCollection {
                                definition: collection.definition.clone(),
                                data_epoch: collection.data_epoch,
                                archived_document_count: collection.archived_documents.len() as u64,
                            }),
                    )
                })
                .collect(),
        };
        drop(generation);
        reservation.retain_workspace();
        for collection in &request.collections {
            self.release_event(
                context,
                Some(collection),
                snapshot.revision,
                true,
                snapshot.policy_epoch,
                "schema_read",
            )
            .await?;
        }
        self.access()?;
        Ok(snapshot)
    }

    pub async fn schema_activation_status(
        &self,
        context: &RequestContext,
        request: &ReadSchemaActivation,
    ) -> Result<SchemaActivationStatus> {
        let fence = self.schema_status_response_fence(context, request);
        let result = match &fence {
            Ok(_) => self.schema_activation_status_inner(context, request).await,
            Err(error) => Err(error.clone()),
        };
        let audited = self.audit_result(context, result).await;
        if let Ok(fence) = fence {
            fence.check()?;
        }
        audited
    }

    async fn schema_activation_status_inner(
        &self,
        context: &RequestContext,
        request: &ReadSchemaActivation,
    ) -> Result<SchemaActivationStatus> {
        self.access()?;
        self.engine
            .authorize_discovery(context, Action::Admin, None)?;
        let mut reservation = self.admission().reserve(1 << 20, None)?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        let now = self
            .command_clock
            .lock()
            .map_err(|_| Error::new(ErrorCode::Unavailable, "command clock unavailable"))?
            .now_ms()?;
        crate::state::schema::validate_admission(
            &generation.state,
            context,
            &request.read_set,
            now,
        )?;
        let record = crate::state::schema::lookup(&generation.state, context, &request.reference)?;
        let status = SchemaActivationStatus {
            request_digest: record.request_digest.clone(),
            outcome: record.outcome.clone(),
        };
        let collections = record.collections.clone();
        let epoch = generation.state.policy_epoch;
        let revision = generation.state.revision;
        drop(generation);
        reservation.retain_workspace();
        // Administrative activation outcomes always have durable release audits,
        // including failed requests for collections that were never created.
        for collection in collections {
            self.release_event(
                context,
                Some(&collection),
                revision,
                true,
                epoch,
                "schema_activation_status",
            )
            .await?;
        }
        self.access()?;
        crate::state::schema::lookup(
            &self.engine.generation()?.state,
            context,
            &request.reference,
        )?;
        Ok(status)
    }
}

// This path is reached only after the original effect succeeded. An expired
// Before assertion or changed release policy must not look like a rejected
// activation: its permanent identity is the authoritative recovery path.
fn schema_acknowledgement(error: Error) -> Error {
    if matches!(error.code, ErrorCode::Conflict | ErrorCode::Unauthorized) {
        Error::new(
            ErrorCode::UnknownOutcome,
            "schema response release was fenced; resolve the original activation with current lookup admission",
        )
    } else {
        error
    }
}
