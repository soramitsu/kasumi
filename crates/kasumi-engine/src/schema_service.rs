use super::*;

impl Database {
    pub async fn activate_schema(
        &self,
        context: RequestContext,
        request: SchemaChangeSet,
    ) -> Result<WriteReceipt> {
        let reference = request.reference()?;
        let result = async {
            let receipt = self
                .administer(context.clone(), Operation::ActivateSchema(request))
                .await?;
            self.schema_activation_response_fence(&context, &reference)?
                .check()?;
            Ok(receipt)
        }
        .await;
        self.audit_result(&context, result).await
    }

    /// Capture the acknowledgement epoch before rechecking current authority.
    /// Adapters retain this fence through serialization and authorized handoff.
    pub fn schema_activation_response_fence(
        &self,
        context: &RequestContext,
        reference: &SchemaActivationRef,
    ) -> Result<ResponseFence<'_>> {
        let fence = self.response_fence(context)?;
        crate::state::schema::lookup(&self.engine.generation()?.state, context, reference)?;
        fence.check()?;
        Ok(fence)
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
        reference: &SchemaActivationRef,
    ) -> Result<SchemaActivationStatus> {
        let result = self
            .schema_activation_status_inner(context, reference)
            .await;
        self.audit_result(context, result).await
    }

    async fn schema_activation_status_inner(
        &self,
        context: &RequestContext,
        reference: &SchemaActivationRef,
    ) -> Result<SchemaActivationStatus> {
        self.access()?;
        self.engine
            .authorize_discovery(context, Action::Admin, None)?;
        let mut reservation = self.admission().reserve(1 << 20, None)?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        let record = crate::state::schema::lookup(&generation.state, context, reference)?;
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
        crate::state::schema::lookup(&self.engine.generation()?.state, context, reference)?;
        Ok(status)
    }
}
