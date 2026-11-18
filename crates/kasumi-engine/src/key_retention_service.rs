//! A page is an observation of the authenticated local catalogs and retained
//! tenant archive head. Every source outside that observation is explicit in
//! coverage. A page grants no provider mutation or retirement authority.
use super::*;

impl Database {
    pub async fn read_key_retention(
        &self,
        context: &RequestContext,
        request: ReadKeyRetentionRequest,
    ) -> Result<AdmittedOutput<KeyRetentionPage>> {
        let result = self.key_retention_page(context, &request).await;
        self.audit_result(context, result).await
    }

    async fn key_retention_page(
        &self,
        context: &RequestContext,
        request: &ReadKeyRetentionRequest,
    ) -> Result<AdmittedOutput<KeyRetentionPage>> {
        request.validate()?;
        self.access()?;
        self.engine.authorize(context, None, Action::Admin)?;
        let control = match &request.scope {
            KeyRetentionScope::Tenant { tenant }
                if tenant == &context.tenant && tenant != crate::control::CONTROL_TENANT =>
            {
                false
            }
            KeyRetentionScope::Control {} if context.tenant == crate::control::CONTROL_TENANT => {
                true
            }
            KeyRetentionScope::Tenant { .. } | KeyRetentionScope::Control {} => {
                return Err(Error::new(
                    ErrorCode::Forbidden,
                    "key retention scope differs from authorization",
                ));
            }
            _ => {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    "requested key retention scope requires its independent installed owner",
                ));
            }
        };
        let cancellation = QueryCancellation::default();
        let _cancel = CancelOnDrop(cancellation.clone());
        let registration = self.work.begin(cancellation.clone())?;
        // One extra ordered entry decides whether a continuation is needed.
        // Fund the original tree, cloned cursor, result vector and the largest
        // transient identity before reading either catalog.
        let budget = (u64::from(request.limit) + 4)
            * 2
            * (MAX_KEY_REF_BYTES + MAX_KEY_PROVIDER_BYTES + 1024) as u64
            + (256 << 10);
        let reservation = self
            .admission()
            .reserve(budget, Some(cancellation.clone()))?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        let state = &generation.state;
        if control {
            context.authorization.require_control(&state.incarnation)?;
        }
        let epoch = state.policy_epoch;
        self.engine
            .authorize_release(context, None, Action::Admin, epoch)?;
        let metrics = self.group.metrics();
        let membership = &metrics.membership_config;
        let membership_epoch = membership
            .log_id()
            .as_ref()
            .map_or(0, |position| position.index);
        if membership_epoch > metrics.last_applied.map_or(0, |position| position.index) {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "membership has not reached its applied position",
            ));
        }
        let local = self.group.node_id();
        if !membership.membership().nodes().any(|(&id, _)| id == local) {
            return Err(Error::new(
                ErrorCode::Unavailable,
                "local node lacks a current membership report",
            ));
        }
        let mut missing = BTreeSet::new();
        // This installation does not have an authoritative scope-wide index
        // of authenticated remote backup sessions and completed checkpoints.
        missing.insert(MissingKeyDependency::SessionIndexUnavailable {});
        if state.audit_retention.archive_segments > 1 {
            missing.insert(MissingKeyDependency::RecordUnreadable {
                record_kind: KeyReferenceKind::AuditArchive,
                id: "earlier-archive-segments".into(),
            });
        }
        if !state.history_archives.is_empty() {
            missing.insert(MissingKeyDependency::RecordUnreadable {
                record_kind: KeyReferenceKind::HistoryArchive,
                id: "history-object-catalogs".into(),
            });
        }
        if !state.recovery_control.is_empty() {
            missing.insert(MissingKeyDependency::RecordUnreadable {
                record_kind: KeyReferenceKind::RecoveryRecord,
                id: "recovery-key-dependencies".into(),
            });
        }
        let mut truncated = false;
        for (&node_id, _) in membership.membership().nodes() {
            if node_id != local {
                if missing.len() == MAX_MISSING_KEY_DEPENDENCIES {
                    truncated = true;
                    break;
                }
                missing.insert(MissingKeyDependency::MemberUnreported { node_id });
            }
        }
        let scope_hash = request.scope.sha256()?;
        let request = request.clone();
        let stores = self.stores.clone();
        let revision = state.revision;
        let strict = state.policy.strict_read_audit;
        let (page, mut reservation) = reservation
            .retained_read(cancellation, move |reservation, token| {
                let _registration = registration;
                let mut entries = BTreeSet::new();
                let mut consider = |entry: KeyRetentionEntry| -> Result<()> {
                    token.check()?;
                    entry.validate()?;
                    if request
                        .cursor
                        .as_ref()
                        .is_none_or(|cursor| entry > cursor.after)
                    {
                        entries.insert(entry);
                        if entries.len() > usize::from(request.limit) + 1 {
                            entries.pop_last();
                        }
                    }
                    Ok(())
                };
                let digest = stores
                    .visit_key_retention_catalogs(
                        |custody, catalog_id, provider, key_ref, version| {
                            anyhow::ensure!(
                                provider.len() <= MAX_KEY_PROVIDER_BYTES
                                    && key_ref.len() <= MAX_KEY_REF_BYTES,
                                "catalog identity exceeds key retention bounds"
                            );
                            let domain = if custody {
                                KeyCatalogDomain::RetirementCustody
                            } else if control {
                                KeyCatalogDomain::NodeControl
                            } else {
                                KeyCatalogDomain::Application
                            };
                            consider(KeyRetentionEntry {
                                key: KeyVersionRef {
                                    provider: provider.into(),
                                    key_ref: key_ref.into(),
                                    version,
                                },
                                reference: KeyReference::Catalog {
                                    node_id: local,
                                    catalog_id,
                                    domain,
                                },
                            })?;
                            Ok(())
                        },
                    )
                    .map_err(|error| {
                        error.downcast_ref::<Error>().cloned().unwrap_or_else(|| {
                            Error::new(ErrorCode::Unavailable, error.to_string())
                        })
                    })?;
                let state = &generation.state;
                if let Some(head) = &state.audit_retention.archive_head {
                    consider(KeyRetentionEntry {
                        key: KeyVersionRef::from(&head.key),
                        reference: KeyReference::AuditArchive {
                            stream_id: head.stream_id,
                            first_sequence: head.object.first_sequence,
                        },
                    })?;
                }
                let inventory_sha256 = staged_digest(&(
                    "kasumi.key-retention.local.v1",
                    &scope_hash,
                    &state.incarnation,
                    epoch,
                    membership_epoch,
                    local,
                    digest,
                    &state.audit_retention.archive_head,
                    &missing,
                    truncated,
                ))?
                .0;
                // Strict read auditing may advance the application revision between
                // pages. Keep the original revision only if the observed inventory
                // and membership still match, including catalog-only rotations.
                let coverage_revision = if let Some(cursor) = &request.cursor {
                    if cursor.inventory_sha256 != inventory_sha256
                        || cursor.membership_epoch != membership_epoch
                        || cursor.coverage_revision > revision
                    {
                        return Err(Error::new(
                            ErrorCode::CursorExpired,
                            "key retention inventory changed",
                        ));
                    }
                    cursor.coverage_revision
                } else {
                    revision
                };
                let mut page_entries =
                    Vec::with_capacity(entries.len().min(usize::from(request.limit)));
                let mut bytes = 0;
                let mut more = false;
                for entry in entries {
                    let encoded = crate::accounting::encoded_len(&entry)?;
                    // Leave room for the full cursor (which repeats the final
                    // entry), missing-dependency list and framing. Strings may
                    // expand sixfold under JSON escaping.
                    if page_entries.len() == usize::from(request.limit)
                        || bytes + encoded + 1 > MAX_KEY_RETENTION_PAGE_BYTES - (128 << 10)
                    {
                        more = true;
                        break;
                    }
                    bytes += encoded + 1;
                    page_entries.push(entry);
                }
                let next_cursor = if more {
                    Some(KeyRetentionCursor {
                        scope_sha256: scope_hash,
                        inventory_sha256,
                        membership_epoch,
                        coverage_revision,
                        after: page_entries
                            .last()
                            .ok_or_else(|| {
                                Error::new(
                                    ErrorCode::ResourceExhausted,
                                    "key retention entry exceeds response bound",
                                )
                            })?
                            .clone(),
                    })
                } else {
                    None
                };
                let page = KeyRetentionPage {
                    entries: page_entries,
                    next_cursor,
                    coverage: KeyRetentionCoverage::Incomplete {
                        coverage_revision,
                        membership_epoch,
                        missing: missing.into_iter().collect(),
                        truncated,
                    },
                };
                if crate::accounting::encoded_len(&page)? > MAX_KEY_RETENTION_PAGE_BYTES {
                    return Err(Error::new(
                        ErrorCode::ResourceExhausted,
                        "key retention page exceeds response bound",
                    ));
                }
                page.validate(&request)?;
                Ok((page, reservation))
            })
            .await?;
        reservation.retain_workspace();
        self.release_event(context, None, revision, strict, epoch, "read_key_retention")
            .await?;
        self.engine
            .authorize_release(context, None, Action::Admin, epoch)?;
        self.access()?;
        Ok(AdmittedOutput::new(page, Arc::new(reservation)))
    }
}
