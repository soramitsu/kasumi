//! Authorized embedded read, write and query operations shared by both native drivers.
use crate::{Measurement, Samples, raw::document_body as body};
use anyhow::Result;
use kasumi_engine::Database;
use kasumi_types::*;
use serde_json::json;
use std::{hint::black_box, sync::Arc, time::Instant};

#[derive(Clone, Copy)]
pub struct Dimensions {
    pub documents: usize,
    pub operations: usize,
    pub retain_samples: bool,
}

pub trait EmbeddedDatabases {
    fn tenant_count(&self) -> usize;
    fn context(&self, tenant: usize) -> RequestContext;
    fn write_key(&self, phase: usize, operation: usize) -> String {
        format!("work-{phase}-{operation}")
    }
    fn leader(&self, tenant: usize) -> impl std::future::Future<Output = Result<Arc<Database>>>;
}

pub fn definition(text: bool) -> CollectionDefinition {
    let mut indexes = vec![IndexDefinition {
        name: "ordinal".into(),
        fields: vec![IndexField {
            path: "/ordinal".into(),
            kind: ScalarType::Number,
        }],
        unique: false,
        text: None,
    }];
    if text {
        for (name, analyzer) in [
            ("english", Analyzer::EnglishV1),
            ("japanese", Analyzer::JapaneseV1),
        ] {
            indexes.push(IndexDefinition {
                name: name.into(),
                fields: vec![IndexField {
                    path: "/text".into(),
                    kind: ScalarType::String,
                }],
                unique: false,
                text: Some(TextIndex { analyzer }),
            });
        }
    }
    CollectionDefinition {
        retention_class: kasumi_types::CollectionRetentionClass::Operational,
        write_mode: kasumi_types::CollectionWriteMode::Mutable,
        name: "docs".into(),
        schema: json!({"type":"object","required":["ordinal","version","text","padding"],"properties":{"ordinal":{"type":"integer"},"version":{"type":"integer"},"text":{"type":"string"},"padding":{"type":"string"}},"additionalProperties":false}),
        indexes,
        strict_read_audit: false,
    }
}
pub async fn workload(
    databases: &impl EmbeddedDatabases,
    options: Dimensions,
    name: &str,
    write_percent: usize,
    phase: usize,
) -> Measurement {
    let mut samples = Samples::new(name, options.operations);
    for operation in 0..options.operations {
        let ordinal = operation.wrapping_mul(7919) % options.documents;
        let tenant = ordinal % databases.tenant_count();
        let selection = Instant::now();
        let database = match databases.leader(tenant).await {
            Ok(database) => database,
            Err(error) => {
                samples.record(selection.elapsed(), Err(error));
                break;
            }
        };
        let context = databases.context(tenant);
        let id = ordinal.to_string();
        let start = Instant::now();
        let result: Result<()> = async {
            if (operation + 1) * write_percent / 100 > operation * write_percent / 100 {
                database
                    .mutate(
                        context,
                        MutationBatch {
                            read_set: Vec::new(),
                            idempotency_key: databases.write_key(phase, operation),
                            operations: vec![Mutation::Put {
                                collection: "docs".into(),
                                id,
                                body: body(
                                    ordinal,
                                    phase * options.operations + operation + 1,
                                    databases.tenant_count(),
                                ),
                                expected: Precondition::Any,
                            }],
                        },
                    )
                    .await?;
            } else if name == "embedded_authorized_shared_point_get" {
                black_box(
                    database
                        .get_shared(&context, "docs", &id)
                        .await?
                        .ok_or_else(|| {
                            Error::new(ErrorCode::NotFound, "benchmark document is missing")
                        })?,
                );
            } else {
                black_box(database.get(&context, "docs", &id).await?.ok_or_else(|| {
                    Error::new(ErrorCode::NotFound, "benchmark document is missing")
                })?);
            }
            Ok(())
        }
        .await;
        if !samples.record(start.elapsed(), result) {
            break;
        }
    }
    samples.finish_with_samples(options.retain_samples)
}
pub async fn queries(
    databases: &impl EmbeddedDatabases,
    options: Dimensions,
    text: Option<TextSearch>,
) -> Measurement {
    let name = text
        .as_ref()
        .map(|text| format!("text_{}_{:?}_complete_pages", text.index, text.mode))
        .unwrap_or_else(|| "structured_indexed_equality".into());
    let mut samples = Samples::new(name, options.operations);
    for operation in 0..options.operations {
        let ordinal = operation.wrapping_mul(7919) % options.documents;
        let tenant = ordinal % databases.tenant_count();
        let selection = Instant::now();
        let database = match databases.leader(tenant).await {
            Ok(database) => database,
            Err(error) => {
                samples.record(selection.elapsed(), Err(error));
                break;
            }
        };
        let filter = match &text {
            None => Filter::new().eq("/ordinal", ordinal),
            Some(_) => Filter::new(),
        };
        let mut page = QueryRequest::new("docs")
            .filter(filter)
            .select(["/ordinal"])
            .limit(1000);
        page.search = text.clone();
        let identity = databases.context(tenant);
        let start = Instant::now();
        let result: Result<()> = async {
            loop {
                let response = database.query(&identity, page.clone()).await?;
                let cursor = response.cursor.clone();
                black_box(response);
                if let Some(cursor) = cursor {
                    page.cursor = Some(cursor);
                } else {
                    break;
                }
            }
            Ok(())
        }
        .await;
        if !samples.record(start.elapsed(), result) {
            break;
        }
    }
    samples.finish_with_samples(options.retain_samples)
}
