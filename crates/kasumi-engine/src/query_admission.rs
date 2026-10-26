//! Queue only admitted request backing before taking one of the existing four
//! query worker permits. Candidate/output workspace starts after that wait.
use super::proposal_input::{retained_json_bytes, retained_string_bytes, tree};
use super::*;

pub(super) struct WaitingQuery {
    pub request: QueryRequest,
    registration: Arc<WorkRegistration>,
    bytes: u64,
    // Original request and registration must retire before their funding.
    reservation: Reservation,
}

impl WaitingQuery {
    pub fn admit(
        node: &Arc<NodeAdmission>,
        fence: &Arc<WorkFence>,
        request: QueryRequest,
        cancellation: &QueryCancellation,
    ) -> Result<Self> {
        let bytes = request_bytes(&request)?;
        let reservation = node.reserve_waiting(bytes, Some(cancellation.clone()))?;
        let registration = match fence.begin(cancellation.clone()) {
            Ok(registration) => Arc::new(registration),
            Err(error) => {
                // Parameters normally drop after locals; retire the admitted
                // request explicitly before its local reservation on refusal.
                drop(request);
                return Err(error);
            }
        };
        Ok(Self {
            request,
            registration,
            bytes,
            reservation,
        })
    }

    pub fn into_input(
        self,
        node: &Arc<NodeAdmission>,
        workspace: u64,
        cancellation: &QueryCancellation,
    ) -> Result<(QueryInput, Arc<WorkRegistration>)> {
        let total = add(workspace, self.bytes)?;
        let reservation = node.reserve(total, Some(cancellation.clone()))?;
        let mut memory = QueryMemory::empty(reservation);
        // Retained spare capacity stays live through worker planning; it is
        // not candidate/output workspace that the planner may spend again.
        memory.reserve(self.bytes)?;
        let Self {
            request,
            registration,
            reservation: waiting,
            ..
        } = self;
        let input = QueryInput { request, memory };
        drop(waiting);
        Ok((input, registration))
    }
}

pub(super) fn deadline_error() -> Error {
    Error::new(ErrorCode::ResourceExhausted, "query deadline exceeded")
}

pub(super) async fn permit(
    slots: &Arc<tokio::sync::Semaphore>,
    cancellation: &QueryCancellation,
    deadline: tokio::time::Instant,
) -> Result<tokio::sync::OwnedSemaphorePermit> {
    let permit = tokio::select! {
        result = tokio::time::timeout_at(deadline, slots.clone().acquire_owned()) => {
            result.map_err(|_| deadline_error())?
                .map_err(|_| Error::new(ErrorCode::Sealed, "query workers sealed"))?
        }
        _ = cancelled(cancellation) => return Err(cancelled_error()),
    };
    cancellation.check()?;
    if tokio::time::Instant::now() >= deadline {
        return Err(deadline_error());
    }
    Ok(permit)
}

fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(query_workspace_overflow)
}

fn filter_bytes(filter: &Filter, depth: usize) -> Result<u64> {
    if depth > 128 {
        return Err(query_workspace_overflow());
    }
    let mut bytes = tree::<String, Condition>(filter.fields.len().max(1))?;
    for (key, condition) in &filter.fields {
        bytes = add(bytes, retained_string_bytes(key)?)?;
        for value in [
            &condition.eq,
            &condition.ne,
            &condition.gt,
            &condition.gte,
            &condition.lt,
            &condition.lte,
            &condition.contains,
        ]
        .into_iter()
        .flatten()
        {
            bytes = add(bytes, retained_json_bytes(value, depth + 1)?)?;
        }
        for values in [&condition.r#in, &condition.nin].into_iter().flatten() {
            bytes = add(
                bytes,
                kasumi_query::vec_bytes::<serde_json::Value>(values.capacity())?,
            )?;
            for value in values {
                bytes = add(bytes, retained_json_bytes(value, depth + 1)?)?;
            }
        }
    }
    for children in [&filter.and, &filter.or] {
        bytes = add(
            bytes,
            kasumi_query::vec_bytes::<Filter>(children.capacity())?,
        )?;
        for child in children {
            bytes = add(bytes, filter_bytes(child, depth + 1)?)?;
        }
    }
    if let Some(child) = &filter.not {
        bytes = add(bytes, kasumi_query::vec_bytes::<Filter>(1)?)?;
        bytes = add(bytes, filter_bytes(child, depth + 1)?)?;
    }
    Ok(bytes)
}

fn request_bytes(request: &QueryRequest) -> Result<u64> {
    // Semaphore waiter, cancellation, registration and request/future controls.
    let mut bytes = add(16 << 10, retained_string_bytes(&request.collection)?)?;
    bytes = add(bytes, filter_bytes(&request.filter, 0)?)?;
    if let Some(search) = &request.search {
        bytes = add(
            add(bytes, retained_string_bytes(&search.index)?)?,
            retained_string_bytes(&search.query)?,
        )?;
    }
    bytes = add(
        bytes,
        kasumi_query::vec_bytes::<Sort>(request.sort.capacity())?,
    )?;
    for sort in &request.sort {
        bytes = add(bytes, retained_string_bytes(&sort.field)?)?;
    }
    for fields in [&request.select, &request.group_by] {
        bytes = add(bytes, kasumi_query::vec_bytes::<String>(fields.capacity())?)?;
        for field in fields {
            bytes = add(bytes, retained_string_bytes(field)?)?;
        }
    }
    bytes = add(
        bytes,
        tree::<String, Aggregation>(request.aggregate.len().max(1))?,
    )?;
    for (alias, aggregate) in &request.aggregate {
        bytes = add(bytes, retained_string_bytes(alias)?)?;
        if let Some(field) = &aggregate.field {
            bytes = add(bytes, retained_string_bytes(field)?)?;
        }
    }
    if let Some(cursor) = &request.cursor {
        bytes = add(bytes, retained_string_bytes(cursor)?)?;
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "query_admission_tests.rs"]
mod tests;
