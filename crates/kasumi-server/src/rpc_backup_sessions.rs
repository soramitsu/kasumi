use super::*;
#[derive(Clone, Copy)]
pub(super) enum SessionOperation {
    Status,
    Abort,
    Cleanup,
}
impl NativeAdmin {
    pub(super) async fn backup_session_rpc(
        &self,
        request: Request<BackupSessionJsonRequest>,
        operation: SessionOperation,
    ) -> Result<Response<BackupSessionJsonResponse>, Status> {
        let context = verified(&self.auth, &request).await?;
        let payload = request.into_inner().request_json;
        let database = self.database(&context).await?;
        let fence = self
            .auth
            .audit_result(&context, database.response_fence(&context))
            .await
            .map_err(status)?;
        let mutation = !matches!(operation, SessionOperation::Status);
        let result = match operation {
            SessionOperation::Status => database
                .backup_session_status(context.clone(), decode_json(&payload).map_err(status)?)
                .await
                .and_then(|value| encode_json(&value)),
            SessionOperation::Abort => database
                .abort_backup_session(context.clone(), decode_json(&payload).map_err(status)?)
                .await
                .and_then(|value| encode_json(&value)),
            SessionOperation::Cleanup => database
                .cleanup_backup_session(context.clone(), decode_json(&payload).map_err(status)?)
                .await
                .and_then(|value| encode_json(&value)),
        };
        let result = if mutation {
            mutation_release(result)
        } else {
            result
        };
        let response_json = result.map_err(|error| self.registry.status(&context, error))?;
        Ok(Response::new(
            release_response(
                &self.auth,
                &context,
                fence,
                BackupSessionJsonResponse { response_json },
                mutation,
            )
            .await
            .map_err(status)?,
        ))
    }
}
