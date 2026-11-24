use crate::{ClientError, KasumiAdminClient, proto};
use kasumi_types::{
    MAX_REMOTE_BACKUP_BYTES, RemoteBackupChallenge, RemoteBackupCommand, RemoteBackupConfirmation,
    RemoteBackupRecord,
};
use serde::{Serialize, de::DeserializeOwned};
use std::time::Duration;

// One bytes field has a one-byte tag and at most four bytes of length at
// this limit. Bound Tonic's wire allocation before decoding the JSON.
const MAX_PROTOBUF_BYTES: usize = MAX_REMOTE_BACKUP_BYTES + 5;

fn request(input: &impl Serialize) -> Result<proto::PrivateReadJsonRequest, ClientError> {
    let request_json = crate::encode(input)?;
    if request_json.len() > MAX_REMOTE_BACKUP_BYTES {
        return Err(ClientError::RequestTooLarge);
    }
    Ok(proto::PrivateReadJsonRequest { request_json })
}

fn decode<T: DeserializeOwned>(reply: proto::PrivateReadJsonResponse) -> Result<T, ClientError> {
    if reply.response_json.len() > MAX_REMOTE_BACKUP_BYTES {
        return Err(ClientError::InvalidResponse(
            "backup response exceeds byte limit",
        ));
    }
    Ok(serde_json::from_slice(&reply.response_json)?)
}

impl KasumiAdminClient {
    pub async fn exchange_backup_binding(
        &mut self,
        bearer: &str,
        input: &RemoteBackupCommand,
    ) -> Result<Option<RemoteBackupRecord>, ClientError> {
        input
            .validate()
            .map_err(|_| ClientError::InvalidResponse("invalid backup operation"))?;
        let mut request = self.authorized(bearer, request(input)?)?;
        request.set_timeout(Duration::from_secs(30));
        let reply = self
            .inner
            .clone()
            .max_decoding_message_size(MAX_PROTOBUF_BYTES)
            .exchange_backup_binding(request)
            .await?;
        let observed: Option<RemoteBackupRecord> = decode(reply.into_inner())?;
        if let Some(record) = &observed {
            record
                .validate()
                .map_err(|_| ClientError::InvalidResponse("invalid backup record"))?;
            if record.record.claim.session_id != input.reference.session
                || record.record.claim.tenant != input.reference.tenant
            {
                return Err(ClientError::InvalidResponse("different backup record"));
            }
        }
        Ok(observed)
    }

    pub async fn read_backup_inventory(
        &mut self,
        bearer: &str,
        command: &kasumi_types::BackupInventoryCommand,
    ) -> Result<kasumi_types::BackupInventoryPage, ClientError> {
        command
            .validate()
            .map_err(|_| ClientError::InvalidResponse("invalid backup inventory command"))?;
        let mut request = self.authorized(bearer, request(command)?)?;
        request.set_timeout(Duration::from_secs(30));
        let reply = self
            .inner
            .clone()
            .max_decoding_message_size(MAX_PROTOBUF_BYTES)
            .read_backup_inventory(request)
            .await?;
        let page: kasumi_types::BackupInventoryPage = decode(reply.into_inner())?;
        page.validate(command)
            .map_err(|_| ClientError::InvalidResponse("different backup inventory page"))?;
        Ok(page)
    }

    pub async fn confirm_backup_source(
        &mut self,
        bearer: &str,
        input: &RemoteBackupChallenge,
    ) -> Result<RemoteBackupConfirmation, ClientError> {
        let mut request = self.authorized(bearer, request(input)?)?;
        request.set_timeout(Duration::from_secs(10));
        let reply = self
            .inner
            .clone()
            .max_decoding_message_size(MAX_PROTOBUF_BYTES)
            .confirm_backup_source(request)
            .await?;
        let confirmation: RemoteBackupConfirmation = decode(reply.into_inner())?;
        confirmation
            .validate()
            .map_err(|_| ClientError::InvalidResponse("invalid backup source observation"))?;
        if confirmation.original != *input {
            return Err(ClientError::InvalidResponse(
                "backup source observation differs from challenge",
            ));
        }
        Ok(confirmation)
    }
}
