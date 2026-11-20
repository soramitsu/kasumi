use crate::{ClientError, KasumiAdminClient, proto};
use kasumi_types::{DATA_MEMBER_CATALOG_BYTES, DataMemberCatalogPage, DataMemberCatalogRead};
use std::time::Duration;

impl KasumiAdminClient {
    pub async fn read_data_member_catalog(
        &mut self,
        bearer: &str,
        input: &DataMemberCatalogRead,
    ) -> Result<DataMemberCatalogPage, ClientError> {
        input
            .validate()
            .map_err(|_| ClientError::InvalidResponse("invalid Data catalog read"))?;
        let request_json = crate::encode(input)?;
        if request_json.len() > DATA_MEMBER_CATALOG_BYTES {
            return Err(ClientError::RequestTooLarge);
        }
        let mut request =
            self.authorized(bearer, proto::PrivateReadJsonRequest { request_json })?;
        request.set_timeout(Duration::from_secs(10));
        let reply = self
            .inner
            .clone()
            .max_decoding_message_size(DATA_MEMBER_CATALOG_BYTES + 5)
            .read_data_member_catalog(request)
            .await?
            .into_inner();
        if reply.response_json.len() > DATA_MEMBER_CATALOG_BYTES {
            return Err(ClientError::InvalidResponse(
                "Data service inventory exceeds byte bound",
            ));
        }
        let page: DataMemberCatalogPage = serde_json::from_slice(&reply.response_json)?;
        page.validate(input).map_err(|_| {
            ClientError::InvalidResponse("Data service inventory differs from request")
        })?;
        Ok(page)
    }
}
