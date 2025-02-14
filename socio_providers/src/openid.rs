use serde::{Deserialize, Serialize};
use socio::{
    async_trait, error,
    jwt::verify_jwt_with_jwks_endpoint,
    providers::{SocioProvider, StandardUser},
    types::{OpenIdTokenField, Response, SocioClient},
};

#[derive(Debug)]
pub struct OpenId {
    pub jwks_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenIdClaims(serde_json::Value);

impl OpenId {
    pub fn new(jwks_uri: String) -> Self {
        Self { jwks_uri }
    }
}

#[async_trait]
impl SocioProvider for OpenId {
    async fn exchange_code_standard(
        &self,
        client: &SocioClient,
        code: socio::oauth2::AuthorizationCode,
        pkce_verifier: socio::oauth2::PkceCodeVerifier,
    ) -> error::Result<Response<StandardUser>> {
        let response = client
            .exchange_code::<OpenIdTokenField>(code, pkce_verifier)
            .await?;

        let token = verify_jwt_with_jwks_endpoint::<StandardUser>(
            &response.extra_fields().id_token,
            &self.jwks_uri,
            &client.client_id,
        )
        .await?;

        Ok(Response::from_standard_token_response(
            &response,
            token.claims,
        ))
    }
}
