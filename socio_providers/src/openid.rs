use serde::{Deserialize, Serialize};
use socio::{
    async_trait, error,
    jwt::verify_jwt_with_jwks_endpoint,
    providers::{SocioProvider, StandardUser, UserAwareSocioProvider},
    types::{OpenIdTokenField, Response, SocioClient},
};
use url::Url;

#[derive(Clone, Debug)]
pub struct OpenId {
    pub jwks_url: Url,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OpenIdClaims(serde_json::Value);

impl OpenId {
    pub fn new(jwks_url: Url) -> Self {
        Self { jwks_url }
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
            &self.jwks_url.as_str(),
            &client.client_id,
        )
        .await?;

        Ok(Response::from_standard_token_response(
            &response,
            token.claims,
        ))
    }
}

#[async_trait]
impl UserAwareSocioProvider for OpenId {
    type User = serde_json::Value;

    async fn exchange_code_for_user(
        &self,
        client: &SocioClient,
        code: socio::oauth2::AuthorizationCode,
        pkce_verifier: socio::oauth2::PkceCodeVerifier,
    ) -> error::Result<Response<Self::User>> {
        let response = client
            .exchange_code::<OpenIdTokenField>(code, pkce_verifier)
            .await?;

        let token = verify_jwt_with_jwks_endpoint::<Self::User>(
            &response.extra_fields().id_token,
            &self.jwks_url.as_str(),
            &client.client_id,
        )
        .await?;

        Ok(Response::from_standard_token_response(
            &response,
            token.claims,
        ))
    }
}
