use crate::{
    error,
    types::{AuthorizationRequest, Response, SocioClient},
};
use async_trait::async_trait;
use oauth2::{
    basic::BasicTokenType, AuthorizationCode, ExtraTokenFields, PkceCodeVerifier,
    StandardTokenResponse,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct GenericClaims {
    pub iss: Option<String>,
    pub aud: Option<String>,
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub picture: Option<String>,
}

pub trait NormalizeClaims {
    fn normalize_claims(self) -> Option<GenericClaims>;
}

#[async_trait]
pub trait SocioAuthorize {
    type Fields: ExtraTokenFields;
    type Claims: NormalizeClaims;

    async fn parse_token_response(
        &self,
        config: &SocioClient,
        response: &StandardTokenResponse<Self::Fields, BasicTokenType>,
    ) -> error::Result<Response<Self::Claims>>;
}

trait SocioProvider {
    fn authorize(&self, client: &SocioClient) -> error::Result<AuthorizationRequest> {
        client.authorize()
    }

    async fn exchange_code<Claims>(
        &self,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
    ) -> error::Result<Response<Claims>>;

    async fn exchange_code_generic(
        &self,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
    ) -> error::Result<Response<GenericClaims>>;
}

trait TypedSocioProvider {
    type Claims: NormalizeClaims;

    async fn exchange_code_typed(
        &self,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
    ) -> error::Result<Response<Self::Claims>>;
}
