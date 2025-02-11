use serde::{Deserialize, Serialize};
use socio::{
    async_trait, error,
    jwt::verify_jwt_with_jwks_endpoint,
    oauth2::{basic::BasicTokenType, StandardTokenResponse},
    providers::{GenericClaims, NormalizeClaims, SocioAuthorize},
    types::{SocioClient, OpenIdTokenField, Response},
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
impl SocioAuthorize for OpenId {
    type Fields = OpenIdTokenField;
    type Claims = OpenIdClaims;

    async fn parse_token_response(
        &self,
        config: &SocioClient,
        response: &StandardTokenResponse<Self::Fields, BasicTokenType>,
    ) -> error::Result<Response<Self::Claims>> {
        let token = verify_jwt_with_jwks_endpoint::<Self::Claims>(
            &response.extra_fields().id_token,
            &self.jwks_uri,
            &config.client_id,
        )
        .await?;

        Ok(Response::from_standard_token_response(
            &response,
            token.claims,
        ))
    }
}

impl NormalizeClaims for OpenIdClaims {
    fn normalize_claims(self) -> Option<GenericClaims> {
        let claims = self.0.as_object()?;
        let id = claims.get("sub")?.as_str()?.to_string();
        let name = claims
            .get("name")
            .and_then(|n| n.as_str())
            .map(|n| n.to_string());
        let email = claims
            .get("email")
            .and_then(|e| e.as_str())
            .map(|e| e.to_string());
        let picture = claims
            .get("picture")
            .and_then(|p| p.as_str())
            .map(|p| p.to_string());
        let iss = claims
            .get("iss")
            .and_then(|i| i.as_str())
            .map(|i| i.to_string());
        let aud = claims
            .get("aud")
            .and_then(|a| a.as_str())
            .map(|a| a.to_string());

        Some(GenericClaims {
            id,
            name,
            email,
            picture,
            iss,
            aud,
        })
    }
}
