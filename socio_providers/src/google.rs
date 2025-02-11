use serde::{Deserialize, Serialize};
use socio::{
    async_trait, error,
    jwt::verify_jwt_with_jwks_endpoint,
    oauth2::{basic::BasicTokenType, StandardTokenResponse},
    providers::{GenericClaims, NormalizeClaims, SocioAuthorize},
    types::{OpenIdTokenField, OAuth2Config, Response},
};

#[derive(Debug)]
pub struct Google;

#[async_trait]
impl SocioAuthorize for Google {
    type Fields = OpenIdTokenField;
    type Claims = GoogleClaims;

    async fn parse_token_response(
        &self,
        config: &OAuth2Config,
        response: &StandardTokenResponse<Self::Fields, BasicTokenType>,
    ) -> error::Result<Response<Self::Claims>> {
        let token = verify_jwt_with_jwks_endpoint::<Self::Claims>(
            &response.extra_fields().id_token,
            "https://www.googleapis.com/oauth2/v3/certs",
            &config.client_id,
        )
        .await?;

        Ok(Response::from_standard_token_response(
            &response,
            token.claims,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleClaims {
    iss: String,
    aud: String,
    sub: String,
    email: String,
    email_verified: bool,
    name: String,
    picture: String,
}

impl NormalizeClaims for GoogleClaims {
    fn normalize_claims(self) -> Option<GenericClaims> {
        Some(GenericClaims {
            id: self.sub.clone(),
            name: Some(self.name),
            email: Some(self.email.clone()),
            picture: Some(self.picture),
            iss: Some(self.iss),
            aud: Some(self.aud),
        })
    }
}
