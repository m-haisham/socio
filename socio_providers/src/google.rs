use serde::Deserialize;
use socio::{
    async_trait, error,
    jwt::verify_jwt_with_jwks_endpoint,
    oauth2::{basic::BasicTokenType, StandardTokenResponse},
    providers::{GenericClaims, NormalizeClaims, SocioAuthorize},
    types::IdTokenField,
};

pub struct Google;

#[async_trait]
impl SocioAuthorize for Google {
    type Fields = IdTokenField;
    type Claims = GoogleClaims;

    async fn parse_token_response(
        &self,
        response: StandardTokenResponse<Self::Fields, BasicTokenType>,
    ) -> error::Result<Self::Claims> {
        let token = verify_jwt_with_jwks_endpoint(
            &response.extra_fields().id_token,
            "https://www.googleapis.com/oauth2/v3/certs",
        )
        .await?;

        Ok(token.claims)
    }
}

#[derive(Debug, Deserialize)]
pub struct GoogleClaims {
    iss: String,
    aud: String,
    sub: String,
    email: String,
    email_verified: bool,
    name: String,
    picture: String,
    locale: String,
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
