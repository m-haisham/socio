use serde::{Deserialize, Serialize};
use socio::{
    async_trait, error,
    jwt::verify_jwt_with_jwks_endpoint,
    oauth2::{basic::BasicTokenType, StandardTokenResponse},
    providers::{GenericClaims, NormalizeClaims, SocioAuthorize},
    types::{IdTokenField, OAuth2Config, Response},
};

#[derive(Debug)]
pub struct Microsoft;

#[async_trait]
impl SocioAuthorize for Microsoft {
    type Fields = IdTokenField;
    type Claims = MicrosoftClaims;

    async fn parse_token_response(
        &self,
        config: &OAuth2Config,
        response: &StandardTokenResponse<Self::Fields, BasicTokenType>,
    ) -> error::Result<Response<Self::Claims>> {
        let token = verify_jwt_with_jwks_endpoint::<Self::Claims>(
            &response.extra_fields().id_token,
            "https://login.microsoftonline.com/common/discovery/v2.0/keys",
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
pub struct MicrosoftClaims {
    iss: String,
    aud: String,
    sub: String,
    name: String,
    preferred_username: String,
    email: String,
}

impl NormalizeClaims for MicrosoftClaims {
    fn normalize_claims(self) -> Option<GenericClaims> {
        Some(GenericClaims {
            id: self.sub.clone(),
            name: Some(self.name),
            email: Some(self.email.clone()),
            picture: None,
            iss: Some(self.iss),
            aud: Some(self.aud),
        })
    }
}
