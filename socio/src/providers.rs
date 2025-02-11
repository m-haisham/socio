use crate::{
    error,
    types::{OAuth2Config, Response},
};
use async_trait::async_trait;
use oauth2::{basic::BasicTokenType, ExtraTokenFields, StandardTokenResponse};
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
        config: &OAuth2Config,
        response: &StandardTokenResponse<Self::Fields, BasicTokenType>,
    ) -> error::Result<Response<Self::Claims>>;
}
