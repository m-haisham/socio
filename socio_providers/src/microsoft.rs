use serde::{Deserialize, Serialize};
use socio::{
    async_trait, error,
    jwt::verify_jwt_with_jwks_endpoint,
    providers::{SocioProvider, StandardUser, UserAwareSocioProvider},
    types::{OpenIdTokenField, Response, SocioClient},
};

#[derive(Debug)]
pub struct Microsoft;

impl Microsoft {
    /// Returns the JWKS URI for Microsoft based on the token endpoint.
    /// Microsoft has different tenants, so the JWKS URI is based on the token endpoint.
    pub fn jwks_uri(&self, client: &SocioClient) -> String {
        client
            .token_endpoint
            .strip_suffix("/oauth2/v2.0/token")
            .map(|base_uri| format!("{}/discovery/v2.0/keys", base_uri))
            .unwrap_or_else(|| {
                "https://login.microsoftonline.com/common/discovery/v2.0/keys".to_string()
            })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MicrosoftUser {
    iss: String,
    aud: String,
    sub: String,
    name: String,
    preferred_username: String,
    email: String,
}

#[async_trait]
impl SocioProvider for Microsoft {
    async fn exchange_code_standard(
        &self,
        client: &SocioClient,
        code: socio::oauth2::AuthorizationCode,
        pkce_verifier: socio::oauth2::PkceCodeVerifier,
    ) -> error::Result<Response<StandardUser>> {
        Ok(self
            .exchange_code_for_user(client, code, pkce_verifier)
            .await?
            .standardize())
    }
}

#[async_trait]
impl UserAwareSocioProvider for Microsoft {
    type User = MicrosoftUser;

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
            &self.jwks_uri(&client),
            &client.client_id,
        )
        .await?;

        Ok(Response::from_standard_token_response(
            &response,
            token.claims,
        ))
    }
}

impl From<MicrosoftUser> for StandardUser {
    fn from(value: MicrosoftUser) -> Self {
        StandardUser {
            id: value.sub,
            name: Some(value.name),
            email: Some(value.email),
            picture: None,
        }
    }
}
