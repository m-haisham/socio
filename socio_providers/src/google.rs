use serde::{Deserialize, Serialize};
use socio::{
    Socio, async_trait, error,
    jwt::verify_jwt_with_jwks_endpoint,
    oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, Scope, TokenUrl},
    providers::{SocioProvider, StandardUser, UserAwareSocioProvider},
    types::{OpenIdTokenField, Response, SocioClient},
};
use url_macro::url;

#[derive(Clone, Debug)]
pub struct Google;

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleUser {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub picture: Option<String>,
}

#[async_trait]
impl SocioProvider for Google {
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
impl UserAwareSocioProvider for Google {
    type User = GoogleUser;

    async fn exchange_code_for_user(
        &self,
        client: &SocioClient,
        code: socio::oauth2::AuthorizationCode,
        pkce_verifier: socio::oauth2::PkceCodeVerifier,
    ) -> error::Result<Response<Self::User>> {
        let response = client
            .exchange_code::<OpenIdTokenField>(code, pkce_verifier)
            .await?;

        let token = verify_jwt_with_jwks_endpoint::<GoogleUser>(
            &response.extra_fields().id_token,
            "https://www.googleapis.com/oauth2/v3/certs",
            &client.client_id,
        )
        .await?;

        Ok(Response::from_standard_token_response(
            &response,
            token.claims,
        ))
    }
}

impl From<GoogleUser> for StandardUser {
    fn from(value: GoogleUser) -> Self {
        StandardUser {
            id: value.sub,
            name: value.name,
            email: value.email,
            picture: value.picture,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GoogleConfig {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
    pub redirect_url: RedirectUrl,
}

impl From<GoogleConfig> for SocioClient {
    fn from(value: GoogleConfig) -> Self {
        let auth_url = url!("https://accounts.google.com/o/oauth2/v2/auth");
        let token_url = url!("https://oauth2.googleapis.com/token");

        SocioClient {
            client_id: value.client_id,
            client_secret: value.client_secret,
            redirect_uri: value.redirect_url,
            authorize_endpoint: AuthUrl::from_url(auth_url),
            token_endpoint: TokenUrl::from_url(token_url),
            scopes: ["openid", "profile", "email"]
                .iter()
                .map(|s| Scope::new(s.to_string()))
                .collect(),
        }
    }
}

impl From<GoogleConfig> for Socio<Google> {
    fn from(value: GoogleConfig) -> Self {
        Socio::new(value.into(), Google)
    }
}
