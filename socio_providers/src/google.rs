use serde::{Deserialize, Serialize};
use socio::{
    async_trait, error,
    jwt::verify_jwt_with_jwks_endpoint,
    oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, Scope, TokenUrl},
    providers::{SocioProvider, StandardUser, UserAwareSocioProvider},
    types::{OpenIdTokenField, Response, SocioClient},
    Socio,
};

const GOOGLE_JWKS_ENDPOINT: &str = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/auth";
const GOOGLE_TOKEN_URL: &str = "https://accounts.google.com/o/oauth2/token";

#[derive(Clone, Debug)]
pub struct Google;

#[derive(Debug, Serialize, Deserialize)]
pub struct GoogleUser {
    iss: String,
    aud: String,
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    picture: Option<String>,
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
            GOOGLE_JWKS_ENDPOINT,
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
        SocioClient {
            client_id: value.client_id,
            client_secret: value.client_secret,
            redirect_uri: value.redirect_url,
            authorize_endpoint: AuthUrl::new(GOOGLE_AUTH_URL.to_string())
                .expect("Invalid authorization endpoint URL"), // SAFETY: This is safe because the URL is valid
            token_endpoint: TokenUrl::new(GOOGLE_TOKEN_URL.to_string())
                .expect("Invalid token endpoint URL"), // SAFETY: This is safe because the URL is valid
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_url() {
        assert!(
            AuthUrl::new(GOOGLE_AUTH_URL.to_string()).is_ok(),
            "Invalid authorization endpoint URL"
        );
    }

    #[test]
    fn test_token_url() {
        assert!(
            TokenUrl::new(GOOGLE_TOKEN_URL.to_string()).is_ok(),
            "Invalid token endpoint URL"
        );
    }
}
