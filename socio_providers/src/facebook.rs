use serde::{Deserialize, Serialize};
use socio::{
    Socio, async_trait, error,
    jwt::verify_jwt_with_jwks_endpoint,
    oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, Scope, TokenUrl},
    providers::{SocioProvider, StandardUser, UserAwareSocioProvider},
    types::{OpenIdTokenField, Response, SocioClient},
};

const FACEBOOK_JWKS_ENDPOINT: &str = "https://www.facebook.com/.well-known/oauth/openid/jwks";
const FACEBOOK_AUTH_URL: &str = "https://www.facebook.com/v22.0/dialog/oauth";
const FACEBOOK_TOKEN_URL: &str = "https://graph.facebook.com/v22.0/oauth/access_token";

#[derive(Clone, Debug)]
pub struct Facebook;

#[derive(Debug, Serialize, Deserialize)]
pub struct FacebookUser {
    iss: String,
    aud: String,
    sub: String,
    email: Option<String>,
    name: Option<String>,
    family_name: Option<String>,
    given_name: Option<String>,
    picture: Option<String>,
}

#[async_trait]
impl SocioProvider for Facebook {
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
impl UserAwareSocioProvider for Facebook {
    type User = FacebookUser;

    async fn exchange_code_for_user(
        &self,
        client: &SocioClient,
        code: socio::oauth2::AuthorizationCode,
        pkce_verifier: socio::oauth2::PkceCodeVerifier,
    ) -> error::Result<Response<Self::User>> {
        let response = client
            .exchange_code::<OpenIdTokenField>(code, pkce_verifier)
            .await?;

        let token = verify_jwt_with_jwks_endpoint::<FacebookUser>(
            &response.extra_fields().id_token,
            FACEBOOK_JWKS_ENDPOINT,
            &client.client_id,
        )
        .await?;

        Ok(Response::from_standard_token_response(
            &response,
            token.claims,
        ))
    }
}

impl From<FacebookUser> for StandardUser {
    fn from(value: FacebookUser) -> Self {
        StandardUser {
            id: value.sub,
            name: value.name,
            email: value.email,
            picture: value.picture,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FacebookConfig {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
    pub redirect_url: RedirectUrl,
}

impl From<FacebookConfig> for SocioClient {
    fn from(value: FacebookConfig) -> Self {
        SocioClient {
            client_id: value.client_id,
            client_secret: value.client_secret,
            redirect_uri: value.redirect_url,
            authorize_endpoint: AuthUrl::new(FACEBOOK_AUTH_URL.to_string())
                .expect("Invalid authorization endpoint URL"), // SAFETY: This is safe because the URL is valid
            token_endpoint: TokenUrl::new(FACEBOOK_TOKEN_URL.to_string())
                .expect("Invalid token endpoint URL"), // SAFETY: This is safe because the URL is valid
            scopes: ["openid", "profile", "email"]
                .iter()
                .map(|s| Scope::new(s.to_string()))
                .collect(),
        }
    }
}

impl From<FacebookConfig> for Socio<Facebook> {
    fn from(value: FacebookConfig) -> Self {
        Socio::new(value.into(), Facebook)
    }
}

#[cfg(test)]
mod tests {
    use socio::oauth2::{AuthUrl, TokenUrl};

    use super::*;

    #[test]
    fn test_auth_url() {
        assert!(
            AuthUrl::new(FACEBOOK_AUTH_URL.to_string()).is_ok(),
            "Invalid authorization endpoint URL"
        );
    }

    #[test]
    fn test_token_url() {
        assert!(
            TokenUrl::new(FACEBOOK_TOKEN_URL.to_string()).is_ok(),
            "Invalid token endpoint URL"
        );
    }
}
