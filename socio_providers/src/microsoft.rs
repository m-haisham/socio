use serde::{Deserialize, Serialize};
use socio::{
    async_trait, error,
    jwt::verify_jwt_with_jwks_endpoint,
    oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, Scope, TokenUrl},
    providers::{SocioProvider, StandardUser, UserAwareSocioProvider},
    types::{OpenIdTokenField, Response, SocioClient},
    Socio,
};

#[derive(Clone, Debug)]
pub struct Microsoft;

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
            &jwks_uri(&client),
            &client.client_id,
        )
        .await?;

        Ok(Response::from_standard_token_response(
            &response,
            token.claims,
        ))
    }
}

/// Returns the JWKS URI for Microsoft based on the token endpoint.
/// Microsoft has different tenants, so the JWKS URI is based on the token endpoint.
pub fn jwks_uri(client: &SocioClient) -> String {
    client
        .token_endpoint
        .strip_suffix("/oauth2/v2.0/token")
        .map(|base_uri| format!("{}/discovery/v2.0/keys", base_uri))
        .unwrap_or_else(|| {
            "https://login.microsoftonline.com/common/discovery/v2.0/keys".to_string()
        })
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MicrosoftConfig {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
    pub redirect_uri: RedirectUrl,
    #[serde(default)]
    pub tenant: TenantType,
}

impl From<MicrosoftConfig> for SocioClient {
    fn from(value: MicrosoftConfig) -> Self {
        SocioClient {
            client_id: value.client_id,
            client_secret: value.client_secret,
            redirect_uri: value.redirect_uri,
            authorize_endpoint: value.tenant.auth_url(),
            token_endpoint: value.tenant.token_url(),
            scopes: ["openid", "profile", "email"]
                .iter()
                .map(|s| Scope::new(s.to_string()))
                .collect(),
        }
    }
}

impl From<MicrosoftConfig> for Socio<Microsoft> {
    fn from(value: MicrosoftConfig) -> Self {
        Socio::new(value.into(), Microsoft)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(untagged, rename_all = "snake_case")]
pub enum TenantType {
    #[default]
    Common,
    Consumers,
    Tenant(String),
}

impl TenantType {
    pub fn as_str(&self) -> &str {
        match self {
            TenantType::Common => "common",
            TenantType::Consumers => "consumers",
            TenantType::Tenant(tenant) => tenant,
        }
    }

    pub fn auth_url(&self) -> AuthUrl {
        AuthUrl::new(format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
            self.as_str()
        ))
        .expect("Invalid Microsoft auth URL")
    }

    pub fn token_url(&self) -> TokenUrl {
        TokenUrl::new(format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.as_str()
        ))
        .expect("Invalid Microsoft token URL")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_url() {
        let types = [
            TenantType::Common,
            TenantType::Consumers,
            TenantType::Tenant("my-tenant".to_string()),
        ];

        for tenant in types.iter() {
            tenant.auth_url();
        }
    }

    #[test]
    fn test_token_url() {
        let types = [
            TenantType::Common,
            TenantType::Consumers,
            TenantType::Tenant("my-tenant".to_string()),
        ];

        for tenant in types.iter() {
            tenant.token_url();
        }
    }
}
