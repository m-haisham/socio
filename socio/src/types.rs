use std::time::Duration;

use http::HeaderValue;
use oauth2::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
    AccessToken, AuthUrl, Client, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    EndpointNotSet, EndpointSet, ExtraTokenFields, PkceCodeVerifier, RedirectUrl, RefreshToken,
    Scope, StandardRevocableToken, StandardTokenResponse, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error;

pub type CustomClient<
    Fields = EmptyExtraTokenFields,
    HasAuthUrl = EndpointSet,
    HasTokenUrl = EndpointSet,
> = Client<
    BasicErrorResponse,
    StandardTokenResponse<Fields, BasicTokenType>,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    HasAuthUrl,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    HasTokenUrl,
>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OpenIdTokenField {
    pub id_token: String,
}

impl ExtraTokenFields for OpenIdTokenField {}

#[derive(Clone, Debug)]
pub struct OAuth2Config {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
    pub authorize_endpoint: AuthUrl,
    pub token_endpoint: TokenUrl,
    pub scopes: Vec<Scope>,
    pub redirect_uri: RedirectUrl,
}

impl OAuth2Config {
    pub fn into_custom_client<Fields: ExtraTokenFields>(self) -> CustomClient<Fields> {
        let client = CustomClient::<Fields, EndpointNotSet, EndpointNotSet>::new(self.client_id)
            .set_client_secret(self.client_secret)
            .set_auth_uri(self.authorize_endpoint)
            .set_token_uri(self.token_endpoint)
            .set_redirect_uri(self.redirect_uri);

        client
    }
}

#[derive(Debug)]
pub struct AuthorizationRequest {
    pub url: Url,
    pub pkce_verifier: PkceCodeVerifier,
    pub csrf_token: CsrfToken,
}

impl AuthorizationRequest {
    #[cfg(feature = "axum")]
    pub fn axum_redirect(&self) -> error::Result<crate::integrations::AxumRedirect> {
        let header_value = HeaderValue::from_str(self.url.as_str())
            .map_err(|e| error::Error::HeaderValueError(e))?;
        Ok(crate::integrations::AxumRedirect::new(header_value))
    }

    #[cfg(feature = "rocket")]
    pub fn rocket_redirect(&self) -> crate::integrations::RocketRedirect {
        crate::integrations::RocketRedirect::new(self.url.clone())
    }
}

#[derive(Debug)]
pub struct Response<Claims> {
    pub access_token: AccessToken,
    pub token_type: BasicTokenType,
    pub refresh_token: Option<RefreshToken>,
    pub expires_in: Option<Duration>,
    pub scopes: Option<Vec<Scope>>,
    pub claims: Claims,
}

impl<Claims> Response<Claims> {
    pub fn from_standard_token_response(
        response: &StandardTokenResponse<OpenIdTokenField, BasicTokenType>,
        claims: Claims,
    ) -> Self {
        Response {
            access_token: response.access_token().clone(),
            token_type: response.token_type().clone(),
            refresh_token: response.refresh_token().cloned(),
            expires_in: response.expires_in(),
            scopes: response.scopes().cloned(),
            claims,
        }
    }
}
