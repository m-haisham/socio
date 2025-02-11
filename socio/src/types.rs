use std::time::Duration;

use http::HeaderValue;
use oauth2::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
    AccessToken, AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken,
    EmptyExtraTokenFields, EndpointNotSet, EndpointSet, ExtraTokenFields, PkceCodeVerifier,
    RedirectUrl, RefreshToken, Scope, StandardRevocableToken, StandardTokenResponse, TokenResponse,
    TokenUrl,
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
pub struct SocioClient {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
    pub authorize_endpoint: AuthUrl,
    pub token_endpoint: TokenUrl,
    pub scopes: Vec<Scope>,
    pub redirect_uri: RedirectUrl,
}

impl SocioClient {
    pub fn client<Fields: ExtraTokenFields>(self) -> CustomClient<Fields> {
        let client = CustomClient::<Fields, EndpointNotSet, EndpointNotSet>::new(self.client_id)
            .set_client_secret(self.client_secret)
            .set_auth_uri(self.authorize_endpoint)
            .set_token_uri(self.token_endpoint)
            .set_redirect_uri(self.redirect_uri);

        client
    }

    pub fn authorize(&self) -> error::Result<AuthorizationRequest> {
        let client = self.clone().client::<EmptyExtraTokenFields>();

        let csrf_token = CsrfToken::new_random();
        let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();

        // TODO: add support for extra params
        let (url, csrf_token) = client
            .authorize_url(|| csrf_token.clone())
            .add_scopes(self.scopes.clone())
            .set_pkce_challenge(pkce_challenge)
            .url();

        Ok(AuthorizationRequest {
            url,
            csrf_token,
            pkce_verifier,
        })
    }

    pub async fn exchange_code<Fields: ExtraTokenFields>(
        &self,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
    ) -> error::Result<StandardTokenResponse<Fields, BasicTokenType>> {
        let client = self.clone().client::<Fields>();

        let http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let response = client
            .exchange_code(code)
            .set_pkce_verifier(pkce_verifier)
            .request_async(&http_client)
            .await?;

        Ok(response)
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
