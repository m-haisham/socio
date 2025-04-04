use std::{borrow::Cow, time::Duration};

use oauth2::{
    AccessToken, AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken,
    EmptyExtraTokenFields, EndpointNotSet, EndpointSet, ExtraTokenFields, PkceCodeVerifier,
    RedirectUrl, RefreshToken, Scope, StandardRevocableToken, StandardTokenResponse, TokenResponse,
    TokenUrl,
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{error, providers::StandardUser};

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

    pub fn authorize(&self, params: Option<ExtraParams>) -> error::Result<AuthorizationRequest> {
        let client = self.clone().client::<EmptyExtraTokenFields>();

        let csrf_token = CsrfToken::new_random();
        let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();

        let mut request = client
            .authorize_url(|| csrf_token.clone())
            .add_scopes(self.scopes.clone())
            .set_pkce_challenge(pkce_challenge);

        if let Some(params) = params {
            for (key, value) in params.0 {
                request = request.add_extra_param(key, value);
            }
        }

        let (url, csrf_token) = request.url();

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
    pub fn redirect_axum(&self) -> error::Result<crate::integrations::axum::Redirect> {
        let header_value = http::HeaderValue::from_str(self.url.as_str())
            .map_err(|e| error::Error::HeaderValueError(e))?;
        Ok(crate::integrations::axum::Redirect::new(header_value))
    }

    #[cfg(feature = "rocket")]
    pub fn redirect_rocket(&self) -> crate::integrations::rocket::Redirect {
        crate::integrations::rocket::Redirect::new(self.url.clone())
    }

    #[cfg(feature = "actix")]
    pub fn redirect_actix(&self) -> crate::integrations::actix::Redirect {
        crate::integrations::actix::Redirect::new(self.url.to_string())
    }
}

#[derive(Debug)]
pub struct Response<Claims> {
    pub access_token: AccessToken,
    pub token_type: BasicTokenType,
    pub refresh_token: Option<RefreshToken>,
    pub expires_in: Option<Duration>,
    pub scopes: Option<Vec<Scope>>,
    pub user: Claims,
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
            user: claims,
        }
    }
}

impl<T: Into<StandardUser>> Response<T> {
    pub fn standardize(self) -> Response<StandardUser> {
        Response {
            access_token: self.access_token,
            token_type: self.token_type,
            refresh_token: self.refresh_token,
            expires_in: self.expires_in,
            scopes: self.scopes,
            user: self.user.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExtraParams<'a>(Vec<(Cow<'a, str>, Cow<'a, str>)>);

impl<'a> ExtraParams<'a> {
    pub fn new() -> Self {
        ExtraParams(Vec::new())
    }

    pub fn push(&mut self, key: Cow<'a, str>, value: Cow<'a, str>) {
        self.0.push((key, value));
    }
}
