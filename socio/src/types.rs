use http::HeaderValue;
use oauth2::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
    AuthUrl, Client, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, EndpointNotSet,
    EndpointSet, ExtraTokenFields, PkceCodeVerifier, RedirectUrl, Scope, StandardRevocableToken,
    StandardTokenResponse, TokenUrl,
};
use url::Url;

use crate::{error, integrations::SocioRedirect};

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
    pub fn redirect(&self) -> error::Result<SocioRedirect> {
        let header_value = HeaderValue::from_str(self.url.as_str())
            .map_err(|e| error::Error::HeaderValueError(e))?;
        Ok(SocioRedirect::new(header_value))
    }
}
