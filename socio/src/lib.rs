pub mod error;
pub mod integrations;
pub mod providers;
pub mod types;

#[cfg(feature = "jwt")]
pub mod jwt;

pub use async_trait::async_trait;
pub use oauth2;

use oauth2::{
    basic::BasicTokenType, AuthorizationCode, CsrfToken, EmptyExtraTokenFields, ExtraTokenFields,
    PkceCodeVerifier, StandardTokenResponse,
};
use providers::SocioAuthorize;
use types::{AuthorizationRequest, Response, SocioClient};

#[derive(Clone, Debug)]
pub struct Socio<T> {
    config: SocioClient,
    provider: T,
}

impl<T> Socio<T> {
    pub fn new(config: SocioClient, provider: T) -> Self {
        Socio { config, provider }
    }

    pub fn config(&self) -> &SocioClient {
        &self.config
    }

    pub fn authorize(&self) -> error::Result<AuthorizationRequest> {
        let client = self.config.clone().client::<EmptyExtraTokenFields>();

        let csrf_token = CsrfToken::new_random();

        let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();

        let (url, csrf_token) = client
            .authorize_url(|| csrf_token.clone())
            .add_scopes(self.config.scopes.clone())
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
        let client = self.config.clone().client::<Fields>();

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

impl<T> Socio<T>
where
    T: SocioAuthorize,
{
    pub async fn exchange_and_claims(
        &self,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
    ) -> error::Result<Response<T::Claims>> {
        let response = self.exchange_code::<T::Fields>(code, pkce_verifier).await?;
        let claims = self
            .provider
            .parse_token_response(&self.config, &response)
            .await?;

        Ok(claims)
    }
}
