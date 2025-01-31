mod error;
mod types;

use oauth2::{
    basic::BasicTokenType, AuthorizationCode, CsrfToken, EmptyExtraTokenFields, ExtraTokenFields,
    PkceCodeVerifier, StandardTokenResponse,
};
use rand::{rngs::OsRng, TryRngCore};
use types::OAuth2Config;
use url::Url;

#[derive(Clone, Debug)]
pub struct Socio {
    config: OAuth2Config,
}

#[derive(Debug)]
pub struct AuthorizationRedirect {
    pub url: Url,
    pub pkce_verifier: PkceCodeVerifier,
    pub csrf_token: CsrfToken,
}

impl Socio {
    pub fn authorize(&self) -> error::Result<AuthorizationRedirect> {
        let client = self
            .config
            .clone()
            .into_custom_client::<EmptyExtraTokenFields>();

        let csrf_token = {
            let mut key = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut key)
                .map_err(|e| error::Error::CsrfTokenGenerationError(e))?;
            let key = String::from_utf8_lossy(&key).into_owned();
            CsrfToken::new(key)
        };

        let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();

        let (url, csrf_token) = client
            .authorize_url(|| csrf_token.clone())
            .add_scopes(self.config.scopes.clone())
            .set_pkce_challenge(pkce_challenge)
            .url();

        Ok(AuthorizationRedirect {
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
        let client = self.config.clone().into_custom_client::<Fields>();

        let http_client = reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let token = client
            .exchange_code(code)
            .set_pkce_verifier(pkce_verifier)
            .request_async(&http_client)
            .await?;

        Ok(token)
    }
}
