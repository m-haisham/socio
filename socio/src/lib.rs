mod error;
mod types;

use oauth2::{CsrfToken, EmptyExtraTokenFields, PkceCodeVerifier};
use rand::{rngs::OsRng, TryRngCore};
use types::OAuth2Config;
use url::Url;

#[derive(Clone, Debug)]
pub struct Socio {
    config: OAuth2Config,
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

        let mut request = client.authorize_url(|| csrf_token.clone());

        let (pkce_challenge, pkce_verifier) = oauth2::PkceCodeChallenge::new_random_sha256();

        request = request.add_scopes(self.config.scopes.clone());
        request = request.set_pkce_challenge(pkce_challenge);

        let (url, csrf_token) = request.url();

        Ok(AuthorizationRedirect {
            url,
            csrf_token,
            pkce_verifier,
        })
    }
}

#[derive(Debug)]
pub struct AuthorizationRedirect {
    pub url: Url,
    pub pkce_verifier: PkceCodeVerifier,
    pub csrf_token: CsrfToken,
}
