pub mod error;
pub mod integrations;
pub mod providers;
pub mod types;

#[cfg(feature = "jwt")]
pub mod jwt;

pub use async_trait::async_trait;
pub use oauth2;

use oauth2::{
    basic::BasicTokenType, AuthorizationCode, ExtraTokenFields, PkceCodeVerifier,
    StandardTokenResponse,
};
use providers::{SocioProvider, UserAwareSocioProvider};
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

    pub fn client(&self) -> &SocioClient {
        &self.config
    }

    pub fn provider(&self) -> &T {
        &self.provider
    }

    pub fn authorize(&self) -> error::Result<AuthorizationRequest> {
        self.client().authorize()
    }

    pub async fn exchange_code<Fields: ExtraTokenFields>(
        &self,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
    ) -> error::Result<StandardTokenResponse<Fields, BasicTokenType>> {
        self.client().exchange_code(code, pkce_verifier).await
    }
}

impl<T> Socio<T>
where
    T: SocioProvider,
{
    pub async fn exchange_code_standard(
        &self,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
    ) -> error::Result<Response<providers::StandardUser>> {
        self.provider
            .exchange_code_standard(self.client(), code, pkce_verifier)
            .await
    }
}

impl<T> Socio<T>
where
    T: UserAwareSocioProvider,
{
    pub async fn exchange_code_for_user(
        &self,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
    ) -> error::Result<Response<T::User>> {
        self.provider
            .exchange_code_for_user(self.client(), code, pkce_verifier)
            .await
    }
}
