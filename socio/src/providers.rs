use crate::{
    error,
    types::{AuthorizationRequest, Response, SocioClient},
};
use async_trait::async_trait;
use oauth2::{AuthorizationCode, PkceCodeVerifier};
use serde::{Deserialize, Serialize};

pub type Dynamic = Box<dyn SocioProvider + Sync + Send>;

#[derive(Debug, Serialize, Deserialize)]
pub struct StandardUser {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub picture: Option<String>,
}

#[async_trait]
pub trait SocioProvider {
    fn authorize(&self, client: &SocioClient) -> error::Result<AuthorizationRequest> {
        client.authorize()
    }

    async fn exchange_code_standard(
        &self,
        client: &SocioClient,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
    ) -> error::Result<Response<StandardUser>>;
}

#[async_trait]
impl<T: SocioProvider + Sync + ?Sized> SocioProvider for Box<T> {
    async fn exchange_code_standard(
        &self,
        client: &SocioClient,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
    ) -> error::Result<Response<StandardUser>> {
        self.exchange_code_standard(client, code, pkce_verifier)
            .await
    }
}

#[async_trait]
pub trait UserAwareSocioProvider: SocioProvider {
    type User;

    async fn exchange_code_for_user(
        &self,
        client: &SocioClient,
        code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
    ) -> error::Result<Response<Self::User>>;
}
