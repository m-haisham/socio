use crate::types::AuthorizationRequest;
use std::convert::Infallible;
use url::Url;

#[derive(Debug, Clone)]
pub struct RocketRedirect {
    url: Url,
}

impl RocketRedirect {
    pub fn new(url: Url) -> Self {
        RocketRedirect { url }
    }
}

impl<'r> rocket::response::Responder<'r, 'static> for RocketRedirect {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'static> {
        rocket::response::Response::build()
            .status(rocket::http::Status::Found)
            .header(rocket::http::Header::new("Location", self.url.to_string()))
            .ok()
    }
}

impl TryFrom<AuthorizationRequest> for RocketRedirect {
    type Error = Infallible;

    fn try_from(value: AuthorizationRequest) -> Result<Self, Self::Error> {
        Ok(RocketRedirect::new(value.url))
    }
}
