use crate::types::AuthorizationRequest;
use std::convert::Infallible;
use url::Url;

#[derive(Debug, Clone)]
pub struct Redirect {
    url: Url,
}

impl Redirect {
    pub fn new(url: Url) -> Self {
        Redirect { url }
    }
}

impl<'r> rocket::response::Responder<'r, 'static> for Redirect {
    fn respond_to(self, _: &'r rocket::Request<'_>) -> rocket::response::Result<'static> {
        rocket::response::Response::build()
            .status(rocket::http::Status::Found)
            .header(rocket::http::Header::new("Location", self.url.to_string()))
            .ok()
    }
}

impl TryFrom<AuthorizationRequest> for Redirect {
    type Error = Infallible;

    fn try_from(value: AuthorizationRequest) -> Result<Self, Self::Error> {
        Ok(Redirect::new(value.url))
    }
}
