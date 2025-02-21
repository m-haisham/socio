use actix_web::{
    HttpRequest, HttpResponse, Responder,
    body::BoxBody,
    http::{StatusCode, header},
};

#[derive(Debug, Clone)]
pub struct Redirect {
    url: String,
}

impl Redirect {
    pub fn new(url: String) -> Self {
        Redirect { url }
    }
}

impl Responder for Redirect {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::build(StatusCode::FOUND)
            .insert_header((header::LOCATION, self.url))
            .finish()
    }
}
