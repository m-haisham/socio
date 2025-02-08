pub struct Google;

#[derive(Debug, Deserialize)]
pub struct GoogleClaims {
    iss: String,
    aud: String,
    sub: String,
    email: String,
    email_verified: bool,
    name: String,
    picture: String,
    locale: String,
}

#[async_trait]
impl SocioAuthorize for Google {
    type Fields = IdTokenField;
    type Claims = GoogleClaims;

    async fn parse_token_response(
        &self,
        response: StandardTokenResponse<Self::Fields, BasicTokenType>,
    ) -> error::Result<Self::Claims> {
        let id_token = response.extra_fields().id_token.as_str();

        let header = jsonwebtoken::decode_header(id_token)?;
        let kid = header
            .kid
            .ok_or_else(|| error::Error::ProviderError("No kid".into()))?;

        let jwks = reqwest::get("https://www.googleapis.com/oauth2/v3/certs").await?;
        let jwks = jwks.json::<JwkSet>().await?;

        let jwk = jwks
            .find(&kid)
            .ok_or_else(|| error::Error::ProviderError("No key".into()))?;

        let decoding_key = DecodingKey::from_jwk(jwk)?;
        let validation = Validation::new(header.alg);

        let token = jsonwebtoken::decode::<GoogleClaims>(id_token, &decoding_key, &validation)?;

        Ok(token.claims)
    }
}

impl NormalizeClaims for GoogleClaims {
    fn normalize_claims(self) -> Option<GenericClaims> {
        Some(GenericClaims {
            id: self.sub.clone(),
            name: Some(self.name),
            email: Some(self.email.clone()),
            picture: Some(self.picture),
            iss: Some(self.iss),
            aud: Some(self.aud),
        })
    }
}
