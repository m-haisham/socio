use jsonwebtoken::{jwk::JwkSet, DecodingKey, TokenData, Validation};
use serde::de::DeserializeOwned;

use crate::error;

pub async fn verify_jwt_with_jwks_endpoint<T>(
    jwt: &str,
    jwks_endpoint: &str,
) -> error::Result<TokenData<T>>
where
    T: DeserializeOwned,
{
    let header = jsonwebtoken::decode_header(jwt)?;
    let kid = header
        .kid
        .ok_or_else(|| error::Error::Custom("No 'kid' field found found in the jwt".into()))?;

    let jwks = reqwest::get(jwks_endpoint).await?;
    let jwks = jwks.json::<JwkSet>().await?;

    let jwk = jwks.find(&kid).ok_or_else(|| {
        error::Error::Custom(
            format!("No key matching kid '{kid}' found on endpoint: {jwks_endpoint}").into(),
        )
    })?;

    let decoding_key = DecodingKey::from_jwk(jwk)?;
    let validation = Validation::new(header.alg);

    let token = jsonwebtoken::decode::<T>(jwt, &decoding_key, &validation)?;

    Ok(token)
}
