use crate::{
    jwt::jsonwebtoken_error_converter::JsonWebTokenErrorConverter, traits::JwtServiceTrait,
};
use claw_crypto_interface::jwt::JwtResult;
use jsonwebtoken::{self, DecodingKey, EncodingKey, Header, Validation};
use serde::{de::DeserializeOwned, Serialize};
use std::marker::PhantomData;

#[derive(Debug, PartialEq, Clone)]
pub struct JwtService<C> {
    secret: String,
    marker: PhantomData<C>,
}

impl<C> JwtService<C> {
    pub fn new(secret: String) -> Self {
        Self {
            secret,
            marker: PhantomData,
        }
    }
}

impl<C> JwtServiceTrait<C> for JwtService<C>
where
    C: Serialize + DeserializeOwned,
{
    fn encode(&self, claims: &C) -> JwtResult<String> {
        let result = jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(&self.secret.as_bytes()),
        );

        let token = result.map_err(JsonWebTokenErrorConverter::from)?;
        Ok(token)
    }

    fn decode(&self, token: &str) -> JwtResult<C> {
        let result = jsonwebtoken::decode::<C>(
            token,
            &DecodingKey::from_secret(&self.secret.as_bytes()),
            &Validation::default(),
        );

        let token_data = result.map_err(JsonWebTokenErrorConverter::from)?;
        Ok(token_data.claims)
    }
}
