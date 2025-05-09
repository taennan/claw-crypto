use crate::jwt::{JwtClaims, JwtResult};
use mockall::automock;
use serde::{de::DeserializeOwned, Serialize};

#[automock]
pub trait JwtService<C>
where
    C: Serialize + DeserializeOwned,
{
    fn encode(&self, claims: &C) -> JwtResult<String>;

    fn decode(&self, token: &str) -> JwtResult<JwtClaims<C>>;
}
