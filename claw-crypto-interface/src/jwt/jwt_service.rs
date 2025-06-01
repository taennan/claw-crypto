use crate::jwt::{JwtClaims, JwtClaimsOptions, JwtResult};
use mockall::automock;
use serde::{de::DeserializeOwned, Serialize};

#[automock]
pub trait JwtService<C>
where
    C: Serialize + DeserializeOwned,
{
    fn encode(&self, claims: &C, options: &JwtClaimsOptions) -> JwtResult<String>;

    fn decode(&self, token: &str) -> JwtResult<JwtClaims<C>>;
}
