use crate::jwt::jwt_result::JwtResult;
use mockall::automock;

#[automock]
pub trait JwtService<C> {
    fn encode(&self, claims: &C) -> JwtResult<String>;

    fn decode(&self, token: &str) -> JwtResult<C>;
}
