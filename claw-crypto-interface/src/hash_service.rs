use mockall::automock;

#[automock]
pub trait HashService {
    fn hash(&self, string: &str) -> Result<String, ()>;

    fn verify(&self, token: &str, token_hash: &str) -> bool;
}
