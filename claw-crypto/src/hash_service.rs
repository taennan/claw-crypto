use crate::traits::HashServiceTrait;
use bcrypt;

pub struct HashService {
    cost: u32,
}

impl HashService {
    const MIN_COST: u32 = 4;

    pub fn new(cost: u32) -> Self {
        if cost < HashService::MIN_COST {
            panic!("Minimum cost for HashService is {}", HashService::MIN_COST);
        }
        Self { cost }
    }

    #[cfg(test)]
    pub(crate) fn with_min_cost() -> Self {
        Self {
            cost: HashService::MIN_COST,
        }
    }
}

impl Default for HashService {
    fn default() -> Self {
        Self {
            cost: bcrypt::DEFAULT_COST,
        }
    }
}

impl HashServiceTrait for HashService {
    fn hash(&self, string: &str) -> Result<String, ()> {
        let result = bcrypt::hash(string, self.cost);
        let hash = result.map_err(|_err| ())?;
        Ok(hash)
    }

    fn verify(&self, token: &str, token_hash: &str) -> bool {
        bcrypt::verify(token, token_hash).unwrap_or(false)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_hashes_input() {
        let hash_service = HashService::with_min_cost();

        let input = "this_should_garbled_by_the_hashing_algorithm";
        let hashed = hash_service.hash(input).expect("Got unexpected error");

        assert_ne!(input, hashed);
    }

    #[test]
    fn it_returns_true_when_verifying_correct_token() {
        let hash_service = HashService::with_min_cost();

        let input = "this_should_garbled_by_the_hashing_algorithm";
        let hashed = hash_service.hash(input).expect("Got unexpected error");
        let is_correct = hash_service.verify(input, &hashed);

        assert!(is_correct);
    }

    #[test]
    fn it_returns_false_when_verifying_incorrect_token() {
        let hash_service = HashService::with_min_cost();

        let input = "this_should_garbled_by_the_hashing_algorithm";
        let hashed = hash_service.hash(input).expect("Got unexpected error");
        let is_correct = hash_service.verify("incorrect_input", &hashed);

        assert!(!is_correct);
    }
}
