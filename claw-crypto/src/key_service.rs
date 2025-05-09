use crate::traits::KeyServiceTrait;
pub use claw_crypto_interface::PrefixedKeySplits;
use rand::{self, Rng};

pub struct KeyService;

impl KeyService {
    fn join_digits(&self, digit_vec: &[u8]) -> String {
        let vec: Vec<String> = digit_vec
            .into_iter()
            .map(|digit| digit.to_string())
            .collect();
        vec.join("")
    }
}

impl KeyServiceTrait for KeyService {
    fn digit_string(&self, length: usize) -> String {
        let digit_vec = self.digit_vec(length);
        let key = self.join_digits(&digit_vec);
        key
    }

    fn digit_vec(&self, length: usize) -> Vec<u8> {
        let mut digits = Vec::with_capacity(length);
        for _ in 0..length {
            let digit = rand::thread_rng().gen_range(0..=9);
            let digit = digit as u8;
            digits.push(digit);
        }
        digits
    }

    fn secure_string(&self, length: usize) -> String {
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
        let random_slice = &random_bytes[0..length];
        let string = self.join_digits(random_slice);
        string
    }

    fn split_prefixed_key<'a>(
        &self,
        key: &'a str,
        splitter: &str,
    ) -> Result<PrefixedKeySplits<'a>, &'static str> {
        let splits: Vec<&str> = key.split(splitter).collect();
        let prefix = splits.get(0).ok_or("No prefix found in inputted &str")?;
        let key = splits.get(1).ok_or("No key found in inputted &str")?;

        Ok(PrefixedKeySplits::<'a> { prefix, key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_generates_vector_of_correct_length() {
        let expected = 6usize;
        let actual = KeyService.digit_vec(expected).len();
        assert_eq!(actual, expected);
    }

    #[test]
    fn it_generates_digit_string_of_correct_length() {
        let expected = 16usize;
        let actual = KeyService.digit_string(expected).len();
        assert_eq!(actual, expected);
    }

    // NOTE: Not guaranteed, but very unlikely to fail
    #[test]
    fn it_generates_random_string() {
        let strings: Vec<String> = (0..5).map(|_| KeyService.secure_string(32)).collect();

        let first = &strings[0];
        for (i, other) in strings.iter().skip(1).enumerate() {
            assert_ne!(
                first,
                other,
                "First string is identical to string at index {}",
                i + 1
            );
        }
    }

    #[test]
    fn it_generates_random_string_of_specified_length() {
        let expected = 10usize;
        let actual = KeyService.secure_string(expected).len();
        assert_eq!(actual, expected)
    }
}
