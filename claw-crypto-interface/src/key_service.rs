//use mockall::automock;

pub struct PrefixedKeySplits<'a> {
    pub prefix: &'a str,
    pub key: &'a str,
}

//#[automock]
pub trait KeyService {
    fn digit_vec(&self, length: usize) -> Vec<u8>;

    fn digit_string(&self, length: usize) -> String;

    fn secure_string(&self, length: usize) -> String;

    fn split_prefixed_key<'a>(
        &self,
        key: &'a str,
        splitter: &str,
    ) -> Result<PrefixedKeySplits<'a>, &'static str>;
}
