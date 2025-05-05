pub type JwtResult<T> = Result<T, JwtError>;

#[derive(Debug, PartialEq, Clone)]
pub enum JwtError {
    Expired,
    Invalid,
    Time,
}

impl<T> From<JwtError> for JwtResult<T> {
    fn from(error: JwtError) -> Self {
        Err(error)
    }
}
