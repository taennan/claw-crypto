use claw_crypto_interface::jwt::JwtError;
use jsonwebtoken::errors::{Error as JsonWebTokenError, ErrorKind as JsonWebTokenErrorKind};

pub(crate) struct JsonWebTokenErrorConverter(JwtError);

impl From<JsonWebTokenError> for JsonWebTokenErrorConverter {
    fn from(error: JsonWebTokenError) -> Self {
        JsonWebTokenErrorConverter::from(error.into_kind())
    }
}

impl From<JsonWebTokenErrorKind> for JsonWebTokenErrorConverter {
    fn from(error_kind: JsonWebTokenErrorKind) -> Self {
        let error = match error_kind {
            JsonWebTokenErrorKind::ExpiredSignature => JwtError::Expired,
            _ => JwtError::Invalid,
        };
        JsonWebTokenErrorConverter(error)
    }
}

impl From<JsonWebTokenErrorConverter> for JwtError {
    fn from(converter: JsonWebTokenErrorConverter) -> Self {
        converter.0
    }
}
