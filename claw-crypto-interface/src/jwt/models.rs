use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json;
use std::marker::PhantomData;

use super::{JwtError, JwtResult};

// NOTE: See https://crates.io/crates/jsonwebtoken for the accepted fields
#[derive(Serialize, Deserialize)]
pub struct JwtClaims<S> {
    iat: usize,
    exp: usize,
    sub: String,
    marker: PhantomData<S>,
}

impl<S> JwtClaims<S>
where
    S: Serialize + DeserializeOwned,
{
    pub fn try_new(subject: &S, options: &JwtClaimsOptions) -> JwtResult<Self> {
        let sub = serde_json::to_string(subject).map_err(|_| JwtError::Serde)?;
        let this = Self {
            iat: Utc::now().timestamp() as usize,
            exp: options.expiration.and_utc().timestamp() as usize,
            sub,
            marker: PhantomData,
        };
        Ok(this)
    }

    pub fn issued_at(&self) -> NaiveDateTime {
        DateTime::<Utc>::from_timestamp(self.iat as i64, 0)
            .unwrap_or_default()
            .naive_utc()
    }

    pub fn expires_at(&self) -> NaiveDateTime {
        DateTime::<Utc>::from_timestamp(self.exp as i64, 0)
            .unwrap_or_default()
            .naive_utc()
    }

    pub fn subject(&self) -> S {
        serde_json::from_str(&self.sub).unwrap()
    }
}

pub struct JwtClaimsOptions {
    pub expiration: NaiveDateTime,
}

impl JwtClaimsOptions {
    pub fn new(expiration: NaiveDateTime) -> Self {
        Self { expiration }
    }

    pub fn with_duration(duration: Duration) -> Self {
        let expiration = (Utc::now() + duration).naive_utc();
        Self::new(expiration)
    }
}

impl Default for JwtClaimsOptions {
    fn default() -> Self {
        Self::with_duration(Duration::days(10))
    }
}
