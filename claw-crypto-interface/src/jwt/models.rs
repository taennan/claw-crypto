use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json;
use std::marker::PhantomData;

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
    pub fn new(subject: &S) -> Self {
        Self::new_with_duration(subject, Duration::days(10))
    }

    pub fn new_with_duration(subject: &S, duration: Duration) -> Self {
        let expiry = (Utc::now() + duration).naive_utc();
        Self::new_with_expiry(subject, expiry)
    }

    pub fn new_with_expiry(subject: &S, expiry: NaiveDateTime) -> Self {
        let sub = serde_json::to_string(subject).unwrap();
        Self {
            iat: Self::current_timestamp(),
            exp: expiry.and_utc().timestamp() as usize,
            sub,
            marker: PhantomData,
        }
    }

    fn current_timestamp() -> usize {
        Utc::now().timestamp() as usize
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
