//! `Secret<T>`: travels on the wire, never reaches a log (docs/observability/01 §2.3).
//!
//! - serde is transparent, so wire bytes and signatures are unchanged;
//! - `Debug`/`Display` print `[REDACTED]`;
//! - it does not implement `tracing::Value`, so it cannot be recorded as a field;
//! - the value is read only through [`Secret::expose`].

use std::fmt;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// The only way to read the value. Grep for `expose()` in review.
    pub fn expose(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl From<&str> for Secret<String> {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl Secret<String> {
    /// `expose()` as `&str`, for `Option<Secret<String>>::as_ref().map(Secret::expose_str)`.
    pub fn expose_str(&self) -> &str {
        &self.0
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<T: serde::Serialize> serde::Serialize for Secret<T> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Secret<T> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        T::deserialize(d).map(Self)
    }
}
