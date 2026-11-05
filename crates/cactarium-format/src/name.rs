//! Owner and entry names.
//!
//! Both are lowercase so that uniqueness is case-insensitive by construction:
//! `[a-z0-9]` followed by up to 63 of `[a-z0-9._-]`, not ending in `.` or `-`, with no `..`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

const MAX_LEN: usize = 64;

fn validate(kind: &str, s: &str) -> Result<()> {
    let bad = |why: &str| Err(Error::invalid(format!("'{s}' is not a valid {kind} name: {why}")));
    if s.is_empty() {
        return bad("it is empty");
    }
    if s.len() > MAX_LEN {
        return bad("it is longer than 64 characters");
    }
    let first = s.as_bytes()[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return bad("it must start with a lowercase letter or digit");
    }
    if let Some(c) = s.chars().find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(*c))) {
        return bad(&format!("'{c}' is not allowed (use lowercase letters, digits, '.', '_' or '-')"));
    }
    if s.ends_with('.') || s.ends_with('-') {
        return bad("it must not end with '.' or '-'");
    }
    if s.contains("..") {
        return bad("it must not contain '..'");
    }
    Ok(())
}

macro_rules! name_type {
    ($ty:ident, $kind:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $ty(String);

        impl $ty {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $ty {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self> {
                validate($kind, s)?;
                Ok($ty(s.to_owned()))
            }
        }

        impl TryFrom<String> for $ty {
            type Error = Error;
            fn try_from(s: String) -> Result<Self> {
                validate($kind, &s)?;
                Ok($ty(s))
            }
        }

        impl From<$ty> for String {
            fn from(n: $ty) -> String {
                n.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

name_type!(Owner, "owner");
name_type!(Name, "entry");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_typical_names() {
        for s in ["max-morris", "carpetx", "et", "qc0-bbh", "bhns.gw230529", "a_b", "0x"] {
            Name::from_str(s).unwrap();
        }
    }

    #[test]
    fn rejects_bad_names() {
        for s in ["", "CarpetX", "-x", "x-", "x.", "a..b", "a/b", "a b", ".x", &"a".repeat(65)] {
            assert!(Name::from_str(s).is_err(), "{s:?} should be rejected");
        }
    }
}
