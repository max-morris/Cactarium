use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file is not valid TOML, or does not match the schema.
    #[error("{what} is not valid: {source}")]
    Toml {
        what: &'static str,
        #[source]
        source: toml::de::Error,
    },

    /// The file declares a format generation newer than this reader understands.
    #[error("{what} uses format {found}, but this version only understands format {supported}; upgrade to read it")]
    NewerFormat { what: &'static str, found: u32, supported: u32 },

    /// The file has no usable top-level `format` key.
    #[error("{what} has no 'format' key (expected format = {supported})")]
    MissingFormat { what: &'static str, supported: u32 },

    /// A value failed validation after parsing.
    #[error("{0}")]
    Invalid(String),

    #[error("could not write {what}: {source}")]
    Serialize {
        what: &'static str,
        #[source]
        source: toml::ser::Error,
    },
}

impl Error {
    pub(crate) fn invalid(msg: impl fmt::Display) -> Self {
        Error::Invalid(msg.to_string())
    }
}
