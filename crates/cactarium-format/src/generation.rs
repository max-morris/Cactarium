use crate::{Error, Result};

/// Reads the top-level `format` key before full deserialization, so a file from a newer generation
/// gets an "upgrade" message rather than a confusing unknown-key error.
pub(crate) fn check(text: &str, what: &'static str, supported: u32) -> Result<()> {
    let table: toml::Table = toml::from_str(text).map_err(|source| Error::Toml { what, source })?;
    let found = match table.get("format") {
        Some(toml::Value::Integer(n)) if *n >= 1 && *n <= u32::MAX as i64 => *n as u32,
        Some(_) | None => return Err(Error::MissingFormat { what, supported }),
    };
    if found > supported {
        return Err(Error::NewerFormat { what, found, supported });
    }
    if found < supported {
        // No older generations exist yet. When format 2 lands, upgrade older files here.
        return Err(Error::invalid(format!("{what} uses unknown format {found}")));
    }
    Ok(())
}
