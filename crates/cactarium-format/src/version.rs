//! Track-namespaced semantic versions.
//!
//! A repo can publish several independent version lines ("tracks"). In git the track is a tag
//! prefix: `v1.2.3` is on the default track, `mixed-precision/v1.2.3` is version 1.2.3 on track
//! `mixed-precision`. Git refs cannot contain ':', so Cactarium and cactup write the same version
//! as `1.2.3` and `mixed-precision:1.2.3`, and ranges as `^1.2` and `mixed-precision:^1.2`.
//!
//! Semver ordering and ranges apply within one track only. Versions on different tracks are never
//! compared and never match each other's ranges.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Track names: a lowercase letter followed by up to 63 of `[a-z0-9._-]`. They start with a letter
/// so `pkg@mixed-precision` (a track) can never be confused with `pkg@1` (a range). `default` names
/// the unprefixed track in `cactarium.toml`, `x` is a semver wildcard, and `head` means a stack's
/// unpinned branch tips (see [`crate::slug::HEAD`]), so none of them can be used.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TrackName(String);

/// What `default-track = "default"` means: the unprefixed track.
pub const DEFAULT_TRACK_KEYWORD: &str = "default";

impl TrackName {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(s: &str) -> Result<()> {
        let bad = |why: &str| Err(Error::invalid(format!("'{s}' is not a valid track name: {why}")));
        let Some(first) = s.chars().next() else { return bad("it is empty") };
        if s.len() > 64 {
            return bad("it is longer than 64 characters");
        }
        if !first.is_ascii_lowercase() {
            return bad("it must start with a lowercase letter");
        }
        if let Some(c) = s.chars().find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(*c))) {
            return bad(&format!("'{c}' is not allowed"));
        }
        if s == DEFAULT_TRACK_KEYWORD || s == "x" || s == crate::slug::HEAD {
            return bad("it is reserved");
        }
        Ok(())
    }
}

impl FromStr for TrackName {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        TrackName::validate(s)?;
        Ok(TrackName(s.to_owned()))
    }
}

impl TryFrom<String> for TrackName {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        TrackName::validate(&s)?;
        Ok(TrackName(s))
    }
}

impl From<TrackName> for String {
    fn from(t: TrackName) -> String {
        t.0
    }
}

impl fmt::Display for TrackName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A version on a track: `1.2.3` (default track) or `mixed-precision:1.2.3`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TrackedVersion {
    pub track: Option<TrackName>,
    pub version: semver::Version,
}

impl TrackedVersion {
    /// Reads a git tag. Returns `None` for tags that are not versions: anything other than
    /// `[<track>/][v]X.Y.Z[-pre][+build]` with a single-segment, valid track name. Such tags are
    /// simply ignored by the registry, not errors.
    pub fn from_tag(tag: &str) -> Option<TrackedVersion> {
        let tag = tag.strip_prefix("refs/tags/").unwrap_or(tag);
        let (track, rest) = match tag.split_once('/') {
            Some((prefix, rest)) => (Some(prefix.parse::<TrackName>().ok()?), rest),
            None => (None, tag),
        };
        let rest = rest.strip_prefix('v').unwrap_or(rest);
        let version = semver::Version::parse(rest).ok()?;
        Some(TrackedVersion { track, version })
    }

    /// The conventional git tag for this version: `v1.2.3` or `mixed-precision/v1.2.3`.
    pub fn conventional_tag(&self) -> String {
        match &self.track {
            Some(t) => format!("{t}/v{}", self.version),
            None => format!("v{}", self.version),
        }
    }

    /// Orders two versions on the same track. Versions on different tracks are not comparable.
    pub fn cmp_within_track(&self, other: &TrackedVersion) -> Option<Ordering> {
        (self.track == other.track).then(|| self.version.cmp(&other.version))
    }
}

/// Splits `track:rest`. A leading lowercase letter means a track; anything else is plain semver.
fn split_track(s: &str) -> Result<(Option<TrackName>, &str)> {
    match s.split_once(':') {
        Some((track, rest)) => Ok((Some(track.parse()?), rest)),
        None => Ok((None, s)),
    }
}

impl FromStr for TrackedVersion {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let (track, rest) = split_track(s)?;
        let version = semver::Version::parse(rest)
            .map_err(|e| Error::invalid(format!("'{s}' is not a version: {e}")))?;
        Ok(TrackedVersion { track, version })
    }
}

impl TryFrom<String> for TrackedVersion {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<TrackedVersion> for String {
    fn from(v: TrackedVersion) -> String {
        v.to_string()
    }
}

impl fmt::Display for TrackedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.track {
            Some(t) => write!(f, "{t}:{}", self.version),
            None => write!(f, "{}", self.version),
        }
    }
}

/// A version range on a track: `^1.2`, `>=2, <3`, `*`, `mixed-precision:^1.2`, or a bare track
/// name (`mixed-precision`, meaning any version on that track).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TrackedReq {
    pub track: Option<TrackName>,
    pub req: semver::VersionReq,
}

impl TrackedReq {
    pub fn matches(&self, v: &TrackedVersion) -> bool {
        self.track == v.track && self.req.matches(&v.version)
    }

    /// The highest version in `candidates` that this range matches.
    pub fn best_match<'a>(&self, candidates: impl IntoIterator<Item = &'a TrackedVersion>) -> Option<&'a TrackedVersion> {
        candidates.into_iter().filter(|v| self.matches(v)).max_by(|a, b| a.version.cmp(&b.version))
    }
}

impl FromStr for TrackedReq {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let (track, rest) = split_track(s)?;
        // A bare track name: any version on it.
        if track.is_none() && s.starts_with(|c: char| c.is_ascii_lowercase()) && s != "x" {
            return Ok(TrackedReq { track: Some(s.parse()?), req: semver::VersionReq::STAR });
        }
        let req = semver::VersionReq::parse(rest)
            .map_err(|e| Error::invalid(format!("'{s}' is not a version range: {e}")))?;
        Ok(TrackedReq { track, req })
    }
}

impl TryFrom<String> for TrackedReq {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<TrackedReq> for String {
    fn from(r: TrackedReq) -> String {
        r.to_string()
    }
}

impl fmt::Display for TrackedReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.track {
            Some(t) => write!(f, "{t}:{}", self.req),
            None => write!(f, "{}", self.req),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> TrackedVersion {
        s.parse().unwrap()
    }

    #[test]
    fn tags_map_to_tracks() {
        assert_eq!(TrackedVersion::from_tag("v1.2.3"), Some(v("1.2.3")));
        assert_eq!(TrackedVersion::from_tag("1.2.3"), Some(v("1.2.3")));
        assert_eq!(TrackedVersion::from_tag("refs/tags/v1.2.3"), Some(v("1.2.3")));
        assert_eq!(TrackedVersion::from_tag("mixed-precision/v1.2.3"), Some(v("mixed-precision:1.2.3")));
        assert_eq!(TrackedVersion::from_tag("mixed-precision/v2.0.0-rc.1"), Some(v("mixed-precision:2.0.0-rc.1")));
        assert_eq!(v("mixed-precision:1.2.3").conventional_tag(), "mixed-precision/v1.2.3");
    }

    #[test]
    fn non_version_tags_are_ignored() {
        for tag in ["ET_2026_05", "mixed-precision-1", "v1.2", "a/b/v1.2.3", "Upper/v1.2.3", "default/v1.0.0"] {
            assert_eq!(TrackedVersion::from_tag(tag), None, "{tag}");
        }
    }

    #[test]
    fn ranges_stay_within_their_track() {
        let r: TrackedReq = "mixed-precision:^1.2".parse().unwrap();
        assert!(r.matches(&v("mixed-precision:1.4.0")));
        assert!(!r.matches(&v("1.4.0")));
        assert!(!r.matches(&v("mixed-precision:2.0.0")));
        let d: TrackedReq = "^1.2".parse().unwrap();
        assert!(d.matches(&v("1.9.0")));
        assert!(!d.matches(&v("mixed-precision:1.9.0")));
    }

    #[test]
    fn bare_track_means_any_version_on_it() {
        let r: TrackedReq = "mixed-precision".parse().unwrap();
        assert!(r.matches(&v("mixed-precision:0.1.0")));
        assert!(!r.matches(&v("0.1.0")));
        let any: TrackedReq = "*".parse().unwrap();
        assert!(any.matches(&v("3.0.0")));
        assert_eq!(r.to_string(), "mixed-precision:*");
    }

    #[test]
    fn best_match_picks_highest_in_track() {
        let all = [v("1.0.0"), v("1.5.0"), v("mixed-precision:1.9.0"), v("2.0.0")];
        let r: TrackedReq = "^1".parse().unwrap();
        assert_eq!(r.best_match(&all), Some(&v("1.5.0")));
        assert_eq!(v("1.0.0").cmp_within_track(&v("mixed-precision:1.0.0")), None);
    }

    #[test]
    fn reserved_track_names() {
        assert!("default".parse::<TrackName>().is_err());
        assert!("x".parse::<TrackName>().is_err());
        assert!("head".parse::<TrackName>().is_err());
        assert!("1abc".parse::<TrackName>().is_err());
    }
}
