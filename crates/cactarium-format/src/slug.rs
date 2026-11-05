//! References users type: `owner/name`, `owner/name/Thorn`, `owner/name@...`.
//!
//! What follows `@` depends on the entry kind, so a [`Slug`] keeps it raw and offers typed
//! readers: a range for packages and stacks ([`Slug::req`]), an exact version ([`Slug::exact`]),
//! or a sim upload number ([`Slug::number`]).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::name::{Name, Owner};
use crate::version::{TrackedReq, TrackedVersion};
use crate::{Error, Result};

/// `owner/stack@head`: a stack's definition with every repo at its branch tip, unpinned. A power-user
/// form (like installing the ET's `master`): never a release and never a stack base. A `.sim` may
/// name it as provenance, since its own `[[repo]]` pins are what make it reproducible.
pub const HEAD: &str = "head";

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Slug {
    pub owner: Owner,
    pub name: Name,
    /// A thorn inside a package (`owner/pkg/Thorn`). Thorn names keep Cactus's case.
    pub thorn: Option<String>,
    /// Everything after `@`, unparsed.
    pub at: Option<String>,
}

fn valid_thorn(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl Slug {
    /// Whether this is `owner/stack@head`, the unpinned branch tips.
    pub fn is_head(&self) -> bool {
        self.at.as_deref() == Some(HEAD)
    }

    /// The `@` part as a version range (`^1.2`, `mixed-precision:^1`). No `@` means any version on
    /// the default track. `@head` is not a range: check [`Slug::is_head`] first.
    pub fn req(&self) -> Result<TrackedReq> {
        match &self.at {
            None => Ok(TrackedReq { track: None, req: semver::VersionReq::STAR }),
            Some(at) if at == HEAD => Err(Error::invalid(format!("'{self}' names unpinned branch tips, not a version"))),
            Some(at) => at.parse(),
        }
    }

    /// The `@` part as one exact version (`1.4.0`, `mixed-precision:1.4.0`).
    pub fn exact(&self) -> Result<TrackedVersion> {
        let at = self.at.as_deref().ok_or_else(|| Error::invalid(format!("'{self}' names no version")))?;
        at.parse()
    }

    /// The `@` part as an upload number (sims: `owner/name@3`).
    pub fn number(&self) -> Result<Option<u32>> {
        match &self.at {
            None => Ok(None),
            Some(at) => at
                .parse::<u32>()
                .ok()
                .filter(|n| *n >= 1)
                .map(Some)
                .ok_or_else(|| Error::invalid(format!("'{at}' in '{self}' is not a version number"))),
        }
    }

    /// `owner/name`, without thorn or version.
    pub fn entry(&self) -> String {
        format!("{}/{}", self.owner, self.name)
    }
}

impl FromStr for Slug {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let bad = |why: &str| Error::invalid(format!("'{s}' is not a Cactarium reference: {why}"));
        let (path, at) = match s.split_once('@') {
            Some((_, "")) => return Err(bad("nothing follows '@'")),
            Some((p, a)) => (p, Some(a.to_owned())),
            None => (s, None),
        };
        let mut parts = path.split('/');
        let (Some(owner), Some(name)) = (parts.next(), parts.next()) else {
            return Err(bad("expected owner/name"));
        };
        let thorn = parts.next().map(str::to_owned);
        if parts.next().is_some() {
            return Err(bad("expected owner/name or owner/name/Thorn"));
        }
        if let Some(t) = &thorn
            && !valid_thorn(t)
        {
            return Err(bad(&format!("'{t}' is not a thorn name")));
        }
        Ok(Slug { owner: owner.parse()?, name: name.parse()?, thorn, at })
    }
}

impl TryFrom<String> for Slug {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<Slug> for String {
    fn from(s: Slug) -> String {
        s.to_string()
    }
}

impl fmt::Display for Slug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)?;
        if let Some(t) = &self.thorn {
            write!(f, "/{t}")?;
        }
        if let Some(a) = &self.at {
            write!(f, "@{a}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_shapes() {
        let s: Slug = "max-morris/carpetx/TestReal4@mixed-precision:^1.4".parse().unwrap();
        assert_eq!(s.entry(), "max-morris/carpetx");
        assert_eq!(s.thorn.as_deref(), Some("TestReal4"));
        assert!(s.req().unwrap().matches(&"mixed-precision:1.5.0".parse().unwrap()));
        assert_eq!(s.to_string(), "max-morris/carpetx/TestReal4@mixed-precision:^1.4");

        let sim: Slug = "mmorris/qc0-bbh@3".parse().unwrap();
        assert_eq!(sim.number().unwrap(), Some(3));

        let exact: Slug = "max-morris/carpetx@mixed-precision:1.4.0".parse().unwrap();
        assert_eq!(exact.exact().unwrap().to_string(), "mixed-precision:1.4.0");

        let head: Slug = "max-morris/carpetx@head".parse().unwrap();
        assert!(head.is_head());
        assert!(head.req().is_err() && head.exact().is_err());

        let bare: Slug = "einsteintoolkit/et".parse().unwrap();
        assert!(bare.req().unwrap().matches(&"2026.5.0".parse().unwrap()));
    }

    #[test]
    fn rejects_malformed() {
        for s in ["carpetx", "a/b/c/d", "a/b@", "A/b", "a/b/1Thorn", "a/b/Th-orn", "a/b@0"] {
            let r = s.parse::<Slug>().and_then(|x| x.number().map(|_| x));
            assert!(r.is_err(), "{s} should be rejected");
        }
    }
}
