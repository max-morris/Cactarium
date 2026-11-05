//! File formats shared by the Cactarium registry server and cactup.
//!
//! - [`sim`]: `.sim` files, which hold a parfile together with the thornlist it ran on, both kept
//!   verbatim, plus per-repo pins.
//! - [`manifest`]: `cactarium.toml` (a package) and `cactarium-stack.toml` (a stack), committed
//!   in a repo and read at each tag.
//! - [`stack`]: stack definitions (flat thornlist, recipe, or both) and frozen releases.
//! - [`ccl`]: dependency facts from a thorn's interface.ccl and configuration.ccl.
//! - [`crl`]: the CRL 1.0 thornlist parser (shared with cactup).
//! - [`name`], [`version`], [`slug`]: owner/name identifiers, track-namespaced semver, and the
//!   `owner/name[/Thorn][@...]` references users type.
//!
//! Every format carries a top-level `format` generation. Readers are strict: unknown keys are an
//! error, and a generation newer than this crate knows is rejected with an upgrade message (the
//! same discipline as cactup's MDB generations).

pub mod ccl;
pub mod crl;
pub mod error;
pub mod manifest;
pub mod name;
pub mod sim;
pub mod slug;
pub mod stack;
pub mod version;

mod generation;

pub use error::{Error, Result};

/// The `.sim` format generation this crate reads and writes.
pub const SIM_FORMAT: u32 = 1;
/// The `cactarium.toml` format generation this crate reads and writes.
pub const MANIFEST_FORMAT: u32 = 1;
