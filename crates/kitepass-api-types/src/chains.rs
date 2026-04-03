use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported wallet chain families.
///
/// Each variant maps to a CAIP-2 namespace and defines the cryptographic
/// curve used for wallet key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainFamily {
    Evm,
    // future: Solana, Cosmos, etc.
}

impl ChainFamily {
    /// CAIP-2 namespace prefix for this chain family.
    pub fn namespace(&self) -> &'static str {
        match self {
            ChainFamily::Evm => "eip155",
        }
    }

    /// Check whether a CAIP-2 `chain_id` (e.g. `"eip155:8453"`) belongs to
    /// this chain family.
    pub fn matches_chain_id(&self, chain_id: &str) -> bool {
        chain_id.starts_with(self.namespace())
            && chain_id.as_bytes().get(self.namespace().len()) == Some(&b':')
    }

    /// Parse a user-supplied string into a [`ChainFamily`].
    ///
    /// Accepts the canonical lowercase name (`"evm"`), common aliases
    /// (`"eip155"`, `"base"`), and is case-insensitive.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "evm" | "eip155" | "base" => Some(ChainFamily::Evm),
            _ => None,
        }
    }
}

impl fmt::Display for ChainFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainFamily::Evm => write!(f, "evm"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_canonical_and_aliases() {
        assert_eq!(ChainFamily::parse("evm"), Some(ChainFamily::Evm));
        assert_eq!(ChainFamily::parse("eip155"), Some(ChainFamily::Evm));
        assert_eq!(ChainFamily::parse("base"), Some(ChainFamily::Evm));
        assert_eq!(ChainFamily::parse("EVM"), Some(ChainFamily::Evm));
        assert_eq!(ChainFamily::parse("  evm  "), Some(ChainFamily::Evm));
        assert_eq!(ChainFamily::parse("solana"), None);
        assert_eq!(ChainFamily::parse(""), None);
    }

    #[test]
    fn matches_chain_id_checks_namespace_prefix() {
        let evm = ChainFamily::Evm;
        assert!(evm.matches_chain_id("eip155:1"));
        assert!(evm.matches_chain_id("eip155:8453"));
        assert!(!evm.matches_chain_id("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"));
        assert!(!evm.matches_chain_id("eip155"));
        assert!(!evm.matches_chain_id("eip1551:1"));
    }

    #[test]
    fn serde_round_trip() {
        let evm = ChainFamily::Evm;
        let json = serde_json::to_string(&evm).unwrap();
        assert_eq!(json, "\"evm\"");
        let parsed: ChainFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, evm);
    }

    #[test]
    fn display_matches_serde() {
        assert_eq!(ChainFamily::Evm.to_string(), "evm");
    }
}
