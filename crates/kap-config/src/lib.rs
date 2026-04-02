// Layered config loading: defaults → config file → environment variables.
//
// Each service defines its own config struct and uses this crate's
// helpers to load it from the standard layered sources.

use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::de::DeserializeOwned;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("configuration loading failed: {0}")]
    LoadFailed(String),
}

/// Load a configuration struct from layered sources.
///
/// Layer priority (highest wins):
/// 1. Environment variables with `KITEPASS_` prefix (underscore-separated)
/// 2. TOML config file at the given path (if provided)
/// 3. Defaults from `T::default()`
pub fn load_config<T>(config_path: Option<&str>) -> Result<T, ConfigError>
where
    T: Default + serde::Serialize + DeserializeOwned,
{
    let mut figment = Figment::from(Serialized::defaults(T::default()));

    if let Some(path) = config_path {
        figment = figment.merge(Toml::file(path));
    }

    figment = figment.merge(Env::prefixed("KITEPASS_").split("_"));

    figment
        .extract()
        .map_err(|e| ConfigError::LoadFailed(e.to_string()))
}

/// Load configuration using only defaults and environment variables.
pub fn load_config_from_env<T>() -> Result<T, ConfigError>
where
    T: Default + serde::Serialize + DeserializeOwned,
{
    load_config::<T>(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
    struct TestConfig {
        pub host: String,
        pub port: u16,
    }

    #[test]
    fn load_defaults() {
        let cfg: TestConfig = load_config_from_env().unwrap();
        assert_eq!(cfg, TestConfig::default());
    }
}
