// Layered config loading: defaults → config file → environment variables.
//
// Each service defines its own config struct and uses this crate's
// helpers to load it from the standard layered sources.
