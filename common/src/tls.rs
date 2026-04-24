use crate::KeyExchangeMode;
use rustls::crypto::{
    SupportedKxGroup,
    aws_lc_rs::kx_group::{SECP256R1, SECP256R1MLKEM768, X25519, X25519MLKEM768},
};

/// Return the single TLS key-exchange group used for a benchmark mode.
#[must_use]
pub fn key_exchange_groups(mode: KeyExchangeMode) -> Vec<&'static dyn SupportedKxGroup> {
    match mode {
        KeyExchangeMode::X25519 => vec![X25519],
        KeyExchangeMode::Secp256r1 => vec![SECP256R1],
        KeyExchangeMode::X25519Mlkem768 => vec![X25519MLKEM768],
        KeyExchangeMode::Secp256r1Mlkem768 => vec![SECP256R1MLKEM768],
    }
}
