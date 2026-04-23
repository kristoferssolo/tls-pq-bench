use common::{KeyExchangeMode, ProtocolMode};

pub(super) const fn proto_order(proto: ProtocolMode) -> u8 {
    match proto {
        ProtocolMode::Raw => 0,
        ProtocolMode::Http1 => 1,
    }
}

pub(super) const fn mode_order(mode: KeyExchangeMode) -> u8 {
    match mode {
        KeyExchangeMode::X25519 => 0,
        KeyExchangeMode::Secp256r1 => 1,
        KeyExchangeMode::X25519Mlkem768 => 2,
        KeyExchangeMode::Secp256r1Mlkem768 => 3,
    }
}
