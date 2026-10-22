//! Unified addresses and viewing keys are shown as `u1…` and `uview1…` (ZIP 316 revision 0),
//! whatever the key crate's default encoding is.
//!
//! The NU7 key crate (zcash_keys 0.17) can encode unified addresses as revision 2 (`zu1…`
//! shielded-only, `tu1…` with a transparent receiver) and unified full viewing keys as
//! `uvf1…`; its pre-release default was revision 2, the final release prefers revision 0 and
//! falls back to revision 2 for what revision 0 cannot carry. Other wallets and the published
//! collection manifests use the revision-0 strings, and nothing in this wallet needs the
//! revision-2 metadata, so every string this wallet hands out or compares is re-encoded as
//! revision 0: decode whatever the crate produced, keep its data items, drop the metadata,
//! encode again. `zu1`/`tu1`/`uvf1` strings from others are accepted wherever a string is
//! parsed. Revisit when the ecosystem moves (2026-10-02; final crates 2026-10-22).

use zcash_address::unified::{self, Container, Encoding, Revision, Uitem};
use zcash_keys::address::UnifiedAddress;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::MainNetwork;

/// `s` re-encoded as revision 0 if it is a unified container of type `T` on any network.
fn to_r0<T: Encoding + Container>(s: &str) -> Option<String> {
    let (net, _revision, c) = T::decode(s).ok()?;
    let items = c.items().into_iter().map(Uitem::Data).collect();
    T::try_from_items(Revision::R0, items).ok().map(|r0| r0.encode(&net))
}

/// Any unified address string (`u1`, `zu1`, `tu1`) as `u1`; anything else unchanged.
pub fn as_u1(s: &str) -> String {
    to_r0::<unified::Address>(s).unwrap_or_else(|| s.to_owned())
}

/// Any unified full viewing key string (`uview1`, `uvf1`) as `uview1`; anything else unchanged.
pub fn as_uview1(s: &str) -> String {
    to_r0::<unified::Ufvk>(s).unwrap_or_else(|| s.to_owned())
}

/// The `u1…` encoding of `ua` on mainnet, every receiver kept.
pub fn encode_u1(ua: &UnifiedAddress) -> String {
    as_u1(&ua.encode(&MainNetwork))
}

/// The `uview1…` encoding of `ufvk` on mainnet.
///
/// The final key crate's `encode` returns an error only for a key with no ZIP 316 encoding at
/// any revision; every key this wallet derives has Sapling or Orchard items and so always
/// has one.
pub fn encode_uview1(ufvk: &UnifiedFullViewingKey) -> String {
    let s = ufvk
        .encode(&MainNetwork)
        .expect("a unified full viewing key with shielded items always has a ZIP 316 encoding");
    as_uview1(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_registry_address_and_key_round_trip_as_revision_0() {
        let a = crate::issuance_v1::REGISTRY_ADDRESS;
        assert!(a.starts_with("u1"));
        assert_eq!(as_u1(a), a);
        let ua = match zcash_keys::address::Address::decode(&MainNetwork, a) {
            Some(zcash_keys::address::Address::Unified(ua)) => ua,
            _ => panic!("not a unified address"),
        };
        assert_eq!(encode_u1(&ua), a);
        // Whatever revision the crate's own default produces, it must never reach the screen
        // or a file; and the revision-2 form of the same address re-encodes to the same `u1`.
        assert_eq!(as_u1(&ua.encode(&MainNetwork)), a);
        let r2 = ua.encode_revision(&MainNetwork, Revision::R2).expect("revision 2 encodes every address");
        assert!(r2.starts_with("zu1") || r2.starts_with("tu1"));
        assert_eq!(as_u1(&r2), a);

        let k = crate::issuance_v1::REGISTRY_UFVK;
        assert!(k.starts_with("uview1"));
        let ufvk = UnifiedFullViewingKey::decode(&MainNetwork, k).unwrap();
        assert_eq!(encode_uview1(&ufvk), k);
        assert_eq!(as_uview1(&ufvk.encode(&MainNetwork).unwrap()), k);
        let r2 = ufvk.encode_revision(&MainNetwork, Revision::R2).expect("revision 2 encodes every key");
        assert!(r2.starts_with("uvf1"));
        assert_eq!(as_uview1(&r2), k);
        assert_eq!(as_uview1("not a key"), "not a key");
    }
}
