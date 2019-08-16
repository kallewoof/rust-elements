//! Implemenation of SLIP-0077: Deterministic blinding key derivation
//! for Confidential Transactions
//!
//! Spec: https://github.com/satoshilabs/slips/blob/master/slip-0077.md

use bitcoin;
use bitcoin_hashes::{hmac, sha256, Hash, HashEngine};
use secp256k1;
use slip21;

const SLIP77_DERIVATION: &'static str = "SLIP-0077";

/// A SLIP-77 master blinding key used to derive shared blinding keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MasterBlindingKey(pub secp256k1::SecretKey);

impl MasterBlindingKey {
    /// Create a new master blinding key from a seed.
    pub fn new(seed: &[u8]) -> MasterBlindingKey {
        let master = slip21::Node::new_master(&seed);
        let child = master.derive_child(&SLIP77_DERIVATION.as_bytes());
        let key = child.key();
        assert_eq!(key.len(), 32);
        MasterBlindingKey(secp256k1::SecretKey::from_slice(key).expect("len is 32"))
    }

    /// Derive a blinding private key for a given scriptPubkey.
    pub fn derive_blinding_key(&self, script_pubkey: &bitcoin::Script) -> secp256k1::SecretKey {
        let mut engine: hmac::HmacEngine<sha256::Hash> = hmac::HmacEngine::new(&self.0[..]);
        engine.input(script_pubkey.as_bytes());

        let bytes = hmac::Hmac::<sha256::Hash>::from_engine(engine).into_inner();
        secp256k1::SecretKey::from_slice(&bytes[..]).expect("len is 32")
    }

    /// Derive a shared nonce from the master blinding key and a blinding pubkey.
    pub fn derive_shared_nonce(&self, other: &secp256k1::PublicKey) -> [u8; 32] {
        let shared_secret = secp256k1::ecdh::SharedSecret::new(&other, &self.0);
        sha256::Hash::hash(&shared_secret[..]).into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use secp256k1::SecretKey;

    #[test]
    fn test_slip77() {
        //! Test vector from libwally.

        let seed_hex = "731e9b42eb9774f8a6b51af35a06f6ef1cdb6cf04402163ceacf0c8bace2831a";
        let master = MasterBlindingKey::new(&hex::decode(&seed_hex).unwrap());

        let privkey_hex = "c2f338e32ad1a2bd9cac569e67728163bf4c326a1770ec2293ba65548a581e97";
        let privkey = SecretKey::from_slice(&hex::decode(privkey_hex).unwrap()).unwrap();
        assert_eq!(master.0, privkey);

        let scriptpk_hex = "a914afa92d77cd3541b443771649572db096cf49bf8c87";
        let scriptpk: bitcoin::Script = hex::decode(&scriptpk_hex).unwrap().clone().into();

        let blindingkey_hex = "02b067c374bb56c54c016fae29218c000ada60f81ef45b4aeebbeb24931bb8bc";
        let blindingkey = SecretKey::from_slice(&hex::decode(blindingkey_hex).unwrap()).unwrap();
        assert_eq!(master.derive_blinding_key(&scriptpk), blindingkey);
    }
}
