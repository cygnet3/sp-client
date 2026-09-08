use bitcoin::{
    bip32::{DerivationPath, Fingerprint},
    CompressedPublicKey,
};
use psbt_v2::v2::Input;
use secp256k1::PublicKey;

pub trait Bip375UpdaterExt {
    fn get_sp_spend_bip32_derivation(&self) -> Option<(PublicKey, Fingerprint, DerivationPath)>;

    fn set_sp_spend_bip32_derivation(
        &mut self,
        spend_pubkey: CompressedPublicKey,
        fingerprint: Fingerprint,
        path: DerivationPath,
    ) -> Option<(Fingerprint, DerivationPath)>;

    fn get_bip32_derivation(&self) -> Option<(PublicKey, Fingerprint, DerivationPath)>;

    fn set_bip32_derivation(
        &mut self,
        pubkey: &PublicKey,
        fingerprint: Fingerprint,
        path: DerivationPath,
    ) -> Option<(Fingerprint, DerivationPath)>;

    fn set_sp_tweak(&mut self, tweak: [u8; 32]) -> Option<[u8; 32]>;
}

impl Bip375UpdaterExt for Input {
    fn get_sp_spend_bip32_derivation(&self) -> Option<(PublicKey, Fingerprint, DerivationPath)> {
        let (compressed_spend_pubkey, key_source) =
            self.sp_spend_bip32_derivations.iter().next()?; // For now we can only have one key
        Some((
            compressed_spend_pubkey.0,
            key_source.0,
            key_source.1.clone(),
        ))
    }

    fn set_sp_spend_bip32_derivation(
        &mut self,
        spend_pubkey: CompressedPublicKey,
        fingerprint: Fingerprint,
        path: DerivationPath,
    ) -> Option<(Fingerprint, DerivationPath)> {
        let key_source = (fingerprint, path);
        self.sp_spend_bip32_derivations
            .insert(spend_pubkey, key_source)
    }

    fn get_bip32_derivation(&self) -> Option<(PublicKey, Fingerprint, DerivationPath)> {
        let (compressed_pubkey, key_source) = self.bip32_derivations.iter().next()?; // For now we can only have one key
        Some((compressed_pubkey.inner, key_source.0, key_source.1.clone()))
    }

    fn set_bip32_derivation(
        &mut self,
        pubkey: &PublicKey,
        fingerprint: Fingerprint,
        path: DerivationPath,
    ) -> Option<(Fingerprint, DerivationPath)> {
        self.bip32_derivations
            .insert(bitcoin::PublicKey::new(*pubkey), (fingerprint, path))
    }

    fn set_sp_tweak(&mut self, tweak: [u8; 32]) -> Option<[u8; 32]> {
        let previous_tweak = if let Some(existing_tweak) = self.sp_tweak {
            if existing_tweak == tweak {
                return Some(tweak);
            } else {
                Some(existing_tweak)
            }
        } else {
            None
        };
        self.sp_tweak = Some(tweak);
        previous_tweak
    }
}
