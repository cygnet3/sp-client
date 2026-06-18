use crate::utils::common::{OutPoint, TransactionSharedSecret};
use bitcoin_hashes::{Hash, HashEngine, sha256t_hash_newtype};
use secp256k1::{PublicKey, Scalar, SecretKey};

sha256t_hash_newtype! {
    struct InputsTag = hash_str("BIP0352/Inputs");

    /// BIP0352-tagged hash with tag \"Inputs\".
    ///
    /// This is used for computing the inputs hash.
    #[hash_newtype(forward)]
    struct InputsHash(_);

    struct LabelTag = hash_str("BIP0352/Label");

    /// BIP0352-tagged hash with tag \"Label\".
    ///
    /// This is used for computing the label tweak.
    #[hash_newtype(forward)]
    struct LabelHash(_);

    pub(crate) struct SharedSecretTag = hash_str("BIP0352/SharedSecret");

    /// BIP0352-tagged hash with tag \"SharedSecret\".
    ///
    /// This hash type is for computing the shared secret.
    #[hash_newtype(forward)]
    pub(crate) struct SharedSecretHash(_);
}

impl InputsHash {
    fn from_outpoint_and_A_sum(smallest_outpoint: &OutPoint, A_sum: PublicKey) -> InputsHash {
        let mut eng = InputsHash::engine();
        eng.input(&smallest_outpoint.0);
        eng.input(&A_sum.serialize());
        InputsHash::from_engine(eng)
    }

    fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

impl LabelHash {
    pub(crate) fn from_b_scan_and_m(b_scan: SecretKey, m: u32) -> LabelHash {
        let mut eng = LabelHash::engine();
        eng.input(&b_scan.secret_bytes());
        eng.input(&m.to_be_bytes());
        LabelHash::from_engine(eng)
    }

    pub(crate) fn to_scalar(self) -> Scalar {
        // This is statistically extremely unlikely to panic.
        Scalar::from_be_bytes(self.to_byte_array()).expect("hash value greater than curve order")
    }
}

impl SharedSecretHash {
    pub(crate) fn from_ecdh_and_k(ecdh: &TransactionSharedSecret, k: u32) -> SharedSecretHash {
        let mut eng = SharedSecretHash::engine();
        eng.input(&ecdh.as_ecdh_shared_secret().serialize());
        eng.input(&k.to_be_bytes());
        SharedSecretHash::from_engine(eng)
    }
}

pub(crate) fn calculate_input_hash(smaller_outpoint: &OutPoint, A_sum: PublicKey) -> Scalar {
    InputsHash::from_outpoint_and_A_sum(&smaller_outpoint, A_sum).to_scalar()
}

pub(crate) fn calculate_label_hash(b_scan: SecretKey, m: u32) -> Scalar {
    LabelHash::from_b_scan_and_m(b_scan, m).to_scalar()
}

pub(crate) fn calculate_shared_secret_hash(ecdh: &TransactionSharedSecret, k: u32) -> [u8; 32] {
    SharedSecretHash::from_ecdh_and_k(ecdh, k).to_byte_array()
}
