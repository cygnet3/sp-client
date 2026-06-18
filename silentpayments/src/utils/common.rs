#[cfg(feature = "encode")]
use core::fmt;

#[cfg(any(feature = "sending", feature = "receiving"))]
use crate::Error;
use crate::Result;
#[cfg(any(feature = "sending", feature = "receiving"))]
use crate::utils::hash::calculate_shared_secret_hash;
#[cfg(feature = "receiving")]
use crate::utils::receiving::PublicTweakData;
#[cfg(any(feature = "sending", feature = "receiving"))]
use crate::utils::script::is_eligible;
#[cfg(feature = "encode")]
use bech32::{FromBase32, ToBase32};
use secp256k1::PublicKey;
#[cfg(any(feature = "sending", feature = "receiving"))]
use secp256k1::constants::PUBLIC_KEY_SIZE;
#[cfg(any(feature = "sending", feature = "receiving"))]
use secp256k1::{Scalar, Secp256k1, SecretKey, ecdh::shared_secret_point};
#[cfg(all(feature = "serde", feature = "encode"))]
use serde::Deserializer;
#[cfg(all(feature = "serde", feature = "encode"))]
use serde::ser::Serializer;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Struct representing an OutPoint type.
///
/// This can be constructed from a rust-bitcoin outpoint:
/// ```
/// use silentpayments::utils::OutPoint;
/// use bitcoin::hashes::Hash;
/// # use std::str::FromStr;
/// # let bitcoin_outpoint = bitcoin::OutPoint::from_str(&format!("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f:0")).unwrap();
///
/// let outpoint = OutPoint::from_txid_bytes_and_vout(
///     bitcoin_outpoint.txid.to_byte_array(),
///     bitcoin_outpoint.vout
/// );
/// ```
/// Or alternatively
/// ```
/// use silentpayments::utils::OutPoint;
/// use bitcoin::consensus::serialize;
/// # use std::str::FromStr;
///
/// # let bitcoin_outpoint = bitcoin::OutPoint::from_str(&format!("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f:0")).unwrap();
/// let serialized: [u8; 36] = serialize(&bitcoin_outpoint).try_into().unwrap();
/// let outpoint = OutPoint::from_bytes(serialized);
/// ```
#[cfg(any(feature = "sending", feature = "receiving"))]
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct OutPoint(pub(crate) [u8; 36]);

#[cfg(any(feature = "sending", feature = "receiving"))]
impl OutPoint {
    /// Parse outpoin from a [String] txid and [u32] vout.
    /// This may fail if the txid is not a valid 32 byte hex string.
    pub fn from_txid_and_vout(txid: String, vout: u32) -> Result<Self> {
        let mut bytes: Vec<u8> = hex::decode(&txid)?;

        if bytes.len() != 32 {
            return Err(Error::GenericError(format!(
                "Invalid outpoint hex representation: {}",
                txid
            )));
        }

        // txid in string format is big endian and we need little endian
        bytes.reverse();

        let mut buffer = [0u8; 36];

        buffer[..32].copy_from_slice(&bytes);
        buffer[32..].copy_from_slice(&vout.to_le_bytes());
        Ok(Self(buffer))
    }

    /// Parse outpoint from a txid byte array, and a vout as a u32.
    /// Can be used to convert a rust-bitcoin OutPoint struct.
    pub fn from_txid_bytes_and_vout(txid: [u8; 32], vout: u32) -> Self {
        let mut buf = [0u8; 36];
        buf[..32].copy_from_slice(&txid);
        buf[32..].copy_from_slice(&vout.to_le_bytes());
        Self(buf)
    }

    pub fn from_bytes(bytes: [u8; 36]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 36] {
        self.0
    }
}

/// Parallel per-vin input data for BIP352 shared secret derivation.
///
/// All fields are indexed by input vin. Use [`Self::new`] and [`Self::push`] when building
/// from chain data.
#[cfg(any(feature = "sending", feature = "receiving"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionInputs {
    outpoints: Vec<OutPoint>,
    script_pubkeys: Vec<Vec<u8>>,
    input_pubkeys: Vec<Option<PublicKey>>,
}

#[cfg(any(feature = "sending", feature = "receiving"))]
impl TransactionInputs {
    /// Create an empty input set for incremental construction.
    pub fn new() -> Self {
        Self {
            outpoints: Vec::new(),
            script_pubkeys: Vec::new(),
            input_pubkeys: Vec::new(),
        }
    }
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            outpoints: Vec::with_capacity(capacity),
            script_pubkeys: Vec::with_capacity(capacity),
            input_pubkeys: Vec::with_capacity(capacity),
        }
    }

    /// Append one transaction input.
    pub fn push(
        &mut self,
        outpoint: OutPoint,
        script_pubkey: Vec<u8>,
        input_pubkey: Option<PublicKey>,
    ) {
        self.outpoints.push(outpoint);
        self.script_pubkeys.push(script_pubkey);
        self.input_pubkeys.push(input_pubkey);
    }

    pub fn len(&self) -> usize {
        self.outpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.outpoints.is_empty()
    }

    pub fn outpoints(&self) -> &[OutPoint] {
        &self.outpoints
    }

    pub fn script_pubkeys(&self) -> &[Vec<u8>] {
        &self.script_pubkeys
    }

    pub fn input_pubkeys(&self) -> &[Option<PublicKey>] {
        &self.input_pubkeys
    }

    pub fn input_pubkey(&self, vin: usize) -> Option<&PublicKey> {
        self.input_pubkeys.get(vin).and_then(|pk| pk.as_ref())
    }

    pub(crate) fn min_outpoint(&self) -> &OutPoint {
        self.outpoints.iter().min().expect("non-empty")
    }

    pub(crate) fn eligible_pubkeys(&self) -> Result<Vec<&PublicKey>> {
        let eligible: Vec<&PublicKey> = self
            .script_pubkeys
            .iter()
            .zip(&self.input_pubkeys)
            .filter_map(|(spk, pk)| pk.as_ref().filter(|_| is_eligible(spk)))
            .collect();
        if eligible.is_empty() {
            return Err(Error::GenericError("No eligible input pubkeys".to_owned()));
        }
        Ok(eligible)
    }

    pub(crate) fn eligible_pubkeys_sum(&self) -> Result<PublicKey> {
        let eligible_pubkeys = self.eligible_pubkeys()?;
        Ok(PublicKey::combine_keys(&eligible_pubkeys)?)
    }
}

/// Compute `private_key * public_key` as a secp256k1 [`PublicKey`].
///
/// # Arguments
///
/// * `public_key` - Either the recipient scan public key (sender) or the sum of all eligible inputs public keys (recipient).
/// * `private_key` - Either one or all private keys used in the inputs of the transaction (sender) or the private scan key (recipient).
///
/// # Returns
///
/// The shared secret as a [`PublicKey`].
///
/// # Errors
///
/// This function will error if:
///
/// * The elliptic curve computation results in an invalid public key.
///
/// Uses `shared_secret_point` for constant-time scalar multiplication.
#[cfg(any(feature = "sending", feature = "receiving"))]
pub(crate) fn ecdh_multiply(public_key: &PublicKey, private_key: &SecretKey) -> Result<PublicKey> {
    let mut ss_bytes = [0u8; 65];
    ss_bytes[0] = 0x04;
    ss_bytes[1..].copy_from_slice(&shared_secret_point(public_key, private_key));
    Ok(PublicKey::from_slice(&ss_bytes)?)
}

/// Represents the shared secret, one for each scan key in the outputs, which is either obtained from
/// * sum of all eligible inputs private keys multiplied with the input hash, multiplied with the scan public key, or
/// * sum of all eligible inputs public keys multiplied with the input hash, multiplied with the scan private key
/// Since sender and recipient are supposed to end up with the same shared secret, this is the final type used for both.
#[cfg(any(feature = "sending", feature = "receiving"))]
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct TransactionSharedSecret {
    ecdh_shared_secret: PublicKey,
    recipient_scan_key: PublicKey,
}

impl TransactionSharedSecret {
    #[cfg(feature = "sending")]
    pub(crate) fn from_sender_ecdh(
        ecdh_shared_secret: PublicKey,
        recipient_scan_key: PublicKey,
    ) -> Self {
        Self {
            ecdh_shared_secret,
            recipient_scan_key,
        }
    }

    /// Calculate the shared secret of a transaction as a receiver.
    ///
    /// # Arguments
    ///
    /// * `tweak_data` - The tweak data of the transaction, see [`PublicTweakData::new`].
    /// * `recipient_scan_key` - The scan private key used by the wallet.
    ///
    /// # Returns
    ///
    /// This function returns the shared secret of this transaction. This shared secret can be used to scan the transaction of outputs that are for the current user. See [`Receiver::scan_transaction`](crate::receiving::Receiver::scan_transaction).
    #[cfg(feature = "receiving")]
    pub fn new_from_public_tweak_data<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        tweak_data: &PublicTweakData,
        recipient_scan_key: &SecretKey,
    ) -> Result<Self> {
        Ok(Self {
            ecdh_shared_secret: ecdh_multiply(tweak_data.as_inner(), recipient_scan_key)?,
            recipient_scan_key: PublicKey::from_secret_key(&secp, recipient_scan_key),
        })
    }

    pub fn as_ecdh_shared_secret(&self) -> &PublicKey {
        &self.ecdh_shared_secret
    }

    pub fn into_ecdh_shared_secret(self) -> PublicKey {
        self.ecdh_shared_secret
    }

    pub fn as_recipient_scan_key(&self) -> &PublicKey {
        &self.recipient_scan_key
    }
}

#[cfg(any(feature = "sending", feature = "receiving"))]
pub(crate) fn calculate_t_n(
    ecdh_shared_secret: &TransactionSharedSecret,
    k: u32,
) -> Result<SecretKey> {
    let hash = calculate_shared_secret_hash(ecdh_shared_secret, k);
    let sk = SecretKey::from_slice(&hash)?;

    Ok(sk)
}

#[cfg(any(feature = "sending", feature = "receiving"))]
pub(crate) fn calculate_P_n(B_spend: &PublicKey, t_n: Scalar) -> Result<PublicKey> {
    let secp = Secp256k1::new();

    let P_n = B_spend.add_exp_tweak(&secp, &t_n)?;

    Ok(P_n)
}

/// The network format used for a [`SilentPaymentCode`].
///
/// There are three network types: Mainnet (`sp1..`), Testnet (`tsp1..`), and Regtest (`sprt1..`).
/// Signet uses the same network type as Testnet.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<Network> for &str {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => "bitcoin", // we use the same string as rust-bitcoin for compatibility
            Network::Regtest => "regtest",
            Network::Testnet => "testnet",
        }
    }
}

impl TryFrom<&str> for Network {
    type Error = crate::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let res = match value {
            "bitcoin" | "main" => Self::Mainnet, // We also take the core style argument
            "regtest" => Self::Regtest,
            "testnet" | "signet" | "test" => Self::Testnet, // core arg
            _ => return Err(Error::InvalidNetwork(value.to_string())),
        };
        Ok(res)
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum SpVersion {
    ZERO,
}

impl From<SpVersion> for u8 {
    fn from(value: SpVersion) -> Self {
        match value {
            SpVersion::ZERO => 0u8,
        }
    }
}

impl TryFrom<u8> for SpVersion {
    type Error = crate::Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ZERO),
            _ => Err(Error::GenericError(
                "Unknown silent payment version".to_string(),
            )),
        }
    }
}

/// Silent payment key material (version + scan pubkey + `m` pubkey), without network.
///
/// [`m_pubkey`](Self::m_pubkey) is the spend pubkey (`B_m` in BIP352):
/// the receiver's spend public key, which may be unlabeled (`B_spend`) or labeled
/// (`B_spend + m·G`).
#[cfg_attr(
    feature = "encode",
    doc = "\n\nNetwork is only needed for bech32m strings; construct a [`SilentPaymentCode`] when encoding or showing a code. Convert a code to key material with [`SilentPaymentKeyMaterial::from`]."
)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SilentPaymentKeyMaterial {
    version: SpVersion,
    scan_key: PublicKey,
    m_pubkey: PublicKey,
}

impl SilentPaymentKeyMaterial {
    /// Create silent payment key material from version, scan pubkey, and `m` pubkey.
    ///
    /// `m_pubkey` is the spend pubkey (`B_m`), which may be labeled or not.
    pub fn new(version: SpVersion, scan_key: PublicKey, m_pubkey: PublicKey) -> Self {
        Self {
            version,
            scan_key,
            m_pubkey,
        }
    }

    /// Create version-0 silent payment key material.
    ///
    /// `m_pubkey` is the spend pubkey (`B_m`), which may be labeled or not.
    pub fn new_v0(scan_key: PublicKey, m_pubkey: PublicKey) -> Self {
        Self::new(SpVersion::ZERO, scan_key, m_pubkey)
    }

    pub fn try_from_byte_array_v0(bytes: &[u8; PUBLIC_KEY_SIZE * 2]) -> Result<Self> {
        let scan_key = PublicKey::from_slice(&bytes[..PUBLIC_KEY_SIZE])?;
        let m_pubkey = PublicKey::from_slice(&bytes[PUBLIC_KEY_SIZE..])?;
        Ok(Self::new(SpVersion::ZERO, scan_key, m_pubkey))
    }

    pub fn version(&self) -> SpVersion {
        self.version
    }

    pub fn scan_key(&self) -> PublicKey {
        self.scan_key
    }

    /// The spend pubkey (`B_m` in BIP352).
    ///
    /// This may be the unlabeled spend pubkey, or a labeled one (`B_spend + m·G`).
    pub fn m_pubkey(&self) -> PublicKey {
        self.m_pubkey
    }
}

#[cfg(feature = "encode")]
impl From<SilentPaymentCode> for SilentPaymentKeyMaterial {
    fn from(value: SilentPaymentCode) -> Self {
        value.sp_key_material
    }
}

#[cfg(feature = "encode")]
impl From<&SilentPaymentCode> for SilentPaymentKeyMaterial {
    fn from(value: &SilentPaymentCode) -> Self {
        value.sp_key_material
    }
}

/// A silent payment code: [`SilentPaymentKeyMaterial`] plus [`Network`], serializable as bech32m.
#[cfg(feature = "encode")]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct SilentPaymentCode {
    sp_key_material: SilentPaymentKeyMaterial,
    network: Network,
}

#[cfg(feature = "serde")]
impl Serialize for SilentPaymentCode {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: String = (*self).into();
        serializer.serialize_str(&encoded)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SilentPaymentCode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let code_str: String = Deserialize::deserialize(deserializer)?;

        Self::try_from(code_str.as_str()).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "encode")]
impl SilentPaymentCode {
    fn from_key_material(sp_key_material: SilentPaymentKeyMaterial, network: Network) -> Self {
        Self {
            sp_key_material,
            network,
        }
    }

    /// Construct a [`SilentPaymentCode`] from its component parts.
    ///
    /// Combines scan/`m` pubkeys with a [`Network`] for bech32m string encoding.
    /// Convert back to network-agnostic keys with [`SilentPaymentKeyMaterial::from`].
    ///
    /// If you use your own bech32 parser, extract the HRP and payload, then call
    /// this method with the pubkeys and network.
    ///
    /// # Bech32 format (for external parsers)
    ///
    /// Silent payment codes use bech32m encoding with the following structure:
    /// - **HRP (Human Readable Part)**:
    ///   - Mainnet: `"sp"`
    ///   - Testnet/Signet: `"tsp"`
    ///   - Regtest: `"sprt"`
    /// - **Data**: a single 5-bit version digit, then the 66-byte payload
    ///   `serP(B_scan) ‖ serP(B_m)` converted to 5-bit characters.
    ///   `B_m` is the spend pubkey (labeled or not).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use secp256k1::PublicKey;
    /// use silentpayments::{Network, SilentPaymentCode, SpVersion};
    ///
    /// // After parsing bech32 yourself and extracting the pubkeys:
    /// let scan_key = PublicKey::from_slice(&scan_bytes)?;
    /// let m_pubkey = PublicKey::from_slice(&m_pubkey_bytes)?;
    ///
    /// let code = SilentPaymentCode::new(
    ///     SpVersion::ZERO,
    ///     scan_key,
    ///     m_pubkey,
    ///     Network::Mainnet,
    /// );
    ///
    /// // Sending APIs take the network-agnostic key material:
    /// let sp_key_material: silentpayments::SilentPaymentKeyMaterial = code.into();
    /// ```
    ///
    /// `m_pubkey` is the spend pubkey (`B_m`), which may be labeled or not.
    pub fn new(
        version: SpVersion,
        scan_key: PublicKey,
        m_pubkey: PublicKey,
        network: Network,
    ) -> Self {
        Self::from_key_material(
            SilentPaymentKeyMaterial::new(version, scan_key, m_pubkey),
            network,
        )
    }

    /// Calls [`Self::new`] with version set to [`SpVersion::ZERO`].
    ///
    /// `m_pubkey` is the spend pubkey (`B_m`), which may be labeled or not.
    pub fn new_v0(scan_key: PublicKey, m_pubkey: PublicKey, network: Network) -> Self {
        Self::new(SpVersion::ZERO, scan_key, m_pubkey, network)
    }

    pub fn scan_key(&self) -> PublicKey {
        self.sp_key_material.scan_key()
    }

    /// The spend pubkey (`B_m` in BIP352).
    ///
    /// This may be the unlabeled spend pubkey, or a labeled one (`B_spend + m·G`).
    pub fn m_pubkey(&self) -> PublicKey {
        self.sp_key_material.m_pubkey()
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn version(&self) -> SpVersion {
        self.sp_key_material.version()
    }
}

#[cfg(feature = "encode")]
impl fmt::Display for SilentPaymentCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", <Self as Into<String>>::into(*self))
    }
}

#[cfg(feature = "encode")]
impl TryFrom<&str> for SilentPaymentCode {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        let (hrp, data, _variant) = bech32::decode(s)?;

        if data.len() != 107 {
            return Err(Error::InvalidCode("Code length is wrong".to_owned()));
        }

        let version: SpVersion = data[0].to_u8().try_into()?;

        let network = match hrp.as_str() {
            "sp" => Network::Mainnet,
            "tsp" => Network::Testnet,
            "sprt" => Network::Regtest,
            _ => {
                return Err(Error::InvalidCode(format!(
                    "Wrong prefix, expected \"sp\", \"tsp\", or \"sprt\", got \"{}\"",
                    &hrp
                )));
            }
        };

        let data = Vec::<u8>::from_base32(&data[1..])?;

        let scan_key = PublicKey::from_slice(&data[..33])?;
        let m_pubkey = PublicKey::from_slice(&data[33..])?;

        Ok(Self::from_key_material(
            SilentPaymentKeyMaterial::new(version, scan_key, m_pubkey),
            network,
        ))
    }
}

#[cfg(feature = "encode")]
impl TryFrom<String> for SilentPaymentCode {
    type Error = Error;

    fn try_from(s: String) -> Result<Self> {
        s.as_str().try_into()
    }
}

#[cfg(feature = "encode")]
impl From<SilentPaymentCode> for String {
    fn from(val: SilentPaymentCode) -> Self {
        let hrp = match val.network {
            Network::Testnet => "tsp",
            Network::Regtest => "sprt",
            Network::Mainnet => "sp",
        };

        let version = bech32::u5::try_from_u8(val.version().into())
            .expect("SpVersion guarantees this conversion");

        let B_scan_bytes = val.scan_key().serialize();
        let B_m_bytes = val.m_pubkey().serialize();

        let mut data = [B_scan_bytes, B_m_bytes].concat().to_base32();

        data.insert(0, version);

        bech32::encode(hrp, data, bech32::Variant::Bech32m).expect("We know our hrps")
    }
}

pub(crate) struct NonEmptyArray<'a, T>(&'a [T]);

impl<'a, T> NonEmptyArray<'a, T> {
    pub fn new(arr: &'a [T]) -> crate::Result<Self> {
        if !arr.is_empty() {
            Ok(Self(arr))
        } else {
            Err(crate::Error::EmptyArray)
        }
    }

    pub fn as_inner(&'a self) -> &'a [T] {
        self.0
    }
}

impl<'a, T> NonEmptyArray<'a, T>
where
    T: Ord,
{
    pub fn min(&'a self) -> &'a T {
        self.0.iter().min().expect("Is non-empty")
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{consensus::serialize, hashes::Hash};

    use crate::utils;

    #[test]
    fn outpoint_parsing_equivalence() {
        // example outpoint from genesis block
        let txid = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let vout = 0;

        let sp_outpoint_from_txid_and_vout =
            utils::OutPoint::from_txid_and_vout(txid.to_string(), vout).unwrap();

        let outpoint = bitcoin::OutPoint::from_str(&format!("{txid}:{vout}")).unwrap();
        // consensus serialization of bitcoin outpoint struct to byte array
        let outpoint_bytes: [u8; 36] = serialize(&outpoint).try_into().unwrap();
        let sp_outpoint_from_bytes = utils::OutPoint::from_bytes(outpoint_bytes);

        let sp_outpoint_from_byte_array_and_vout =
            utils::OutPoint::from_txid_bytes_and_vout(outpoint.txid.to_byte_array(), outpoint.vout);

        assert_eq!(sp_outpoint_from_txid_and_vout, sp_outpoint_from_bytes);
        assert_eq!(sp_outpoint_from_bytes, sp_outpoint_from_byte_array_and_vout);
    }
}
