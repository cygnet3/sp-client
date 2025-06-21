//! Example of using sp_client in a WASM environment
//! 
//! This example shows how to create a basic silent payment client
//! and generate receiving addresses in a WASM context.

use sp_client::{SpClient, SpendKey};
use bitcoin::{Network, secp256k1::SecretKey};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

/// Create a new silent payment client for WASM
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn create_client(scan_key_hex: &str, network: &str) -> Result<String, JsValue> {
    // Parse the scan key
    let scan_key_bytes = hex::decode(scan_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid scan key: {}", e)))?;
    let scan_sk = SecretKey::from_slice(&scan_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {}", e)))?;
    
    // Parse network
    let network = match network {
        "bitcoin" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => return Err(JsValue::from_str("Invalid network")),
    };
    
    // Create spend key (using scan key as spend key for this example)
    let spend_key = SpendKey::Secret(scan_sk);
    
    // Create client
    let client = SpClient::new(scan_sk, spend_key, network)
        .map_err(|e| JsValue::from_str(&format!("Failed to create client: {}", e)))?;
    
    // Get receiving address
    let address = client.get_receiving_address();
    
    Ok(address.to_string())
}

/// Get client fingerprint for WASM
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn get_fingerprint(scan_key_hex: &str, network: &str) -> Result<String, JsValue> {
    // Parse the scan key
    let scan_key_bytes = hex::decode(scan_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid scan key: {}", e)))?;
    let scan_sk = SecretKey::from_slice(&scan_key_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {}", e)))?;
    
    // Parse network
    let network = match network {
        "bitcoin" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => return Err(JsValue::from_str("Invalid network")),
    };
    
    // Create spend key (using scan key as spend key for this example)
    let spend_key = SpendKey::Secret(scan_sk);
    
    // Create client
    let client = SpClient::new(scan_sk, spend_key, network)
        .map_err(|e| JsValue::from_str(&format!("Failed to create client: {}", e)))?;
    
    // Get fingerprint
    let fingerprint = client.get_client_fingerprint()
        .map_err(|e| JsValue::from_str(&format!("Failed to get fingerprint: {}", e)))?;
    
    Ok(hex::encode(fingerprint))
}

// Non-WASM example for testing
#[cfg(not(target_arch = "wasm32"))]
pub fn create_client_example() -> Result<String, Box<dyn std::error::Error>> {
    // Create a test scan key
    let scan_sk = SecretKey::from_slice(&[0x01; 32])?;
    let spend_key = SpendKey::Secret(scan_sk);
    
    // Create client for testnet
    let client = SpClient::new(scan_sk, spend_key, Network::Testnet)?;
    
    // Get receiving address
    let address = client.get_receiving_address();
    
    Ok(address.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_create_client() {
        let result = create_client_example();
        assert!(result.is_ok());
        let address = result.unwrap();
        assert!(address.starts_with("sp"));
    }
} 