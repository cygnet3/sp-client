use electrum_client::{Client, ConfigBuilder};
use log::info;

const ELECTRS_URI: &str = "ssl://silentpayments.dev:51002";
const VALIDATE_DOMAIN: bool = false; // self-signed cert, so we don't validate

pub fn create_electrum_client() -> anyhow::Result<Client> {
    let config = ConfigBuilder::new()
        .validate_domain(VALIDATE_DOMAIN)
        .build();
    let electrum_client = Client::from_config(ELECTRS_URI, config)?;
    info!("ssl client {}", ELECTRS_URI);

    Ok(electrum_client)
}
