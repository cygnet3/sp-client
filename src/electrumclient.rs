use electrum_client::{ConfigBuilder, Client};

const ELECTRS_URI: &str = "ssl://170.75.163.219:51002";
const VALIDATE_DOMAIN: bool = false; // self-signed cert, so we don't validate

pub fn create_electrum_client() -> anyhow::Result<Client> {
    let config = ConfigBuilder::new().validate_domain(VALIDATE_DOMAIN).build();
    let electrum_client = Client::from_config(ELECTRS_URI, config)?;
    crate::stream::loginfo(format!("ssl client {}", ELECTRS_URI).as_str());

    Ok(electrum_client)
}
