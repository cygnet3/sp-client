use std::time::Duration;

use bitcoin::{
    Txid,
    secp256k1::{PublicKey, SecretKey},
};
use electrum_streaming_client::{AsyncClient, Event, request, response::FullTx};
use futures::channel::mpsc::UnboundedReceiver;
use serde::{Deserialize, Serialize};
use tokio::{net::TcpStream, task::JoinHandle, time::timeout};
pub struct FrigateClient {
    pub host_url: String,
    pub client: AsyncClient,
    pub events: UnboundedReceiver<Event>,
    pub worker: JoinHandle<Result<(), std::io::Error>>,
    pub request_timeout: Duration,
}

#[derive(Serialize, Deserialize)]
pub struct SubscribeRequest {
    pub scan_priv_key: SecretKey,
    pub spend_pub_key: PublicKey,
    pub start_height: Option<u32>,
    pub labels: Option<Vec<u32>>,
}

#[derive(Serialize, Deserialize)]
pub struct UnsubscribeRequest {
    pub scan_priv_key: SecretKey,
    pub spend_pub_key: PublicKey,
}

#[derive(Debug)]
pub enum FrigateError {
    Serde(serde_json::Error),
    Generic(String),
}

impl FrigateClient {
    pub async fn connect(host_url: &str) -> Result<Self, FrigateError> {
        let stream = TcpStream::connect(host_url)
            .await
            .map_err(|_| FrigateError::Generic("Can't connect to socket".to_string()))?;

        let (reader, writer) = stream.into_split();
        let (client, events, worker) = AsyncClient::new_tokio(reader, writer);

        let worker: JoinHandle<Result<(), std::io::Error>> = tokio::spawn(async move {
            if let Err(e) = worker.await {
                return Err(e);
            }
            Ok(())
        });

        Ok(Self {
            host_url: host_url.to_string(),
            client,
            events,
            worker,
            request_timeout: Duration::from_secs(10),
        })
    }

    /// Sets a custom request timeout for this client.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Send a request to the Frigate electrum server and return if found
    // the transaction with the passed txid
    pub async fn get_transaction(&mut self, txid: Txid) -> Result<FullTx, FrigateError> {
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::GetTx { txid }),
        )
        .await
        .map_err(|_| FrigateError::Generic("GetTx request timed out".to_string()))?
        .map_err(|e| FrigateError::Generic(e.to_string()))?;
        Ok(res)
    }

    /// Send a request to the Frigate electrum server for version negotiation
    /// This is the first request that should be sent before subsequent one.
    pub async fn version(&mut self) -> Result<String, FrigateError> {
        let res = timeout(
            self.request_timeout,
            self.client.send_request(request::ServerVersion {
                client_name: "silent-payment-dev-kit".into(),
                protocol_version: request::SupportedVersion::Range(["1.4".into(), "1.6".into()]),
            }),
        )
        .await
        .map_err(|_| FrigateError::Generic("Version request timed out".to_string()))?
        .map_err(|e| FrigateError::Generic(e.to_string()))?;
        Ok(res.protocol_version)
    }

    /// Make a request to the Frigate electrum server to subscribe to the outputs beloging to the given silent payment address
    /// Once the server receives the request notification will be sent to the client everytime an ouput is found.
    ///
    /// See: <https://github.com/sparrowwallet/frigate#blockchainsilentpaymentssubscribe>
    pub async fn subscribe(&mut self, req: &SubscribeRequest) -> Result<String, FrigateError> {
        let subscribe_req = request::SpSubscribe {
            scan_priv_key: req.scan_priv_key,
            spend_pub_key: req.spend_pub_key,
            labels: req.labels.clone(),
            start_height: req.start_height,
        };

        let res = timeout(
            self.request_timeout,
            self.client.send_request(subscribe_req),
        )
        .await
        .map_err(|_| FrigateError::Generic("Subscribe request timed out".to_string()))?
        .map_err(|e| FrigateError::Generic(e.to_string()))?;
        Ok(res)
    }
}
