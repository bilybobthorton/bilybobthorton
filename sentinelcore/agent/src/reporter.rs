/// HTTP reporter — ships alerts to the SentinelCore API backend.
/// Batches alerts and retries on transient failures.
use crate::alert::Alert;
use anyhow::Result;
use crossbeam_channel::Receiver;
use reqwest::Client;
use serde::Serialize;
use std::time::Duration;
use tracing::{debug, error, info, warn};

#[derive(Debug, Serialize)]
struct AlertPayload<'a> {
    agent_id: &'a str,
    hostname: &'a str,
    alert: &'a Alert,
}

pub struct Reporter {
    client: Client,
    api_url: String,
    api_key: String,
    agent_id: String,
    hostname: String,
}

impl Reporter {
    pub fn new(
        api_url: String,
        api_key: String,
        agent_id: String,
        hostname: String,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("SentinelCore-Agent/0.1")
            .build()?;

        Ok(Self {
            client,
            api_url,
            api_key,
            agent_id,
            hostname,
        })
    }

    pub async fn run(&self, rx: Receiver<Alert>) {
        info!("Reporter started — shipping alerts to {}", self.api_url);

        loop {
            // Block until an alert arrives (no async recv on crossbeam, so spawn_blocking equivalent)
            let alert = match rx.recv() {
                Ok(a) => a,
                Err(_) => {
                    info!("Alert channel closed — reporter shutting down");
                    break;
                }
            };

            debug!("Sending alert: {:?}", alert.kind);
            self.send_with_retry(&alert).await;
        }
    }

    async fn send_with_retry(&self, alert: &Alert) {
        let payload = AlertPayload {
            agent_id: &self.agent_id,
            hostname: &self.hostname,
            alert,
        };

        let url = format!("{}/api/v1/agent/alert", self.api_url);

        for attempt in 1..=4u32 {
            match self
                .client
                .post(&url)
                .header("X-API-Key", &self.api_key)
                .json(&payload)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    debug!("Alert shipped: {}", alert.id);
                    return;
                }
                Ok(resp) => {
                    warn!(
                        "Alert rejected (attempt {}): HTTP {} for alert {}",
                        attempt,
                        resp.status(),
                        alert.id
                    );
                }
                Err(e) => {
                    warn!("Alert send failed (attempt {}): {}", attempt, e);
                }
            }

            if attempt < 4 {
                let backoff = Duration::from_secs(2u64.pow(attempt - 1));
                tokio::time::sleep(backoff).await;
            }
        }

        error!(
            "Failed to ship alert {} after 4 attempts — dropping",
            alert.id
        );
    }
}

/// Logs all alerts locally regardless of API availability.
pub async fn log_alerts_locally(rx: Receiver<Alert>) {
    loop {
        match rx.recv() {
            Ok(alert) => {
                tracing::warn!(
                    alert_id = %alert.id,
                    kind = ?alert.kind,
                    severity = ?alert.severity,
                    title = %alert.title,
                    "ALERT"
                );
            }
            Err(_) => break,
        }
    }
}
