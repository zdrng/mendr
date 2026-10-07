//! Tiny blocking HTTP helpers on top of `ureq`, shared by OSV and adapters.

use std::sync::OnceLock;
use std::time::Duration;

/// Maximum response body size (npm packuments can be large).
const BODY_LIMIT: u64 = 256 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("HTTP {status} from {url}")]
    Status { url: String, status: u16 },
    #[error("request to {url} failed: {message}")]
    Transport { url: String, message: String },
}

/// Shared agent: 60s global timeout, `mendr/<version>` user agent, HTTP
/// status codes >= 400 reported as errors.
pub fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            .user_agent(concat!(
                "mendr/",
                env!("CARGO_PKG_VERSION"),
                " (https://github.com/zdrng/mendr)"
            ))
            .build();
        ureq::Agent::new_with_config(config)
    })
}

fn map_err(url: &str, e: ureq::Error) -> HttpError {
    match e {
        ureq::Error::StatusCode(404) => HttpError::NotFound(url.to_string()),
        ureq::Error::StatusCode(status) => HttpError::Status {
            url: url.to_string(),
            status,
        },
        other => HttpError::Transport {
            url: url.to_string(),
            message: other.to_string(),
        },
    }
}

/// GET `url` and return the body as a string. Extra headers are optional.
pub fn get_string(url: &str, headers: &[(&str, &str)]) -> Result<String, HttpError> {
    let mut req = agent().get(url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let mut resp = req.call().map_err(|e| map_err(url, e))?;
    resp.body_mut()
        .with_config()
        .limit(BODY_LIMIT)
        .read_to_string()
        .map_err(|e| map_err(url, e))
}

/// POST a JSON body to `url` and return the response body as a string.
pub fn post_json(url: &str, body: &serde_json::Value) -> Result<String, HttpError> {
    let mut resp = agent()
        .post(url)
        .send_json(body)
        .map_err(|e| map_err(url, e))?;
    resp.body_mut()
        .with_config()
        .limit(BODY_LIMIT)
        .read_to_string()
        .map_err(|e| map_err(url, e))
}
