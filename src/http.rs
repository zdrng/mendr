//! Tiny blocking HTTP helpers on top of `ureq`, shared by OSV and adapters.
//!
//! Requests that fail with a transport error (connection, DNS, timeout),
//! HTTP 408, 429 or 5xx are retried up to [`RETRIES`] times with jittered
//! exponential backoff, waiting at least as long as the server's
//! `Retry-After` (capped at 30s). Other 4xx responses fail at once.

use std::io::Read;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

/// Maximum response body size (npm packuments can be large).
const BODY_LIMIT: u64 = 256 * 1024 * 1024;
/// Retries after the first attempt.
const RETRIES: u32 = 3;
/// Backoff before retry `n` (0-based) is `BACKOFF_BASE * 2^n`, minus up to
/// half of it as jitter.
const BACKOFF_BASE: Duration = if cfg!(test) {
    Duration::from_millis(1)
} else {
    Duration::from_secs(1)
};
/// Longest `Retry-After` honored.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);
/// Bytes of an error response read for [`HttpError`] messages.
const ERROR_BODY_BYTES: u64 = 4096;
/// Characters of an error response kept in [`HttpError`] messages.
const SNIPPET_CHARS: usize = 500;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("not found: {0}")]
    NotFound(String),
    /// HTTP 429, still returned after the retries.
    #[error("HTTP 429 (rate limited) from {url}{}", snippet_suffix(.body))]
    RateLimited { url: String, body: String },
    /// Any other status >= 400. `body` is the start of the response
    /// (whitespace collapsed, at most 500 characters).
    #[error("HTTP {status} from {url}{}", snippet_suffix(.body))]
    Status {
        url: String,
        status: u16,
        body: String,
    },
    #[error("request to {url} failed: {message}")]
    Transport {
        url: String,
        message: String,
        /// Whether trying again may help (connection, DNS, timeout, I/O).
        retryable: bool,
    },
}

fn snippet_suffix(body: &str) -> String {
    if body.is_empty() {
        String::new()
    } else {
        format!(": {body}")
    }
}

/// Shared agent: `mendr/<version>` user agent, status codes checked by
/// [`finish`]. Timeouts are per phase rather than one global deadline, so
/// large bodies (npm packuments) on slow links still complete: ureq has no
/// per-read idle timeout, so the body gets its own generous budget.
pub fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        let config = ureq::Agent::config_builder()
            .timeout_resolve(Some(Duration::from_secs(30)))
            .timeout_connect(Some(Duration::from_secs(30)))
            .timeout_send_request(Some(Duration::from_secs(30)))
            .timeout_send_body(Some(Duration::from_secs(60)))
            .timeout_recv_response(Some(Duration::from_secs(60)))
            .timeout_recv_body(Some(Duration::from_secs(600)))
            .http_status_as_error(false)
            .user_agent(concat!(
                "mendr/",
                env!("CARGO_PKG_VERSION"),
                " (https://github.com/zdrng/mendr)"
            ))
            .build();
        ureq::Agent::new_with_config(config)
    })
}

fn status_error(url: &str, status: u16, body: String) -> HttpError {
    match status {
        404 => HttpError::NotFound(url.to_string()),
        429 => HttpError::RateLimited {
            url: url.to_string(),
            body,
        },
        status => HttpError::Status {
            url: url.to_string(),
            status,
            body,
        },
    }
}

fn map_err(url: &str, e: ureq::Error) -> HttpError {
    let retryable = matches!(
        e,
        ureq::Error::Io(_)
            | ureq::Error::Timeout(_)
            | ureq::Error::HostNotFound
            | ureq::Error::ConnectionFailed
            | ureq::Error::Protocol(_)
    );
    match e {
        ureq::Error::StatusCode(status) => status_error(url, status, String::new()),
        other => HttpError::Transport {
            url: url.to_string(),
            message: other.to_string(),
            retryable,
        },
    }
}

/// One failed attempt, with the server's `Retry-After` if it sent one.
struct Failure {
    error: HttpError,
    retry_after: Option<Duration>,
}

impl From<HttpError> for Failure {
    fn from(error: HttpError) -> Self {
        Failure {
            error,
            retry_after: None,
        }
    }
}

fn retryable(e: &HttpError) -> bool {
    match e {
        HttpError::NotFound(_) => false,
        HttpError::RateLimited { .. } => true,
        HttpError::Status { status, .. } => *status == 408 || *status >= 500,
        HttpError::Transport { retryable, .. } => *retryable,
    }
}

/// Run `attempt` until it succeeds, fails for good, or the retries are used
/// up. `sleep` waits between attempts (injectable for tests).
fn with_retries<T>(
    url: &str,
    mut attempt: impl FnMut() -> Result<T, Failure>,
    mut sleep: impl FnMut(Duration),
) -> Result<T, HttpError> {
    let mut retry = 0;
    loop {
        match attempt() {
            Ok(v) => return Ok(v),
            Err(f) if retry < RETRIES && retryable(&f.error) => {
                let delay =
                    backoff(retry).max(f.retry_after.unwrap_or_default().min(MAX_RETRY_AFTER));
                show(&format!(
                    "{} (retry {}/{RETRIES} in {:.1}s: {})",
                    display_url(url),
                    retry + 1,
                    delay.as_secs_f64(),
                    f.error
                ));
                sleep(delay);
                retry += 1;
            }
            Err(f) => return Err(f.error),
        }
    }
}

/// `BACKOFF_BASE * 2^retry`, randomly shortened by up to half.
fn backoff(retry: u32) -> Duration {
    let full = BACKOFF_BASE * 2u32.pow(retry);
    full.mul_f64(1.0 - 0.5 * jitter())
}

/// Pseudo-random number in `[0, 1)`: xorshift64, seeded from the clock.
fn jitter() -> f64 {
    static STATE: AtomicU64 = AtomicU64::new(0);
    let mut x = STATE.load(Ordering::Relaxed);
    if x == 0 {
        x = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0x9e37_79b9_7f4a_7c15, |d| d.as_nanos() as u64)
            | 1;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    STATE.store(x, Ordering::Relaxed);
    (x >> 11) as f64 / (1u64 << 53) as f64
}

/// `Retry-After`: delay in seconds or an HTTP date.
fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    if let Ok(secs) = value.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let at = jiff::fmt::rfc2822::parse(value).ok()?.timestamp();
    let secs = at
        .as_second()
        .saturating_sub(jiff::Timestamp::now().as_second());
    Some(Duration::from_secs(secs.max(0) as u64))
}

/// Body of a successful response, or the error (with a body snippet and
/// `Retry-After`) for a status >= 400.
fn finish(
    url: &str,
    result: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<String, Failure> {
    let mut resp = result.map_err(|e| map_err(url, e))?;
    let status = resp.status().as_u16();
    if status < 400 {
        return Ok(resp
            .body_mut()
            .with_config()
            .limit(BODY_LIMIT)
            .read_to_string()
            .map_err(|e| map_err(url, e))?);
    }
    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_retry_after);
    let mut bytes = Vec::new();
    if status != 404 {
        let _ = resp
            .body_mut()
            .as_reader()
            .take(ERROR_BODY_BYTES)
            .read_to_end(&mut bytes);
    }
    Err(Failure {
        error: status_error(url, status, snippet(&String::from_utf8_lossy(&bytes))),
        retry_after,
    })
}

/// One line, at most [`SNIPPET_CHARS`] characters.
fn snippet(text: &str) -> String {
    let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match line.char_indices().nth(SNIPPET_CHARS) {
        Some((cut, _)) => format!("{}…", &line[..cut]),
        None => line,
    }
}

/// GET `url` and return the body as a string. Extra headers are optional.
pub fn get_string(url: &str, headers: &[(&str, &str)]) -> Result<String, HttpError> {
    show(&display_url(url));
    with_retries(
        url,
        || {
            let mut req = agent().get(url);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            finish(url, req.call())
        },
        std::thread::sleep,
    )
}

/// POST a JSON body to `url` and return the response body as a string.
pub fn post_json(url: &str, body: &serde_json::Value) -> Result<String, HttpError> {
    show(&display_url(url));
    with_retries(
        url,
        || finish(url, agent().post(url).send_json(body)),
        std::thread::sleep,
    )
}

/// `registry.npmjs.org/foo` for `https://registry.npmjs.org/foo`.
fn display_url(url: &str) -> String {
    url.strip_prefix("https://").unwrap_or(url).to_string()
}

/// Show the request on the progress status line.
fn show(text: &str) {
    crate::progress::detail(text);
}

/// A canned HTTP server on localhost for offline tests.
#[cfg(test)]
pub mod stub {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    /// A request as the stub saw it.
    #[derive(Clone, Debug)]
    pub struct Request {
        pub method: String,
        pub path: String,
        pub body: String,
    }

    /// `(status, extra headers, body)`.
    pub type Response = (u16, Vec<(&'static str, String)>, String);

    /// Serve `handler` on `127.0.0.1` (one connection per request, closed
    /// after the response) until the test process exits. Returns the base
    /// URL, e.g. `http://127.0.0.1:12345`.
    pub fn serve(handler: impl Fn(&Request) -> Response + Send + Sync + 'static) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            std::thread::scope(|s| {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    let handler = &handler;
                    s.spawn(move || {
                        let mut reader = BufReader::new(&stream);
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            return;
                        }
                        let mut parts = line.split_whitespace();
                        let method = parts.next().unwrap_or_default().to_string();
                        let path = parts.next().unwrap_or_default().to_string();
                        let mut length = 0;
                        loop {
                            let mut header = String::new();
                            if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                                break;
                            }
                            if let Some((k, v)) = header.split_once(':')
                                && k.eq_ignore_ascii_case("content-length")
                            {
                                length = v.trim().parse().unwrap_or(0);
                            }
                        }
                        let mut body = vec![0; length];
                        let _ = reader.read_exact(&mut body);
                        let request = Request {
                            method,
                            path,
                            body: String::from_utf8_lossy(&body).into_owned(),
                        };
                        let (status, headers, body) = handler(&request);
                        let mut out = format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                            body.len()
                        );
                        for (k, v) in headers {
                            out.push_str(&format!("{k}: {v}\r\n"));
                        }
                        out.push_str("\r\n");
                        out.push_str(&body);
                        let _ = (&stream).write_all(out.as_bytes());
                    });
                }
            });
        });
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    fn status(status: u16, retry_after: Option<u64>) -> Failure {
        Failure {
            error: status_error("u", status, String::new()),
            retry_after: retry_after.map(Duration::from_secs),
        }
    }

    #[test]
    fn errors_are_classified() {
        assert!(matches!(
            map_err("u", ureq::Error::StatusCode(404)),
            HttpError::NotFound(_)
        ));
        assert!(matches!(
            map_err("u", ureq::Error::StatusCode(429)),
            HttpError::RateLimited { .. }
        ));
        let e = map_err("u", ureq::Error::StatusCode(503));
        assert!(matches!(e, HttpError::Status { status: 503, .. }));
        assert!(retryable(&e));
        assert!(!retryable(&status_error("u", 400, String::new())));
        assert!(retryable(&status_error("u", 408, String::new())));
        assert!(!retryable(&status_error("u", 404, String::new())));
        let io = map_err(
            "u",
            ureq::Error::Io(std::io::ErrorKind::ConnectionReset.into()),
        );
        assert!(retryable(&io), "{io:?}");
        assert!(retryable(&map_err("u", ureq::Error::HostNotFound)));
        assert!(!retryable(&map_err("u", ureq::Error::BadUri("x".into()))));
        assert!(!retryable(&map_err("u", ureq::Error::BodyExceedsLimit(1))));
    }

    #[test]
    fn error_messages_carry_a_body_snippet() {
        let long = format!("oops\n  {}", "x".repeat(1000));
        let e = status_error("http://h/p", 500, snippet(&long));
        let text = e.to_string();
        assert!(
            text.starts_with("HTTP 500 from http://h/p: oops xxx"),
            "{text}"
        );
        assert_eq!(
            text.chars().count(),
            "HTTP 500 from http://h/p: ".len() + 501
        );
        assert_eq!(
            status_error("u", 502, String::new()).to_string(),
            "HTTP 502 from u"
        );
        assert_eq!(
            status_error("u", 429, "slow down".into()).to_string(),
            "HTTP 429 (rate limited) from u: slow down"
        );
    }

    #[test]
    fn retries_transient_failures_with_backoff() {
        let mut outcomes = vec![Err(status(503, None)), Err(status(429, Some(5)))].into_iter();
        let mut sleeps = Vec::new();
        let r = with_retries(
            "u",
            || outcomes.next().unwrap_or(Ok("done")),
            |d| sleeps.push(d),
        );
        assert_eq!(r.unwrap(), "done");
        assert_eq!(sleeps.len(), 2);
        assert!(sleeps[0] >= BACKOFF_BASE / 2 && sleeps[0] <= BACKOFF_BASE);
        assert_eq!(sleeps[1], Duration::from_secs(5), "Retry-After honored");
    }

    #[test]
    fn retry_after_is_capped_and_retries_are_bounded() {
        let calls = AtomicUsize::new(0);
        let sleeps = Mutex::new(Vec::new());
        let r: Result<(), _> = with_retries(
            "u",
            || {
                calls.fetch_add(1, Ordering::Relaxed);
                Err(status(503, Some(3600)))
            },
            |d| sleeps.lock().unwrap().push(d),
        );
        assert!(matches!(r, Err(HttpError::Status { status: 503, .. })));
        assert_eq!(calls.load(Ordering::Relaxed), 1 + RETRIES as usize);
        assert!(sleeps.lock().unwrap().iter().all(|d| *d == MAX_RETRY_AFTER));
    }

    #[test]
    fn permanent_failures_are_not_retried() {
        let mut calls = 0;
        let r: Result<(), _> = with_retries(
            "u",
            || {
                calls += 1;
                Err(status(403, None))
            },
            |_| panic!("no sleep expected"),
        );
        assert!(matches!(r, Err(HttpError::Status { status: 403, .. })));
        assert_eq!(calls, 1);
    }

    #[test]
    fn backoff_grows_with_jitter() {
        for retry in 0..RETRIES {
            let full = BACKOFF_BASE * 2u32.pow(retry);
            let d = backoff(retry);
            assert!(d > full / 2 - Duration::from_nanos(1) && d <= full, "{d:?}");
        }
        assert!((0..100).map(|_| jitter()).all(|j| (0.0..1.0).contains(&j)));
    }

    #[test]
    fn retry_after_formats() {
        assert_eq!(parse_retry_after(" 7 "), Some(Duration::from_secs(7)));
        assert_eq!(
            parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"),
            Some(Duration::ZERO),
            "dates in the past mean now"
        );
        let soon = jiff::Timestamp::now() + jiff::SignedDuration::from_secs(120);
        let header = jiff::fmt::rfc2822::DateTimePrinter::new()
            .timestamp_to_rfc9110_string(&soon)
            .unwrap();
        let d = parse_retry_after(&header).unwrap();
        assert!(
            d > Duration::from_secs(100) && d <= Duration::from_secs(120),
            "{d:?}"
        );
        assert_eq!(parse_retry_after("soon"), None);
    }

    #[test]
    fn get_string_against_stub_server() {
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let base = stub::serve(move |req| match req.path.as_str() {
            "/flaky" => {
                if seen.fetch_add(1, Ordering::Relaxed) < 2 {
                    (503, vec![("Retry-After", "0".into())], "busy".into())
                } else {
                    (200, vec![], "ok".into())
                }
            }
            "/missing" => (404, vec![], "nope".into()),
            "/bad" => (400, vec![], "bad <request>\n".repeat(100)),
            "/limited" => (429, vec![], "slow down".into()),
            _ => (500, vec![], String::new()),
        });
        assert_eq!(get_string(&format!("{base}/flaky"), &[]).unwrap(), "ok");
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        assert!(matches!(
            get_string(&format!("{base}/missing"), &[]),
            Err(HttpError::NotFound(_))
        ));
        match get_string(&format!("{base}/bad"), &[]) {
            Err(HttpError::Status {
                status: 400, body, ..
            }) => {
                assert!(body.starts_with("bad <request> bad"));
                assert_eq!(body.chars().count(), SNIPPET_CHARS + 1);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            get_string(&format!("{base}/limited"), &[]),
            Err(HttpError::RateLimited { body, .. }) if body == "slow down"
        ));
        let echo = stub::serve(|req| (200, vec![], format!("{} {}", req.method, req.body)));
        let text = post_json(&echo, &serde_json::json!({"a": 1})).unwrap();
        let (method, body) = text.split_once(' ').unwrap();
        assert_eq!(method, "POST");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            serde_json::json!({"a": 1})
        );
    }
}
