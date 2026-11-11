//! The transport. [`DeviceApi`] is one call; [`HttpApi`] makes it over HTTPS with rustls (ring
//! only, no OpenSSL), redirects off and a timeout. A host or a test can supply its own.

use crate::error::DeviceError;
use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

/// One request: a path under the engine's address, an optional bearer token and a JSON body. The
/// body can hold a code or a key exchange message, so it is wiped on drop and **never printed**:
/// `Debug` shows the method, the path and the body's length only, so a logging wrapper or a test
/// double around [`DeviceApi`] cannot leak it.
pub struct Request {
    pub method: Method,
    pub path: String,
    pub bearer: Option<Zeroizing<String>>,
    pub body: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("body_len", &self.body.as_ref().map(|b| b.len()))
            .finish_non_exhaustive()
    }
}

/// One answer: the status, the `Retry-After` seconds when there is one, and the body (wiped on
/// drop; it can hold a session token). `Debug` shows the status and the body's length only.
pub struct Response {
    pub status: u16,
    pub retry_after: Option<u64>,
    pub body: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// One call to the engine. A failure to get any answer is [`DeviceError::Transport`].
pub trait DeviceApi: Send + Sync {
    fn send(&self, request: Request) -> impl Future<Output = Result<Response, DeviceError>> + Send;
}

/// Whether `address` is a URL whose host is a loopback **IP literal** (`127.0.0.1`, `[::1]`).
/// A name such as `localhost` is not: a name can be made to point anywhere. The app's "local only"
/// gate uses this, and [`HttpApi`] allows plain `http` only for such a host.
pub fn is_loopback_literal(address: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(address) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The real transport. `https` only, except `http` to a loopback IP literal (a local stack).
/// Redirects are off: a redirect could carry the bearer token somewhere else.
pub struct HttpApi {
    client: reqwest::Client,
    base: String,
    max_body: u64,
}

const TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The most a response body may be.
const MAX_BODY: u64 = 32 * 1024 * 1024;

impl HttpApi {
    /// `base` is the engine's address, such as `https://api.orbyn.dev`: no user info, query or
    /// path beyond `/`.
    pub fn new(base: &str) -> Result<Self, DeviceError> {
        let url = reqwest::Url::parse(base)
            .map_err(|_| DeviceError::InvalidInput("the engine address is not a valid URL"))?;
        let loopback = is_loopback_literal(base);
        let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && loopback);
        let plain = url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/";
        if !scheme_ok || !plain || url.host_str().is_none() {
            return Err(DeviceError::InvalidInput(
                "the engine address must be https (or http to 127.0.0.1 or [::1]) with no path",
            ));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .https_only(!loopback)
            .user_agent(concat!("orbyn-device-client/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| DeviceError::Transport)?;
        Ok(Self {
            client,
            base: url.as_str().trim_end_matches('/').to_owned(),
            max_body: MAX_BODY,
        })
    }

    /// A smaller cap on a response body, in bytes (the default is 32 MiB). It is enforced while
    /// reading, whether or not the server sent a `Content-Length`.
    pub fn with_body_limit(mut self, bytes: u64) -> Self {
        self.max_body = bytes;
        self
    }
}

impl DeviceApi for HttpApi {
    async fn send(&self, request: Request) -> Result<Response, DeviceError> {
        let url = format!("{}{}", self.base, request.path);
        let mut builder = match request.method {
            Method::Get => self.client.get(url),
            Method::Post => self.client.post(url),
            Method::Put => self.client.put(url),
            Method::Delete => self.client.delete(url),
        };
        if let Some(token) = &request.bearer {
            builder = builder.bearer_auth(token.as_str());
        }
        if let Some(body) = request.body {
            builder = builder
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        let mut response = builder.send().await.map_err(|_| DeviceError::Transport)?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        if response.content_length().is_some_and(|n| n > self.max_body) {
            return Err(DeviceError::Transport);
        }
        // Read with a running limit: a server that sends no Content-Length, or lies, is stopped too.
        let mut body = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| DeviceError::Transport)? {
            if body.len() as u64 + chunk.len() as u64 > self.max_body {
                return Err(DeviceError::Transport);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Response {
            status,
            retry_after,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_ip_literals_count_and_names_never_do() {
        for yes in [
            "http://127.0.0.1:18080",
            "https://127.0.0.1",
            "http://[::1]:8080/",
            "http://127.1:9/",
        ] {
            assert!(is_loopback_literal(yes), "{yes}");
        }
        for no in [
            "http://localhost:18080",
            "http://localhost.evil.example",
            "http://127.0.0.1.evil.example",
            "http://0.0.0.0:8080",
            "http://192.168.1.2",
            "https://api.orbyn.dev",
            "not a url",
            "http://[::ffff:8.8.8.8]",
            "",
        ] {
            assert!(!is_loopback_literal(no), "{no}");
        }
    }

    #[test]
    fn the_http_transport_refuses_plain_http_off_loopback_and_odd_addresses() {
        assert!(HttpApi::new("https://api.orbyn.dev").is_ok());
        assert!(HttpApi::new("http://127.0.0.1:18080").is_ok());
        for bad in [
            "http://api.orbyn.dev",
            "http://localhost:18080",
            "https://user:pw@api.orbyn.dev",
            "https://api.orbyn.dev/v1",
            "https://api.orbyn.dev/?x=1",
            "ftp://api.orbyn.dev",
            "nonsense",
        ] {
            assert!(HttpApi::new(bad).is_err(), "{bad}");
        }
    }
}
