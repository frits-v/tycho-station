//! Bounded HTTP calls to the Restate admin API (HTTP/1.1) and the endpoint (h2c).

use std::io::Read;
use std::time::Duration;

use crate::config::HTTP_BODY_MAX_BYTES;

/// What came back from one request, before any decoder reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Response { status: u16, body: String },
    Unreachable(String),
    BodyTooLarge,
}

#[derive(Debug, Clone)]
pub struct Http {
    http1: reqwest::blocking::Client,
    http2: reqwest::blocking::Client,
}

impl Http {
    pub fn new(timeout: Duration) -> Result<Self, reqwest::Error> {
        Ok(Self {
            http1: reqwest::blocking::Client::builder()
                .timeout(timeout)
                .no_proxy()
                .build()?,
            http2: reqwest::blocking::Client::builder()
                .timeout(timeout)
                .no_proxy()
                .http2_prior_knowledge()
                .build()?,
        })
    }

    #[must_use]
    pub fn get(&self, url: &str) -> Outcome {
        read(self.http1.get(url).send())
    }

    /// The Restate SDK endpoint speaks HTTP/2 without TLS only.
    #[must_use]
    pub fn get_h2c(&self, url: &str) -> Outcome {
        read(self.http2.get(url).send())
    }

    /// A POST with no body and no content type, as Restate wants for a handler without input.
    #[must_use]
    pub fn post_empty(&self, url: &str) -> Outcome {
        read(self.http1.post(url).send())
    }

    #[must_use]
    pub fn post_json(&self, url: &str, body: String) -> Outcome {
        read(
            self.http1
                .post(url)
                .header("content-type", "application/json")
                .body(body)
                .send(),
        )
    }
}

impl Http {
    /// A POST with a content type and extra headers, such as an idempotency key.
    #[must_use]
    pub fn post(
        &self,
        url: &str,
        content_type: &str,
        headers: &[(&str, &str)],
        body: String,
    ) -> Outcome {
        let mut request = self
            .http1
            .post(url)
            .header("content-type", content_type)
            .body(body);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        read(request.send())
    }
}

fn read(sent: reqwest::Result<reqwest::blocking::Response>) -> Outcome {
    let response = match sent {
        Ok(response) => response,
        Err(error) => return Outcome::Unreachable(error.to_string()),
    };
    let status = response.status().as_u16();
    let limit = u64::try_from(HTTP_BODY_MAX_BYTES).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    if let Err(error) = response
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
    {
        return Outcome::Unreachable(error.to_string());
    }
    if bytes.len() > HTTP_BODY_MAX_BYTES {
        return Outcome::BodyTooLarge;
    }
    Outcome::Response {
        status,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn a_body_over_the_cap_is_too_large() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _read = std::io::Read::read(&mut stream, &mut request).unwrap();
            let length = HTTP_BODY_MAX_BYTES + 1;
            let head =
                format!("HTTP/1.1 200 OK\r\ncontent-length: {length}\r\nconnection: close\r\n\r\n");
            if stream.write_all(head.as_bytes()).is_err() {
                return;
            }
            if stream.write_all(&vec![b'a'; length]).is_err() {}
        });
        let http = Http::new(Duration::from_secs(5)).unwrap();
        let outcome = http.get(&format!("http://{address}/"));
        server.join().unwrap();
        assert_eq!(outcome, Outcome::BodyTooLarge);
    }
}
