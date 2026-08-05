//! HTTP/1.x request parsing (**Phase 3**).
//!
//! Finds the request head in a reassembled client-to-server stream and fills
//! the sticky buffers rules match against. This is where the Phase 2
//! normalization primitives finally get their caller: the URI a rule is tested
//! against is the **canonical** one, so `/foo/../etc/passwd` and
//! `%252e%252e%252fetc/passwd` reach detection as the same request the server
//! will serve.
//!
//! # Scope
//!
//! Requests only, and only their head. Response parsing and body framing follow
//! with the phases that need them; matching on a request line, its headers and
//! its URI is what unlocks the rules that exist.
//!
//! # Bounded, because the head arrives from the network
//!
//! A head with no terminator would otherwise buffer for ever, so it is capped.
//! Past the cap the parser gives up on that request and says so, rather than
//! growing — a client that never sends `\r\n\r\n` must not cost more than a
//! client that does.

use cybersentinel_reassembly::normalize::{normalize_path, NormalizationFlags, NormalizeOptions};

/// Largest request head the parser will buffer.
pub const DEFAULT_MAX_HEAD: usize = 64 << 10;

/// Headers kept per request, so a crafted request cannot cost unbounded
/// bookkeeping.
const MAX_HEADERS: usize = 128;

/// One parsed request head.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpRequest {
    /// The method, as written.
    pub method: Vec<u8>,
    /// The request target exactly as it arrived.
    pub raw_uri: Vec<u8>,
    /// The **normalized** path — what the server will resolve the target to.
    pub uri: Vec<u8>,
    /// What normalizing the URI had to do. Detection signal in its own right.
    pub normalization: NormalizationFlags,
    /// The protocol version token.
    pub version: Vec<u8>,
    /// The raw header block, headers separated by newlines.
    pub headers: Vec<u8>,
    /// The `User-Agent` value.
    pub user_agent: Option<Vec<u8>>,
    /// The `Host` value.
    pub host: Option<Vec<u8>>,
    /// The head exceeded the cap or was malformed; the fields are best effort.
    pub truncated: bool,
}

/// Running totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HttpCounters {
    /// Request heads parsed.
    pub requests: u64,
    /// Heads abandoned for exceeding the size cap.
    pub oversized: u64,
    /// Heads whose request line could not be read.
    pub malformed: u64,
}

/// Incremental request parser for one direction of one flow.
#[derive(Debug)]
pub struct HttpParser {
    buffer: Vec<u8>,
    max_head: usize,
    counters: HttpCounters,
    /// Set once a head is abandoned, so its body is not mistaken for requests.
    resynchronising: bool,
}

impl Default for HttpParser {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_HEAD)
    }
}

impl HttpParser {
    /// A parser that will buffer at most `max_head` bytes of head.
    #[must_use]
    pub fn new(max_head: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_head: max_head.max(64),
            counters: HttpCounters::default(),
            resynchronising: false,
        }
    }

    /// Running totals.
    #[must_use]
    pub fn counters(&self) -> HttpCounters {
        self.counters
    }

    /// Bytes currently held.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Offer newly reassembled client-to-server bytes.
    ///
    /// Returns every request head that became complete.
    pub fn push(&mut self, bytes: &[u8], options: &NormalizeOptions) -> Vec<HttpRequest> {
        self.buffer.extend_from_slice(bytes);
        let mut requests = Vec::new();

        loop {
            let Some(end) = find_head_end(&self.buffer) else {
                // No terminator yet. A head that will not end must not buffer
                // for ever.
                if self.buffer.len() > self.max_head {
                    self.counters.oversized += 1;
                    self.buffer.clear();
                    self.resynchronising = true;
                }
                break;
            };

            let head: Vec<u8> = self.buffer.drain(..end).collect();
            if self.resynchronising {
                // The tail of a head we already gave up on. Drop it and start
                // clean rather than parsing a fragment as a request.
                self.resynchronising = false;
                continue;
            }
            match parse_head(&head, options) {
                Some(request) => {
                    self.counters.requests += 1;
                    requests.push(request);
                }
                None => self.counters.malformed += 1,
            }
        }

        requests
    }
}

/// Find the end of a request head, including its terminator.
///
/// Both `\r\n\r\n` and the bare-LF `\n\n` are accepted: servers differ, and a
/// sensor that only understood the strict form would miss requests a lenient
/// server answers.
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    let crlf = buffer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4);
    let lf = buffer.windows(2).position(|w| w == b"\n\n").map(|p| p + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn parse_head(head: &[u8], options: &NormalizeOptions) -> Option<HttpRequest> {
    let mut lines = head.split(|byte| *byte == b'\n');
    let request_line = trim(lines.next()?);
    if request_line.is_empty() {
        return None;
    }

    // METHOD SP TARGET SP VERSION
    let mut parts = request_line.splitn(3, |byte| *byte == b' ');
    let method = trim(parts.next()?).to_vec();
    let raw_uri = trim(parts.next()?).to_vec();
    let version = parts.next().map(trim).unwrap_or_default().to_vec();

    if method.is_empty() || raw_uri.is_empty() {
        return None;
    }
    // A method that is not a token is not a request line; treating it as one
    // would let arbitrary binary traffic manufacture HTTP buffers.
    if !method.iter().all(|byte| byte.is_ascii_alphabetic()) {
        return None;
    }

    // The query string is left alone: path collapsing is a filesystem notion
    // and `..` inside a parameter is not a traversal.
    let path_end = raw_uri
        .iter()
        .position(|byte| *byte == b'?')
        .unwrap_or(raw_uri.len());
    let normalized = normalize_path(&raw_uri[..path_end], options);
    let mut uri = normalized.bytes;
    uri.extend_from_slice(&raw_uri[path_end..]);

    let mut request = HttpRequest {
        method,
        raw_uri,
        uri,
        normalization: normalized.flags,
        version,
        ..HttpRequest::default()
    };

    let mut seen = 0usize;
    for line in lines {
        let line = trim(line);
        if line.is_empty() {
            continue;
        }
        seen += 1;
        if seen > MAX_HEADERS {
            request.truncated = true;
            break;
        }
        if !request.headers.is_empty() {
            request.headers.push(b'\n');
        }
        request.headers.extend_from_slice(line);

        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = &line[..colon];
        let value = trim(&line[colon + 1..]);
        if name.eq_ignore_ascii_case(b"user-agent") {
            request.user_agent = Some(value.to_vec());
        } else if name.eq_ignore_ascii_case(b"host") {
            request.host = Some(value.to_vec());
        }
    }

    Some(request)
}

fn trim(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> NormalizeOptions {
        NormalizeOptions::default()
    }

    fn parse(stream: &[u8]) -> Vec<HttpRequest> {
        HttpParser::default().push(stream, &options())
    }

    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn parses_a_request_line_and_headers() {
        let requests = parse(
            b"GET /index.html HTTP/1.1\r\nHost: example.invalid\r\nUser-Agent: curl/8\r\n\r\n",
        );
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(text(&request.method), "GET");
        assert_eq!(text(&request.uri), "/index.html");
        assert_eq!(text(&request.version), "HTTP/1.1");
        assert_eq!(
            request.host.as_deref().map(text).as_deref(),
            Some("example.invalid")
        );
        assert_eq!(
            request.user_agent.as_deref().map(text).as_deref(),
            Some("curl/8")
        );
        assert!(text(&request.headers).contains("Host: example.invalid"));
    }

    /// The point of the whole exercise: a rule on the URI matches whatever
    /// spelling arrived, because the buffer holds what the server will resolve.
    #[test]
    fn the_uri_buffer_is_normalized() {
        for spelling in [
            "/etc/passwd",
            "/foo/../etc/passwd",
            "/etc/./passwd",
            "/%65tc/passwd",
            "/%252e%252e%252fetc/passwd",
        ] {
            let stream = format!("GET {spelling} HTTP/1.1\r\n\r\n");
            let requests = parse(stream.as_bytes());
            assert_eq!(
                text(&requests[0].uri),
                "/etc/passwd",
                "{spelling} did not normalize"
            );
        }
    }

    #[test]
    fn the_raw_uri_is_kept_alongside_the_normalized_one() {
        let requests = parse(b"GET /a/../b HTTP/1.1\r\n\r\n");
        assert_eq!(text(&requests[0].raw_uri), "/a/../b");
        assert_eq!(text(&requests[0].uri), "/b");
    }

    #[test]
    fn normalization_flags_survive_onto_the_request() {
        let requests = parse(b"GET /%252e%252e/x HTTP/1.1\r\n\r\n");
        assert!(requests[0].normalization.double_encoded);
        assert!(requests[0].normalization.traversal);
    }

    #[test]
    fn the_query_string_is_not_path_collapsed() {
        // `..` in a parameter is not a traversal, and rewriting it would change
        // the request the server sees.
        let requests = parse(b"GET /search?q=../etc HTTP/1.1\r\n\r\n");
        assert_eq!(text(&requests[0].uri), "/search?q=../etc");
    }

    #[test]
    fn several_requests_in_one_stream_are_all_returned() {
        let requests = parse(b"GET /one HTTP/1.1\r\n\r\nGET /two HTTP/1.1\r\n\r\n");
        assert_eq!(requests.len(), 2);
        assert_eq!(text(&requests[1].uri), "/two");
    }

    #[test]
    fn a_request_split_across_deliveries_is_parsed_once_complete() {
        let mut parser = HttpParser::default();
        assert!(parser.push(b"GET /split", &options()).is_empty());
        assert!(parser.push(b" HTTP/1.1\r\nHost: x", &options()).is_empty());

        let requests = parser.push(b"\r\n\r\n", &options());
        assert_eq!(requests.len(), 1);
        assert_eq!(text(&requests[0].uri), "/split");
    }

    #[test]
    fn a_bare_lf_terminator_is_accepted() {
        // Lenient servers answer these, so a sensor that insisted on CRLF would
        // be looking at a request nobody served and missing one somebody did.
        let requests = parse(b"GET /lenient HTTP/1.0\n\n");
        assert_eq!(requests.len(), 1);
        assert_eq!(text(&requests[0].uri), "/lenient");
    }

    #[test]
    fn non_http_traffic_produces_no_requests() {
        assert!(parse(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\r\n\r\n").is_empty());
        assert!(parse(&[0xff; 64]).is_empty());
        assert!(parse(b"SSH-2.0-OpenSSH_9.6\r\n\r\n").is_empty());
    }

    #[test]
    fn an_oversized_head_is_abandoned_rather_than_buffered() {
        let mut parser = HttpParser::new(1_024);
        for _ in 0..64 {
            parser.push(&[b'A'; 64], &options());
        }
        // The property is that memory stays bounded, however much arrives; a
        // long enough stream of headerless bytes is abandoned more than once.
        assert!(
            parser.buffered() <= 1_024 + 64,
            "buffered {}",
            parser.buffered()
        );
        assert!(parser.counters().oversized >= 1);
    }

    #[test]
    fn parsing_resumes_cleanly_after_an_abandoned_head() {
        let mut parser = HttpParser::new(256);
        parser.push(&[b'A'; 512], &options());
        // The tail of the abandoned head is discarded, not parsed.
        parser.push(b"junk\r\n\r\n", &options());
        let requests = parser.push(b"GET /after HTTP/1.1\r\n\r\n", &options());
        assert_eq!(requests.len(), 1);
        assert_eq!(text(&requests[0].uri), "/after");
    }

    #[test]
    fn the_header_count_is_capped() {
        let mut stream = b"GET / HTTP/1.1\r\n".to_vec();
        for index in 0..500 {
            stream.extend_from_slice(format!("X-Pad-{index}: v\r\n").as_bytes());
        }
        stream.extend_from_slice(b"\r\n");
        let requests = parse(&stream);
        assert!(requests[0].truncated);
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let inputs: [&[u8]; 7] = [
            b"",
            b"\r\n\r\n",
            b"\n\n",
            b"GET\r\n\r\n",
            b"GET  \r\n\r\n",
            b" / HTTP/1.1\r\n\r\n",
            &[0x00; 512],
        ];
        for input in inputs {
            let _ = parse(input);
        }
    }
}
