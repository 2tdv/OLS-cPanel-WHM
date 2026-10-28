//! Everything the activator observes or changes outside its state directory, behind one trait so the
//! decision logic is testable without root: the systemd unit, OLS processes, the loopback marker and
//! vhost health endpoints, and time. Every subprocess is bounded: it leads its own process group, which is
//! killed at its time limit (review RV-29, finding 4).

use crate::engine::command::{self, Failure};
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const UNIT: &str = "ols-cpanel.service";
pub const PROCESS_PATTERN: &str = "^openlitespeed \\(lshttpd";
/// `systemctl is-active`, `pgrep` and `pkill` answer at once; one that hangs is killed after this long.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// The HTTPS health client: the broker has no TLS library (review RV-29, finding 12).
pub const CURL: &str = "/usr/bin/curl";
/// What a TLS health request may print (the body counts up to 4096 bytes, like `ols_generation.health_body`).
const MAX_CURL_OUTPUT: usize = 1 << 20;
/// The output of systemctl, pgrep and pkill is discarded; anything larger than this is not theirs.
const MAX_PROBE_OUTPUT: usize = 64 << 10;

pub trait Runtime {
    /// `systemctl is-active --quiet ols-cpanel.service` succeeded.
    fn service_active(&self) -> bool;
    /// `systemctl <action> ols-cpanel.service` (reload, start, stop), killed after `timeout`; the exit status
    /// (negative signal: -9 when it was killed).
    fn systemctl(&self, action: &str, timeout: Duration) -> i32;
    /// `pgrep -f '^openlitespeed \(lshttpd'` found a process.
    fn ols_process(&self) -> bool;
    /// `pkill -KILL -f '^openlitespeed \(lshttpd'`.
    fn kill_ols(&self);
    /// GET `url`: Some(body) for a 2xx answer whose body is UTF-8 (stripped), None otherwise.
    fn marker(&self, url: &str, timeout: Duration) -> Option<String>;
    /// GET `url` with `Host: host`: the body (lossy UTF-8, stripped) or "error: HTTP <code>" /
    /// "error: <Python exception class name>". An `https://<IPv4>:<port>/...` URL is requested over TLS from that
    /// address with `host` as the SNI name and the Host header, without certificate verification or redirects;
    /// only a 200 answer passes its body (`ols_generation.health_body`).
    fn health(&self, url: &str, host: &str, timeout: Duration) -> String;
    fn sleep(&self, duration: Duration);
    /// Wall clock, seconds since the epoch (`time.time()`).
    fn now(&self) -> f64;
    /// Monotonic clock in seconds (`time.monotonic()`).
    fn monotonic(&self) -> f64;
}

/// Runs a fixed argv through the engine's command runner (own process group, fixed environment, the group
/// killed at `timeout`): the exit status, -9 when killed, 127 when it could not start.
fn bounded(argv: &[&str], timeout: Duration) -> i32 {
    match command::run(argv, timeout, MAX_PROBE_OUTPUT) {
        Ok(out) => out.code,
        Err(Failure::Timeout | Failure::TooLarge) => -9,
        Err(Failure::Spawn(_)) => 127,
    }
}

/// The production runtime: systemctl, pgrep/pkill, plain HTTP/1.1 over TCP and HTTPS through curl.
pub struct SystemRuntime {
    started: Instant,
    /// The HTTPS health client (tests substitute a script).
    pub curl: PathBuf,
}

impl SystemRuntime {
    pub fn new() -> SystemRuntime {
        SystemRuntime { started: Instant::now(), curl: PathBuf::from(CURL) }
    }
}

impl Default for SystemRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime for SystemRuntime {
    fn service_active(&self) -> bool {
        bounded(&["/usr/bin/systemctl", "is-active", "--quiet", UNIT], PROBE_TIMEOUT) == 0
    }

    fn systemctl(&self, action: &str, timeout: Duration) -> i32 {
        bounded(&["/usr/bin/systemctl", action, UNIT], timeout)
    }

    fn ols_process(&self) -> bool {
        // A pgrep that cannot run or does not answer proves nothing: count OLS as running (fail closed).
        let code = bounded(&["/usr/bin/pgrep", "-f", PROCESS_PATTERN], PROBE_TIMEOUT);
        code == 0 || code == 127 || code < 0
    }

    fn kill_ols(&self) {
        bounded(&["/usr/bin/pkill", "-KILL", "-f", PROCESS_PATTERN], PROBE_TIMEOUT);
    }

    fn marker(&self, url: &str, timeout: Duration) -> Option<String> {
        match http_get(url, None, timeout) {
            Ok(Response { status: 200..=299, body }) => String::from_utf8(body).ok().map(|t| super::pystr::strip(&t).to_string()),
            _ => None,
        }
    }

    fn health(&self, url: &str, host: &str, timeout: Duration) -> String {
        if url.starts_with("https://") {
            return https_health(&self.curl, url, host, timeout);
        }
        match http_get(url, Some(host), timeout) {
            Ok(Response { status: 200..=299, body }) => super::pystr::strip(&String::from_utf8_lossy(&body)).to_string(),
            Ok(Response { status, .. }) => format!("error: HTTP {status}"),
            Err(name) => format!("error: {name}"),
        }
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn now(&self) -> f64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
    }

    fn monotonic(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }
}

/// A TLS SNI and Host name the health client sends: letters, digits, dots and hyphens, starting with a letter or
/// digit (health targets carry the builder's domain grammar or `*.invalid` names).
fn sni_name(host: &str) -> bool {
    let b = host.as_bytes();
    !b.is_empty() && b.len() <= 253 && b[0].is_ascii_alphanumeric() && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'.' || *c == b'-')
}

/// The fixed curl argv of an HTTPS health request (review RV-29, finding 12): no configuration file (`-q`
/// first), no proxy, HTTP/1.1 over https only, the certificate not verified (`--insecure`: the check proves which
/// generation answers on the local server, not the server's identity), no redirect followed (no `--location`),
/// `host` resolved to the URL's IPv4 address (`--resolve`, so `host` is the SNI name) and sent as the Host header,
/// connection and whole request bounded by `timeout`; stdout is the body followed by a line with the status.
pub fn curl_argv(curl: &Path, url: &str, host: &str, timeout: Duration) -> Result<Vec<OsString>, &'static str> {
    let rest = url.strip_prefix("https://").ok_or("InvalidURL")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (address, port) = authority.rsplit_once(':').ok_or("InvalidURL")?;
    let address: Ipv4Addr = address.parse().map_err(|_| "InvalidURL")?;
    let port: u16 = port.parse().ok().filter(|p| *p != 0).ok_or("InvalidURL")?;
    if !path.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("InvalidURL");
    }
    if !sni_name(host) {
        return Err("ValueError");
    }
    let seconds = format!("{:.3}", timeout.as_secs_f64());
    let resolve = format!("{host}:{port}:{address}");
    let header = format!("Host: {host}");
    let target = format!("https://{host}:{port}{path}");
    let mut argv: Vec<OsString> = vec![curl.into()];
    for arg in [
        "-q", "--silent", "--show-error", "--insecure", "--http1.1", "--proto", "=https", "--noproxy", "*",
        "--max-redirs", "0", "--connect-timeout", &seconds, "--max-time", &seconds, "--resolve", &resolve,
        "--header", &header, "--output", "-", "--write-out", "\n%{http_code}", &target,
    ] {
        argv.push(arg.into());
    }
    Ok(argv)
}

/// The health answer of a curl run: the body (at most 4096 bytes, lossy UTF-8, stripped) for a 200, "error: HTTP
/// <status>" for any other status, otherwise "error: <the Python exception class>" `ols_generation.health_body`
/// reports for that failure.
pub fn curl_answer(result: Result<command::Output, Failure>) -> String {
    let out = match result {
        Ok(out) => out,
        Err(Failure::Timeout) => return "error: timeout".into(),
        Err(Failure::TooLarge) => return "error: IncompleteRead".into(),
        Err(Failure::Spawn(_)) => return "error: FileNotFoundError".into(),
    };
    let name = match out.code {
        0 => {
            let Some(i) = out.stdout.iter().rposition(|b| *b == b'\n') else { return "error: BadStatusLine".into() };
            let (body, status) = (&out.stdout[..i], &out.stdout[i + 1..]);
            return match std::str::from_utf8(status).ok().and_then(|s| s.trim().parse::<u16>().ok()) {
                Some(200) => super::pystr::strip(&String::from_utf8_lossy(&body[..body.len().min(4096)])).to_string(),
                Some(status) if status >= 100 => format!("error: HTTP {status}"),
                _ => "error: BadStatusLine".into(),
            };
        }
        1 | 3 => "InvalidURL",
        7 => "ConnectionRefusedError",
        8 => "BadStatusLine",
        18 => "IncompleteRead",
        28 => "timeout",
        35 | 51 | 53 | 54 | 58 | 59 | 60 | 64 | 66 | 77 | 80 | 82 | 83 | 90 | 91 => "SSLError",
        52 => "RemoteDisconnected",
        55 | 56 => "ConnectionResetError",
        _ => "OSError",
    };
    format!("error: {name}")
}

fn https_health(curl: &Path, url: &str, host: &str, timeout: Duration) -> String {
    match curl_argv(curl, url, host, timeout) {
        // curl keeps its own limit; its process group is killed one second later in any case.
        Ok(argv) => curl_answer(command::run(&argv, timeout + Duration::from_secs(1), MAX_CURL_OUTPUT)),
        Err(name) => format!("error: {name}"),
    }
}

/// For `--lab-root` (non-root parity tests only): no service, no process, nothing answers.
pub struct NullRuntime {
    started: Instant,
}

impl NullRuntime {
    pub fn new() -> NullRuntime {
        NullRuntime { started: Instant::now() }
    }
}

impl Default for NullRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime for NullRuntime {
    fn service_active(&self) -> bool {
        false
    }
    fn systemctl(&self, _action: &str, _timeout: Duration) -> i32 {
        1
    }
    fn ols_process(&self) -> bool {
        false
    }
    fn kill_ols(&self) {}
    fn marker(&self, _url: &str, _timeout: Duration) -> Option<String> {
        None
    }
    fn health(&self, url: &str, _host: &str, _timeout: Duration) -> String {
        // As with no server listening: urllib wraps the refusal (URLError), the TLS connection raises it.
        if url.starts_with("https://") { "error: ConnectionRefusedError" } else { "error: URLError" }.into()
    }
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
    fn now(&self) -> f64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
    }
    fn monotonic(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }
}

pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Bodies the activator reads are a generation ID and a vhost name; anything larger is cut.
const MAX_BODY: usize = 1 << 20;

struct Url {
    host: String,
    port: u16,
    path: String,
    authority: String,
}

fn parse_url(url: &str) -> Result<Url, &'static str> {
    let rest = url.strip_prefix("http://").ok_or("URLError")?;
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let path = path.split('#').next().unwrap_or("/");
    let path = if path.starts_with('?') { format!("/{path}") } else { path.to_string() };
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, port) = if let Some(stripped) = host_port.strip_prefix('[') {
        let (host, after) = stripped.split_once(']').ok_or("URLError")?;
        (host.to_string(), after.strip_prefix(':').unwrap_or(""))
    } else {
        match host_port.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), port),
            None => (host_port.to_string(), ""),
        }
    };
    let port = if port.is_empty() { 80 } else { port.parse::<u16>().map_err(|_| "InvalidURL")? };
    if host.is_empty() {
        return Err("URLError");
    }
    Ok(Url { host, port, path, authority: host_port.to_string() })
}

fn connect(url: &Url, timeout: Duration) -> Result<TcpStream, &'static str> {
    let addresses: Vec<SocketAddr> = match url.host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, url.port)],
        Err(_) => (url.host.as_str(), url.port).to_socket_addrs().map_err(|_| "URLError")?.collect(),
    };
    for address in addresses {
        if let Ok(stream) = TcpStream::connect_timeout(&address, timeout) {
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            return Ok(stream);
        }
    }
    Err("URLError")
}

fn read_error(error: std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => "timeout",
        std::io::ErrorKind::ConnectionReset => "ConnectionResetError",
        _ => "OSError",
    }
}

fn read_body(reader: &mut BufReader<TcpStream>, headers: &[(String, String)]) -> Result<Vec<u8>, &'static str> {
    let header = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string());
    let mut body = Vec::new();
    if header("transfer-encoding").map_or(false, |v| v.to_ascii_lowercase().contains("chunked")) {
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).map_err(read_error)?;
            let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or("").trim(), 16).map_err(|_| "IncompleteRead")?;
            if size == 0 {
                break;
            }
            if body.len() + size > MAX_BODY {
                return Err("IncompleteRead");
            }
            let mut chunk = vec![0; size];
            reader.read_exact(&mut chunk).map_err(|_| "IncompleteRead")?;
            body.extend_from_slice(&chunk);
            let mut crlf = String::new();
            reader.read_line(&mut crlf).map_err(read_error)?;
        }
    } else if let Some(length) = header("content-length") {
        let length: usize = length.parse().map_err(|_| "IncompleteRead")?;
        if length > MAX_BODY {
            return Err("IncompleteRead");
        }
        body = vec![0; length];
        reader.read_exact(&mut body).map_err(|_| "IncompleteRead")?;
    } else {
        reader.take(MAX_BODY as u64).read_to_end(&mut body).map_err(read_error)?;
    }
    Ok(body)
}

fn request(url: &Url, host: &str, timeout: Duration) -> Result<(u16, Vec<(String, String)>, Vec<u8>), &'static str> {
    let mut stream = connect(url, timeout)?;
    let request = format!(
        "GET {} HTTP/1.1\r\nAccept-Encoding: identity\r\nHost: {}\r\nUser-Agent: Python-urllib/3.9\r\nConnection: close\r\n\r\n",
        url.path, host
    );
    stream.write_all(request.as_bytes()).map_err(|_| "URLError")?;
    let mut reader = BufReader::new(stream);
    loop {
        let mut status_line = String::new();
        let read = reader.read_line(&mut status_line).map_err(read_error)?;
        if read == 0 {
            return Err("RemoteDisconnected");
        }
        let mut words = status_line.split_whitespace();
        let version = words.next().unwrap_or("");
        let status: u16 = words.next().and_then(|s| s.parse().ok()).ok_or("BadStatusLine")?;
        if !version.starts_with("HTTP/") || !(100..=999).contains(&status) {
            return Err("BadStatusLine");
        }
        let mut headers = Vec::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).map_err(read_error)? == 0 {
                break;
            }
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }
        if status == 100 {
            continue; // http.client skips interim 100 Continue answers
        }
        let body = if status == 204 || status == 304 { Vec::new() } else { read_body(&mut reader, &headers)? };
        return Ok((status, headers, body));
    }
}

/// `urllib.request.urlopen` for plain http: follows 301/302/303/307 redirects (at most 10), keeping an
/// explicit Host header like urllib does. Errors carry the Python exception class name.
pub fn http_get(url: &str, host: Option<&str>, timeout: Duration) -> Result<Response, &'static str> {
    let mut current = parse_url(url)?;
    for _ in 0..=10 {
        let host_header = host.map_or_else(|| current.authority.clone(), str::to_string);
        let (status, headers, body) = request(&current, &host_header, timeout)?;
        if matches!(status, 301 | 302 | 303 | 307) {
            let Some(location) = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("location")).map(|(_, v)| v.clone()) else {
                return Ok(Response { status, body });
            };
            current = if location.starts_with("http://") {
                parse_url(&location)?
            } else if location.contains("://") {
                return Ok(Response { status, body }); // urllib refuses other schemes with HTTPError
            } else if location.starts_with('/') {
                Url { path: location, ..current }
            } else {
                let base = current.path.rsplit_once('/').map_or("", |(dir, _)| dir).to_string();
                Url { path: format!("{base}/{location}"), ..current }
            };
            continue;
        }
        return Ok(Response { status, body });
    }
    Err("HTTPError")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn serve_once(answer: &'static str) -> (u16, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.ends_with(b"\r\n\r\n") {
                let n = stream.read(&mut buffer).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..n]);
            }
            stream.write_all(answer.as_bytes()).unwrap();
            String::from_utf8_lossy(&request).into_owned()
        });
        (port, handle)
    }

    #[test]
    fn health_reads_body_and_sends_host() {
        let (port, handle) = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n g1 site\n");
        let body = SystemRuntime::new().health(&format!("http://127.0.0.1:{port}/h/id"), "site.test", Duration::from_secs(2));
        assert_eq!(body, "g1 site");
        let request = handle.join().unwrap();
        assert!(request.starts_with("GET /h/id HTTP/1.1\r\n") && request.contains("\r\nHost: site.test\r\n"), "{request}");
    }

    #[test]
    fn health_reports_http_errors_and_chunked_bodies() {
        let (port, _h) = serve_once("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(SystemRuntime::new().health(&format!("http://127.0.0.1:{port}/"), "x", Duration::from_secs(2)), "error: HTTP 403");
        let (port, _h) = serve_once("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\ng7 \r\n2\r\nab\r\n0\r\n\r\n");
        assert_eq!(SystemRuntime::new().marker(&format!("http://127.0.0.1:{port}/generation"), Duration::from_secs(2)).as_deref(), Some("g7 ab"));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        assert_eq!(SystemRuntime::new().health(&format!("http://127.0.0.1:{port}/"), "x", Duration::from_secs(1)), "error: URLError");
        assert_eq!(SystemRuntime::new().marker(&format!("http://127.0.0.1:{port}/"), Duration::from_secs(1)), None);
    }

    #[test]
    fn urls_parse_like_urllib() {
        let url = parse_url("http://127.0.0.1:8097/generation").unwrap();
        assert_eq!((url.host.as_str(), url.port, url.path.as_str(), url.authority.as_str()), ("127.0.0.1", 8097, "/generation", "127.0.0.1:8097"));
        let url = parse_url("http://[::1]/x?y").unwrap();
        assert_eq!((url.host.as_str(), url.port, url.path.as_str()), ("::1", 80, "/x?y"));
        assert!(parse_url("https://x/").is_err());
    }

    fn strings(argv: &[OsString]) -> Vec<String> {
        argv.iter().map(|a| a.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn https_requests_are_one_fixed_curl_argv() {
        let argv = curl_argv(Path::new(CURL), "https://10.0.0.5:443/.ols-cpanel-generation/id", "tls.a.test", Duration::from_secs(2)).unwrap();
        assert_eq!(strings(&argv), [
            CURL, "-q", "--silent", "--show-error", "--insecure", "--http1.1", "--proto", "=https", "--noproxy", "*",
            "--max-redirs", "0", "--connect-timeout", "2.000", "--max-time", "2.000", "--resolve", "tls.a.test:443:10.0.0.5",
            "--header", "Host: tls.a.test", "--output", "-", "--write-out", "\n%{http_code}",
            "https://tls.a.test:443/.ols-cpanel-generation/id",
        ]);
        assert!(!strings(&argv).iter().any(|a| a == "-L" || a == "--location" || a.starts_with("-K") || a == "--config"));
        // A shorter remaining budget shortens the attempt.
        let short = curl_argv(Path::new(CURL), "https://10.0.0.5:443/x", "a.test", Duration::from_millis(250)).unwrap();
        assert_eq!(strings(&short)[13..16], ["0.250", "--max-time", "0.250"]);
        for (url, host, error) in [
            ("http://10.0.0.5:443/x", "a.test", "InvalidURL"),
            ("https://a.test:443/x", "a.test", "InvalidURL"),
            ("https://10.0.0.5/x", "a.test", "InvalidURL"),
            ("https://10.0.0.5:0/x", "a.test", "InvalidURL"),
            ("https://[::1]:443/x", "a.test", "InvalidURL"),
            ("https://10.0.0.5:443/a b", "a.test", "InvalidURL"),
            ("https://10.0.0.5:443/x", "-K/etc/x", "ValueError"),
            ("https://10.0.0.5:443/x", "a.test:1:2", "ValueError"),
            ("https://10.0.0.5:443/x", "a.test\r\nX: y", "ValueError"),
            ("https://10.0.0.5:443/x", "", "ValueError"),
        ] {
            assert_eq!(curl_argv(Path::new(CURL), url, host, Duration::from_secs(2)).unwrap_err(), error, "{url} {host:?}");
        }
    }

    #[test]
    fn curl_outcomes_read_like_health_body() {
        let out = |code: i32, stdout: &[u8]| Ok(command::Output { code, stdout: stdout.to_vec(), stderr: Vec::new() });
        assert_eq!(curl_answer(out(0, b" g1 tls.a.test\n\n200")), "g1 tls.a.test");
        assert_eq!(curl_answer(out(0, b"moved\n301")), "error: HTTP 301");
        assert_eq!(curl_answer(out(0, b"\n404")), "error: HTTP 404");
        assert_eq!(curl_answer(out(0, b"\n000")), "error: BadStatusLine");
        assert_eq!(curl_answer(out(0, b"200")), "error: BadStatusLine");
        let mut long = vec![b'a'; 5000];
        long.extend_from_slice(b"\n200");
        assert_eq!(curl_answer(out(0, &long)).len(), 4096);
        assert_eq!(curl_answer(out(0, b"a\xffb\n200")), "a\u{fffd}b");
        for (code, name) in [(7, "ConnectionRefusedError"), (28, "timeout"), (35, "SSLError"), (52, "RemoteDisconnected"),
                             (56, "ConnectionResetError"), (6, "OSError")] {
            assert_eq!(curl_answer(out(code, b"\n000")), format!("error: {name}"));
        }
        assert_eq!(curl_answer(Err(Failure::Timeout)), "error: timeout");
        assert_eq!(curl_answer(Err(Failure::Spawn("x".into()))), "error: FileNotFoundError");
    }

    #[test]
    fn https_health_runs_the_client_bounded() {
        let temp = crate::activator::testutil::TempTree::new();
        let script = temp.path().join("curl");
        let log = temp.path().join("argv");
        std::fs::write(&script, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nprintf 'g7 tls.a.test\\n200'\n", log.display())).unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let mut rt = SystemRuntime::new();
        rt.curl = script.clone();
        let url = "https://127.0.0.1:443/.ols-cpanel-generation/id";
        assert_eq!(rt.health(url, "tls.a.test", Duration::from_secs(2)), "g7 tls.a.test");
        let argv = std::fs::read_to_string(&log).unwrap();
        assert!(argv.starts_with("-q\n") && argv.contains("\n--resolve\ntls.a.test:443:127.0.0.1\n"), "{argv}");
        // A client that hangs is killed with its process group at the limit (plus one second).
        std::fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
        let started = Instant::now();
        assert_eq!(rt.health(url, "tls.a.test", Duration::from_millis(200)), "error: timeout");
        assert!(started.elapsed() < Duration::from_secs(5));
        rt.curl = temp.path().join("missing");
        assert_eq!(rt.health(url, "tls.a.test", Duration::from_secs(1)), "error: FileNotFoundError");
        // The real client, where installed: nothing listens on a closed port.
        if Path::new(CURL).exists() {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let answer = SystemRuntime::new().health(&format!("https://127.0.0.1:{port}/.ols-cpanel-generation/id"), "a.test",
                                                     Duration::from_secs(2));
            assert_eq!(answer, "error: ConnectionRefusedError");
        }
        assert_eq!(NullRuntime::new().health(url, "a.test", Duration::from_secs(1)), "error: ConnectionRefusedError");
        assert_eq!(NullRuntime::new().health("http://127.0.0.1:1/x", "a.test", Duration::from_secs(1)), "error: URLError");
    }

    #[test]
    fn subprocesses_are_bounded() {
        let started = Instant::now();
        assert_eq!(bounded(&["/usr/bin/sleep", "30"], Duration::from_millis(200)), -9);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(bounded(&["/nonexistent/program"], PROBE_TIMEOUT), 127);
        assert_eq!(bounded(&["/usr/bin/true"], PROBE_TIMEOUT), 0);
    }
}
