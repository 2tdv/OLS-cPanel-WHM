//! Product-side structural validation of a generated OLS plain configuration (OLS-05), ported from
//! build/vm-qualification/ols_config_lint.py (PHP twin: src/Ols/Validation/ConfigLint.php). Messages
//! are byte-identical to the Python tool (checked by tests/activator_parity.py on the corpus of
//! tests/compiler_equivalence.py).

use super::pystr;
use std::collections::HashMap;

pub const REQUIRED_SERVER: [(&str, &str); 3] =
    [("disableWebAdmin", "1"), ("autoDetectCdn", "0"), ("enableUpdateCheck", "0")];
pub const REQUIRED_BLOCKS: [&str; 1] = ["CGIRLimit"];

#[derive(Default)]
struct Node {
    kind: String,
    name: String,
    values: HashMap<String, Vec<String>>,
    children: Vec<Node>,
    line: usize,
}

fn parse(text: &str) -> (Node, Vec<String>) {
    let mut stack = vec![Node { kind: "root".into(), ..Node::default() }];
    let mut errors = Vec::new();
    for (index, raw) in pystr::splitlines(text).into_iter().enumerate() {
        let number = index + 1;
        // Only whole-line comments: values such as rewrite rules may contain "#".
        let line = if pystr::lstrip(raw).starts_with('#') { "" } else { pystr::strip(raw) };
        if line.is_empty() {
            continue;
        }
        if line == "}" {
            if stack.len() == 1 {
                errors.push(format!("line {number}: unexpected '}}'"));
            } else {
                let node = stack.pop().expect("stack holds a block");
                stack.last_mut().expect("root").children.push(node);
            }
            continue;
        }
        if let Some(head) = line.strip_suffix('{') {
            let words = pystr::split(head);
            stack.push(Node {
                kind: words.first().map(|w| w.to_string()).unwrap_or_default(),
                name: words.get(1..).unwrap_or(&[]).join(" "),
                line: number,
                ..Node::default()
            });
            continue;
        }
        let (key, value) = line.split_once(' ').unwrap_or((line, ""));
        stack.last_mut().expect("root").values.entry(key.to_string()).or_default().push(pystr::strip(value).to_string());
    }
    for node in &stack[1..] {
        errors.push(format!("line {}: block '{} {}' is not closed", node.line, node.kind, node.name));
    }
    // Unclosed blocks still belong to their parents (Python appends a block when it opens).
    while stack.len() > 1 {
        let node = stack.pop().expect("stack holds a block");
        stack.last_mut().expect("root").children.push(node);
    }
    (stack.pop().expect("root"), errors)
}

fn ipv4(text: &str) -> bool {
    let octets: Vec<&str> = text.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.bytes().all(|b| b.is_ascii_digit())
                && octet.len() <= 3
                && (*octet == "0" || !octet.starts_with('0'))
                && octet.parse::<u16>().map_or(false, |v| v <= 255)
        })
}

fn hextet(text: &str) -> bool {
    !text.is_empty() && text.len() <= 4 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `ipaddress.IPv6Address` parsing of Python 3.9 (scope IDs, embedded IPv4, one "::").
fn ipv6(text: &str) -> bool {
    if text.contains('/') {
        return false;
    }
    let address = match text.split_once('%') {
        None => text,
        Some((address, scope)) => {
            if scope.is_empty() || scope.contains('%') {
                return false;
            }
            address
        }
    };
    if address.is_empty() {
        return false;
    }
    let mut parts: Vec<String> = address.split(':').map(str::to_string).collect();
    if parts.len() < 3 {
        return false;
    }
    if parts.last().map_or(false, |last| last.contains('.')) {
        let tail = parts.pop().expect("checked");
        if !ipv4(&tail) {
            return false;
        }
        let value: u32 = tail.split('.').fold(0, |acc, octet| (acc << 8) | octet.parse::<u32>().unwrap_or(0));
        parts.push(format!("{:x}", value >> 16));
        parts.push(format!("{:x}", value & 0xffff));
    }
    if parts.len() > 9 {
        return false;
    }
    let mut skip = None;
    for (i, part) in parts.iter().enumerate().take(parts.len() - 1).skip(1) {
        if part.is_empty() {
            if skip.is_some() {
                return false;
            }
            skip = Some(i);
        }
    }
    let count = parts.len();
    let (hi, lo) = if let Some(skip) = skip {
        let mut hi = skip;
        let mut lo = count - skip - 1;
        if parts[0].is_empty() {
            if hi != 1 {
                return false;
            }
            hi -= 1;
        }
        if parts[count - 1].is_empty() {
            if lo != 1 {
                return false;
            }
            lo -= 1;
        }
        if 8 < hi + lo + 1 {
            return false;
        }
        (hi, lo)
    } else {
        if count != 8 || parts[0].is_empty() || parts[count - 1].is_empty() {
            return false;
        }
        (count, 0)
    };
    parts[..hi].iter().all(|p| hextet(p)) && parts[count - lo..].iter().all(|p| hextet(p))
}

/// `ipaddress.ip_address(text)` succeeds.
pub fn ip_address(text: &str) -> bool {
    (!text.contains('/') && ipv4(text)) || ipv6(text)
}

/// Listener address "host:port": host "*", "[ANY]", an IPv4 address or a (bracketed) IPv6 address.
pub fn valid_address(address: &str) -> bool {
    let Some((host, port)) = address.rsplit_once(':') else {
        return false;
    };
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let port = port.trim_start_matches('0');
    if port.len() > 5 || !(1..65536).contains(&port.parse::<u32>().unwrap_or(0)) {
        return false;
    }
    if host == "*" || host == "[ANY]" {
        return true;
    }
    let host = if host.starts_with('[') && host.ends_with(']') && host.len() >= 2 { &host[1..host.len() - 1] } else { host };
    ip_address(host)
}

/// Structural errors of an OLS configuration text; with `require_policy`, also the product's
/// mandatory server directives and blocks (server configuration only, not vhconf files).
pub fn lint(text: &str, require_policy: bool) -> Vec<String> {
    let (root, mut errors) = parse(text);
    for node in root.children.iter().filter(|node| node.kind == "listener") {
        let address = node.values.get("address").and_then(|v| v.first()).map(String::as_str).unwrap_or("");
        if !valid_address(address) {
            errors.push(format!("line {}: listener {} has invalid address '{}'", node.line, node.name, address));
        }
        if node.values.get("secure").and_then(|v| v.first()).map(String::as_str).unwrap_or("0") == "1" {
            for key in ["keyFile", "certFile"] {
                if !node.values.contains_key(key) {
                    errors.push(format!("line {}: secure listener {} lacks {}", node.line, node.name, key));
                }
            }
        }
    }
    if require_policy {
        for (key, expected) in REQUIRED_SERVER {
            let actual = root.values.get(key);
            if actual.map_or(true, |values| values.len() != 1 || values[0] != expected) {
                let found = actual.map_or_else(|| "None".to_string(), |values| pystr::repr_list(values));
                errors.push(format!("server directive {key} must be exactly '{expected}' (found {found})"));
            }
        }
        for block in REQUIRED_BLOCKS {
            if !root.children.iter().any(|child| child.kind == block) {
                errors.push(format!("required server block {block} is missing"));
            }
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "disableWebAdmin 1\nautoDetectCdn 0\nenableUpdateCheck 0\nCGIRLimit {\n  maxCGIInstances 20\n}\n\
                        listener http {\n  address *:80\n  secure 0\n}\n";

    #[test]
    fn good_configuration_passes() {
        assert_eq!(lint(GOOD, true), Vec::<String>::new());
        assert_eq!(lint("rewrite {\n  rules <<<END\nRewriteRule ^a#b$ /c [L]\nEND\n}\n", false), Vec::<String>::new());
    }

    #[test]
    fn structure_and_policy_errors() {
        assert_eq!(lint(&format!("{GOOD}virtualHost broken {{\n  vhRoot /x/\n"), true),
                   vec!["line 11: block 'virtualHost broken' is not closed"]);
        assert_eq!(lint(&format!("{GOOD}}}\n"), true), vec!["line 11: unexpected '}'"]);
        assert_eq!(lint(&format!("{GOOD}listener bad {{\n  address not-an-address\n}}\nlistener t {{\n  address 127.0.0.1:8443\n  secure 1\n}}\n"), true),
                   vec!["line 11: listener bad has invalid address 'not-an-address'",
                        "line 14: secure listener t lacks keyFile", "line 14: secure listener t lacks certFile"]);
        assert_eq!(lint("a b\nc {\n d e\n}\n", true), vec![
            "server directive disableWebAdmin must be exactly '1' (found None)",
            "server directive autoDetectCdn must be exactly '0' (found None)",
            "server directive enableUpdateCheck must be exactly '0' (found None)",
            "required server block CGIRLimit is missing"]);
        let doubled = GOOD.replace("autoDetectCdn 0\n", "autoDetectCdn 0\nautoDetectCdn it's\n");
        assert_eq!(lint(&doubled, true), vec!["server directive autoDetectCdn must be exactly '0' (found ['0', \"it's\"])"]);
        // An unclosed listener is still checked (Python appends blocks to their parent when they open).
        assert_eq!(lint("listener x {\n address bad\n", false),
                   vec!["line 1: block 'listener x' is not closed", "line 1: listener x has invalid address 'bad'"]);
    }

    #[test]
    fn addresses_match_python_ipaddress() {
        for good in ["*:80", "[ANY]:443", "127.0.0.1:8088", "[::1]:80", "192.0.2.10:443", "[2001:db8::1]:8443", "::1:80",
                     "*:080", "[fe80::1%eth0]:80", "[::ffff:1.2.3.4]:80", "[1:2:3:4:5:6:7:8]:1", "[::]:1", "[1::]:1"] {
            assert!(valid_address(good), "{good}");
        }
        for bad in ["", "80", "*:", "*:0", "*:65536", "host:80", "[::1:80", "1.2.3.4:abc", "256.1.1.1:80", "01.2.3.4:80",
                    "[1:2:3:4:5:6:7:8:9]:1", "[1::2::3]:1", "[:1:2]:1", "[1:2:]:1", "[12345::]:1", "[fe80::1%]:1",
                    "[1:2:3:4:5:6:7::8]:1", "[]:80", "*:99999999999999999999", "1.2.3.4/32:80"] {
            assert!(!valid_address(bad), "{bad}");
        }
    }
}
