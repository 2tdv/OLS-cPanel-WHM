//! Redaction of log lines before a tenant sees them (FV-08). Applied to every line of every log view, search,
//! download and error group, and searches match the redacted text, so a search cannot probe a hidden value.
//!
//! Removed: the value of any `name=value`, `name: value` or `"name": "value"` whose name contains one of
//! SENSITIVE (query strings and form data included), the whole value of `Authorization`, `Proxy-Authorization`,
//! `Cookie` and `Set-Cookie` headers, and the token after `Bearer` or `Basic`. Control characters never reach the
//! reply (a log line cannot forge another line or a terminal sequence) and a line is cut at MAX_LINE characters.

pub const MAX_LINE: usize = 2000;
const MARK: &str = "[redacted]";
/// A name containing one of these (case-insensitive) has its value removed.
const SENSITIVE: [&str; 10] = ["pass", "pwd", "token", "key", "secret", "sess", "auth", "cookie", "credential", "sig"];
/// Headers whose value runs to the end of the line.
const HEADERS: [&str; 4] = ["authorization", "proxy-authorization", "cookie", "set-cookie"];

fn name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "_.-[]%".contains(c)
}

/// Percent-decoding of a name (twice, so `%2570` is seen as `p`): `%70assword` is `password`.
fn decoded(name: &str) -> String {
    let mut text = name.to_string();
    for _ in 0..2 {
        let bytes = text.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let pair = (bytes[i] == b'%').then(|| (bytes.get(i + 1).copied(), bytes.get(i + 2).copied()));
            let value = pair.and_then(|(h, l)| Some((char::from(h?).to_digit(16)? * 16 + char::from(l?).to_digit(16)?) as u8));
            match value {
                Some(v) => {
                    out.push(v);
                    i += 3;
                }
                None => {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
        }
        text = String::from_utf8_lossy(&out).into_owned();
    }
    text
}

fn value_end(c: char) -> bool {
    c.is_whitespace() || "&\"';,)<>".contains(c)
}

fn sensitive(name: &str) -> bool {
    let lower = decoded(name).to_ascii_lowercase();
    SENSITIVE.iter().any(|s| lower.contains(s))
}

/// Printable text of at most MAX_LINE characters: control characters become `?`.
pub fn clean(line: &str) -> String {
    line.chars().take(MAX_LINE).map(|c| if c == '\t' { ' ' } else if c.is_control() { '?' } else { c }).collect()
}

/// One line, cleaned and redacted.
pub fn redact(line: &str) -> String {
    let chars: Vec<char> = clean(line).chars().collect();
    let mut out = String::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        if !name_char(chars[i]) {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let start = i;
        while i < chars.len() && name_char(chars[i]) {
            i += 1;
        }
        let name: String = chars[start..i].iter().collect();
        out.push_str(&name);
        let lower = decoded(&name).to_ascii_lowercase();
        // A closing quote and blanks may sit between the name and its separator ("password": "x").
        let mut j = i;
        if j < chars.len() && (chars[j] == '"' || chars[j] == '\'') {
            j += 1;
        }
        while j < chars.len() && chars[j] == ' ' {
            j += 1;
        }
        if (lower == "bearer" || lower == "basic") && i < chars.len() && chars[i] == ' ' {
            let mut k = i;
            while k < chars.len() && chars[k] == ' ' {
                k += 1;
            }
            let token_start = k;
            while k < chars.len() && (chars[k].is_ascii_alphanumeric() || "-._~+/=".contains(chars[k])) {
                k += 1;
            }
            // A short token is kept only when it reads as a plain lowercase word ("Basic usage").
            let word = chars[token_start..k].iter().all(|c| c.is_ascii_lowercase());
            if k - token_start >= 8 || (k - token_start >= 4 && !word) {
                out.extend(&chars[i..token_start]);
                out.push_str(MARK);
                i = k;
            }
            continue;
        }
        let separator = j < chars.len() && (chars[j] == '=' || chars[j] == ':') && !(chars[j] == ':' && chars.get(j + 1) == Some(&'/'));
        if !separator {
            continue;
        }
        if HEADERS.contains(&lower.as_str()) {
            out.extend(&chars[i..=j]);
            out.push(' ');
            out.push_str(MARK);
            return out;
        }
        if !sensitive(&name) {
            continue;
        }
        let mut k = j + 1;
        while k < chars.len() && chars[k] == ' ' {
            k += 1;
        }
        let quoted = k < chars.len() && (chars[k] == '"' || chars[k] == '\'');
        out.extend(&chars[i..k]);
        if quoted {
            let quote = chars[k];
            out.push(quote);
            k += 1;
            // A backslash escapes the next character, so an escaped quote does not end the value.
            while k < chars.len() && chars[k] != quote {
                k += if chars[k] == '\\' { 2 } else { 1 };
            }
            k = k.min(chars.len());
        } else {
            while k < chars.len() && !value_end(chars[k]) {
                k += 1;
            }
        }
        out.push_str(MARK);
        i = k;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_values_of_sensitive_names_are_removed() {
        let line = r#"a.test:443 1.2.3.4 - - [28/Oct/2026:10:00:00 +0000] "GET /login?user=bob&password=hunter2&x=1 HTTP/2.0" 200 5 "-" "ua""#;
        let out = redact(line);
        assert!(!out.contains("hunter2") && out.contains("user=bob") && out.contains("password=[redacted]&x=1"), "{out}");
        for (input, hidden) in [("GET /?api_key=abc123&b=2", "abc123"), ("GET /?Access_Token=zz9&b=2", "zz9"), ("/?PHPSESSID=s3ss10n;", "s3ss10n"),
                                ("/?pwd=p%40ss&a=b", "p%40ss"), ("/?secret=top", "top"), ("/?auth=xyz", "xyz"), ("/?userpass=q", "q")] {
            let out = redact(input);
            assert!(!out.contains(hidden) && out.contains(MARK), "{input} -> {out}");
        }
        assert_eq!(redact("/?page=2&sort=name"), "/?page=2&sort=name");
        assert_eq!(redact("/?password=&b=1"), "/?password=[redacted]&b=1");
    }

    #[test]
    fn headers_and_bearer_tokens_are_removed() {
        for input in ["Authorization: Basic dXNlcjpwYXNzd29yZA==", "authorization=Bearer abcdefghijklmnop", "Cookie: a=1; b=2", "Set-Cookie: sid=zzz; Path=/",
                      "Proxy-Authorization: x y z"] {
            let out = redact(input);
            assert!(out.ends_with(MARK) && !out.contains("dXNlcjpwYXNzd29yZA") && !out.contains("abcdefghijklmnop") && !out.contains("b=2")
                    && !out.contains("zzz") && !out.contains("x y"), "{input} -> {out}");
        }
        assert_eq!(redact("sent Bearer abcdefghijklmnop to x"), "sent Bearer [redacted] to x");
        assert_eq!(redact("Basic usage of PHP"), "Basic usage of PHP");
    }

    #[test]
    fn json_and_php_error_forms() {
        let out = redact(r#"PHP Warning:  body {"password": "p w", "name": "x", "api_key":"k1"} in /home/u/a.php on line 3"#);
        assert!(!out.contains("p w") && !out.contains("k1") && out.contains(r#""name": "x""#) && out.contains("on line 3"), "{out}");
        assert_eq!(redact("PHP Warning:  Undefined array key \"x\" in /a.php on line 4"), "PHP Warning:  Undefined array key \"x\" in /a.php on line 4");
        assert_eq!(redact("see https://example.test/key://x"), "see https://example.test/key://x");
    }

    #[test]
    fn escaped_quotes_encoded_names_and_short_tokens() {
        let out = redact(r#"body {"password":"prefix\"SECRET","name":"x"} end"#);
        assert!(!out.contains("SECRET") && !out.contains("prefix") && out.contains(r#""name":"x""#) && out.contains("end"), "{out}");
        let out = redact(r#"{'token': 'a\'b-LEAK'}"#);
        assert!(!out.contains("LEAK"), "{out}");
        for (input, hidden) in [("GET /?%70assword=SECRET&a=1", "SECRET"), ("GET /?api%5Fkey=SECRET", "SECRET"), ("/?%2570wd=SECRET", "SECRET"),
                                ("/?%54oken=SECRET;", "SECRET"), ("Authorization: Basic YTpi", "YTpi"), ("sent Basic YTpi to x", "YTpi"),
                                ("sent Bearer ab12 to x", "ab12")] {
            let out = redact(input);
            assert!(!out.contains(hidden) && out.contains(MARK), "{input} -> {out}");
        }
        assert_eq!(redact("/?page=2&100%=3"), "/?page=2&100%=3");
        assert_eq!(redact("Basic usage of PHP"), "Basic usage of PHP");
        assert_eq!(redact("%zz=1 %7"), "%zz=1 %7");
    }

    #[test]
    fn control_characters_and_length() {
        assert_eq!(redact("a\x1b[31mb\rc\0d\te"), "a?[31mb?c?d e");
        assert_eq!(clean(&"x".repeat(5000)).len(), MAX_LINE);
        assert_eq!(redact("é password=ß"), "é password=[redacted]");
    }
}
