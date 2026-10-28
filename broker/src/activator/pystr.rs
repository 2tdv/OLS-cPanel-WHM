//! Python 3 string semantics the lab tools rely on (str.isspace, strip, split, splitlines, int(),
//! os.path.dirname/basename, repr of str). Ported exactly where the result can reach a verdict or an
//! on-disk record; documented approximations are noted per function.

/// `str.isspace()` (also what `\s` matches in a Python `re` str pattern): Unicode bidirectional
/// classes WS, B, S and category Zs, as of the Unicode version used by Python 3.9.
pub fn is_space(c: char) -> bool {
    matches!(c,
        '\t'..='\r' | '\x1c'..='\x1f' | ' ' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}'
        | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}

/// `str.strip()` without arguments.
pub fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `str.lstrip()` without arguments.
pub fn lstrip(s: &str) -> &str {
    s.trim_start_matches(is_space)
}

/// `str.split()` without arguments.
pub fn split(s: &str) -> Vec<&str> {
    s.split(is_space).filter(|part| !part.is_empty()).collect()
}

fn is_line_break(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// `str.splitlines()` (keepends=False): "\r\n" is one break; no empty element after a final break.
pub fn splitlines(s: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((index, c)) = chars.next() {
        if !is_line_break(c) {
            continue;
        }
        lines.push(&s[start..index]);
        let mut end = index + c.len_utf8();
        if c == '\r' {
            if let Some(&(_, '\n')) = chars.peek() {
                chars.next();
                end += 1;
            }
        }
        start = end;
    }
    if start < s.len() {
        lines.push(&s[start..]);
    }
    lines
}

/// Universal-newline translation of Python text mode (read_text(), subprocess text=True).
pub fn universal_newlines(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

/// `int(text)` for a str: surrounding whitespace, an optional sign, ASCII digits with single
/// underscores between them. Values beyond i64 saturate (only their order matters to callers).
/// Python also accepts non-ASCII decimal digits; those are rejected here, which callers treat as
/// unknown (fail closed).
pub fn int(text: &str) -> Option<i64> {
    let s = strip(text);
    let (negative, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    let mut value: i128 = 0;
    for b in digits.bytes() {
        match b {
            b'_' => continue,
            b'0'..=b'9' => value = (value * 10 + i128::from(b - b'0')).min(i128::from(i64::MAX) + 1),
            _ => return None,
        }
    }
    let value = if negative { -value } else { value };
    Some(value.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64)
}

/// `float(text)` for a str (whitespace, sign, decimal or exponent forms, inf/nan, underscores between
/// digits). Used for history times only.
pub fn float(text: &str) -> Option<f64> {
    let s = strip(text);
    if s.is_empty() || s.contains("__") || s.starts_with('_') || s.ends_with('_') {
        return None;
    }
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'_' && !(i > 0 && bytes[i - 1].is_ascii_digit() && bytes.get(i + 1).map_or(false, u8::is_ascii_digit)) {
            return None;
        }
    }
    s.replace('_', "").parse::<f64>().ok()
}

/// `os.path.dirname` for POSIX paths.
pub fn dirname(path: &str) -> String {
    let head = match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "",
    };
    if !head.is_empty() && head.bytes().any(|b| b != b'/') {
        head.trim_end_matches('/').to_string()
    } else {
        head.to_string()
    }
}

/// `os.path.basename` for POSIX paths.
pub fn basename(path: &str) -> String {
    match path.rfind('/') {
        Some(i) => path[i + 1..].to_string(),
        None => path.to_string(),
    }
}

/// `os.path.join(a, b)` for a relative `b`.
pub fn join(a: &str, b: &str) -> String {
    if a.is_empty() || a.ends_with('/') {
        format!("{a}{b}")
    } else {
        format!("{a}/{b}")
    }
}

/// First `n` characters (`s[:n]`).
pub fn head(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Last `n` characters (`s[-n:]`).
pub fn tail(s: &str, n: usize) -> String {
    let count = s.chars().count();
    s.chars().skip(count.saturating_sub(n)).collect()
}

/// `str.isprintable()` approximation: control, separator (other than space), format, private-use
/// and surrogate code points are not printable. Unassigned code points are treated as printable.
fn printable(c: char) -> bool {
    let v = c as u32;
    !(v < 0x20
        || (0x7f..=0xa0).contains(&v)
        || v == 0xad
        || v == 0x1680
        || (0x2000..=0x200f).contains(&v)
        || (0x2028..=0x202f).contains(&v)
        || (0x205f..=0x206f).contains(&v)
        || v == 0x3000
        || v == 0xfeff
        || (0xfff9..=0xfffb).contains(&v)
        || (0xe000..=0xf8ff).contains(&v)
        || (0xf0000..=0x10ffff).contains(&v)
        || v == 0x061c
        || v == 0x180e)
}

/// `repr(str)`: single quotes unless the text contains a single quote and no double quote.
pub fn repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if printable(c) => out.push(c),
            c if (c as u32) < 0x100 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push(quote);
    out
}

/// `repr(list_of_str)`.
pub fn repr_list(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|item| repr(item)).collect();
    format!("[{}]", parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitlines_matches_python() {
        assert_eq!(splitlines(""), Vec::<&str>::new());
        assert_eq!(splitlines("a\n"), vec!["a"]);
        assert_eq!(splitlines("a\r\nb\rc\x0bd\u{2028}e\n\n"), vec!["a", "b", "c", "d", "e", ""]);
    }

    #[test]
    fn int_matches_python() {
        assert_eq!(int(" 12\n"), Some(12));
        assert_eq!(int("+3"), Some(3));
        assert_eq!(int("-3"), Some(-3));
        assert_eq!(int("1_000"), Some(1000));
        assert_eq!(int("007"), Some(7));
        for bad in ["", "1__0", "_1", "1_", "1.0", "true", "0x10", " - 1"] {
            assert_eq!(int(bad), None, "{bad}");
        }
        assert_eq!(int("99999999999999999999999"), Some(i64::MAX));
    }

    #[test]
    fn float_matches_python() {
        assert_eq!(float(" 100 "), Some(100.0));
        assert_eq!(float("1e3"), Some(1000.0));
        assert_eq!(float("1_0.5"), Some(10.5));
        assert_eq!(float("abc"), None);
        assert_eq!(float("1__0"), None);
    }

    #[test]
    fn paths_match_python() {
        assert_eq!(dirname("/a/b/c.log"), "/a/b");
        assert_eq!(dirname("/x"), "/");
        assert_eq!(dirname("//x"), "//");
        assert_eq!(dirname("/a//b"), "/a");
        assert_eq!(dirname("x"), "");
        assert_eq!(basename("/a/b/"), "");
        assert_eq!(basename("/a/b"), "b");
        assert_eq!(join("/a/", "b"), "/a/b");
        assert_eq!(join("/a", "b"), "/a/b");
    }

    #[test]
    fn repr_matches_python() {
        assert_eq!(repr("1"), "'1'");
        assert_eq!(repr("it's"), "\"it's\"");
        assert_eq!(repr("a'\"b"), "'a\\'\"b'");
        assert_eq!(repr("a\tb\\"), "'a\\tb\\\\'");
        assert_eq!(repr("\u{1}\u{a0}\u{e9}"), "'\\x01\\xa0\u{e9}'");
        assert_eq!(repr_list(&["1".into(), "0".into()]), "['1', '0']");
    }

    #[test]
    fn whitespace_matches_python() {
        assert!(is_space('\x1f') && is_space('\u{85}') && is_space('\u{3000}'));
        assert!(!is_space('\u{200b}') && !is_space('x'));
        assert_eq!(split(" a\t b\u{a0}c "), vec!["a", "b", "c"]);
        assert_eq!(strip("\x1c x \u{2029}"), "x");
    }
}
