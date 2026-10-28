//! Byte-identical `json.dumps` output of the Python tools: `sort_keys=True` (serde_json's map is
//! ordered by key, which equals Python's code-point order), `ensure_ascii=True`, the default
//! separators (", " and ": " compact, "," and ": " with an indent) and Python's float repr.
//! Objects whose key order is insertion order in Python (the validator report) use `Ordered`.

use serde_json::Value;

/// An object serialized in the given key order (Python dict insertion order).
pub struct Ordered<'a>(pub Vec<(&'a str, Value)>);

/// `json.dumps(value, sort_keys=True)` or, with `indent`, `json.dumps(value, indent=n)`.
pub fn dumps(value: &Value, indent: Option<usize>) -> String {
    let mut out = String::new();
    write_value(&mut out, value, indent, 0);
    out
}

/// `json.dumps(dict, indent=n)` keeping the given key order.
pub fn dumps_ordered(object: &Ordered<'_>, indent: Option<usize>) -> String {
    let mut out = String::new();
    write_object(&mut out, object.0.iter().map(|(k, v)| (*k, v)), object.0.is_empty(), indent, 0);
    out
}

/// `json.dumps(list_of_dicts, indent=n)` keeping each dict's key order (health.json of a generation).
pub fn dumps_ordered_list(items: &[Ordered<'_>], indent: Option<usize>) -> String {
    if items.is_empty() {
        return "[]".into();
    }
    let mut out = String::from("[");
    for (index, object) in items.iter().enumerate() {
        if index > 0 {
            separator(&mut out, indent);
        }
        newline(&mut out, indent, 1);
        write_object(&mut out, object.0.iter().map(|(k, v)| (*k, v)), object.0.is_empty(), indent, 1);
    }
    newline(&mut out, indent, 0);
    out.push(']');
    out
}

fn newline(out: &mut String, indent: Option<usize>, level: usize) {
    if let Some(width) = indent {
        out.push('\n');
        out.push_str(&" ".repeat(width * level));
    }
}

fn separator(out: &mut String, indent: Option<usize>) {
    out.push_str(if indent.is_some() { "," } else { ", " });
}

fn write_object<'a, I: Iterator<Item = (&'a str, &'a Value)>>(
    out: &mut String,
    items: I,
    empty: bool,
    indent: Option<usize>,
    level: usize,
) {
    if empty {
        out.push_str("{}");
        return;
    }
    out.push('{');
    for (index, (key, value)) in items.enumerate() {
        if index > 0 {
            separator(out, indent);
        }
        newline(out, indent, level + 1);
        write_string(out, key);
        out.push_str(": ");
        write_value(out, value, indent, level + 1);
    }
    newline(out, indent, level);
    out.push('}');
}

fn write_value(out: &mut String, value: &Value, indent: Option<usize>, level: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => {
            if number.is_f64() {
                out.push_str(&float_repr(number.as_f64().unwrap_or(f64::NAN)));
            } else {
                out.push_str(&number.to_string());
            }
        }
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    separator(out, indent);
                }
                newline(out, indent, level + 1);
                write_value(out, item, indent, level + 1);
            }
            newline(out, indent, level);
            out.push(']');
        }
        Value::Object(map) => write_object(out, map.iter().map(|(k, v)| (k.as_str(), v)), map.is_empty(), indent, level),
    }
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Python `repr(float)`: shortest round-trip digits, fixed notation for decimal exponents in
/// [-4, 16), otherwise "d.ddde+XX".
pub fn float_repr(x: f64) -> String {
    if x.is_nan() {
        return "NaN".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if x == 0.0 {
        return if x.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    let scientific = format!("{:e}", x.abs());
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let decpt = exponent + 1;
    let sign = if x < 0.0 { "-" } else { "" };
    if (-3..=16).contains(&decpt) {
        let fixed = format!("{}", x.abs());
        let fixed = if fixed.contains('.') { fixed } else { format!("{fixed}.0") };
        format!("{sign}{fixed}")
    } else {
        let exp_sign = if exponent < 0 { '-' } else { '+' };
        format!("{sign}{mantissa}e{exp_sign}{:02}", exponent.abs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn floats_match_python_repr() {
        assert_eq!(float_repr(1.0), "1.0");
        assert_eq!(float_repr(100.0), "100.0");
        assert_eq!(float_repr(1729600000.123456), "1729600000.123456");
        assert_eq!(float_repr(1e16), "1e+16");
        assert_eq!(float_repr(1e15), "1000000000000000.0");
        assert_eq!(float_repr(0.0001), "0.0001");
        assert_eq!(float_repr(0.00001), "1e-05");
        assert_eq!(float_repr(1.5e-7), "1.5e-07");
        assert_eq!(float_repr(-2.5), "-2.5");
        assert_eq!(float_repr(1.2345e300), "1.2345e+300");
    }

    #[test]
    fn dumps_matches_python() {
        let value = json!({"b": [1, 2.5, null], "a": {"y": true, "x": "q\"\u{e9}\u{1f600}\n"}, "c": []});
        assert_eq!(
            dumps(&value, None),
            r#"{"a": {"x": "q\"\u00e9\ud83d\ude00\n", "y": true}, "b": [1, 2.5, null], "c": []}"#
        );
        assert_eq!(dumps(&json!({"e": [], "f": ["x"]}), Some(2)), "{\n  \"e\": [],\n  \"f\": [\n    \"x\"\n  ]\n}");
        let ordered = Ordered(vec![("valid", json!(false)), ("errors", json!([]))]);
        assert_eq!(dumps_ordered(&ordered, Some(2)), "{\n  \"valid\": false,\n  \"errors\": []\n}");
        // json.dumps([{"vhost": "xé", "host": "h", "url": "u"}], indent=1) and json.dumps([], indent=1)
        let list = [Ordered(vec![("vhost", json!("x\u{e9}")), ("host", json!("h")), ("url", json!("u"))])];
        assert_eq!(dumps_ordered_list(&list, Some(1)), "[\n {\n  \"vhost\": \"x\\u00e9\",\n  \"host\": \"h\",\n  \"url\": \"u\"\n }\n]");
        assert_eq!(dumps_ordered_list(&[], Some(1)), "[]");
    }
}
