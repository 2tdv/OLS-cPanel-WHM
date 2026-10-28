//! Certificate expiry for `tenant.sites`: the X.509 notAfter of the first certificate in cPanel's
//! `combined` PEM file (private key, certificate, CA bundle, in that order). Parsed in-process (base64,
//! then the few DER elements in front of the validity) instead of running openssl: no process per
//! domain, no new dependency, and nothing else of the file (the private key in particular) ever leaves
//! this function. Anything unexpected gives None ("expiry unknown"), never a guess.

/// One PEM file is at most this large (a combined file with a long chain is a few KiB).
pub const MAX_PEM: u64 = 1 << 20;
const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";

fn base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits, mut padding) = (0u32, 0u32, 0usize);
    for b in text.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => {
                padding += 1;
                continue;
            }
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        if padding > 0 {
            return None; // data after padding
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (padding <= 2).then_some(out)
}

/// One DER element at `pos`: (tag, content start, content end).
fn element(der: &[u8], pos: usize) -> Option<(u8, usize, usize)> {
    let tag = *der.get(pos)?;
    let first = *der.get(pos + 1)?;
    let (len, start) = if first < 0x80 {
        (first as usize, pos + 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | *der.get(pos + 2 + i)? as usize;
        }
        (len, pos + 2 + count)
    };
    let end = start.checked_add(len)?;
    (end <= der.len()).then_some((tag, start, end))
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's days_from_civil).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// UTCTime `YYMMDDHHMMSSZ` (RFC 5280: years 50-99 are 19xx) or GeneralizedTime `YYYYMMDDHHMMSSZ`.
fn time(tag: u8, text: &[u8]) -> Option<i64> {
    let digits = match (tag, text.len()) {
        (0x17, 13) | (0x18, 15) if text.last() == Some(&b'Z') => &text[..text.len() - 1],
        _ => return None,
    };
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let num = |s: &[u8]| s.iter().fold(0i64, |acc, d| acc * 10 + i64::from(d - b'0'));
    let (year, rest) = if tag == 0x17 {
        let yy = num(&digits[..2]);
        (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &digits[2..])
    } else {
        (num(&digits[..4]), &digits[4..])
    };
    let (month, day, hour, minute, second) = (num(&rest[0..2]), num(&rest[2..4]), num(&rest[4..6]), num(&rest[6..8]), num(&rest[8..10]));
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86400 + hour * 3600 + minute * 60 + second)
}

/// notAfter (Unix seconds) of a DER certificate.
pub fn not_after_der(der: &[u8]) -> Option<i64> {
    let (tag, cert, _) = element(der, 0)?;
    let (tbs_tag, mut pos, tbs_end) = element(der, cert)?;
    if tag != 0x30 || tbs_tag != 0x30 {
        return None;
    }
    let tbs = &der[..tbs_end];
    // The element at `pos` with tag `expected`; `pos` moves past it.
    let next = |pos: &mut usize, expected: u8| -> Option<(usize, usize)> {
        let (t, start, end) = element(tbs, *pos)?;
        *pos = end;
        (t == expected).then_some((start, end))
    };
    // version [0] EXPLICIT (optional), serialNumber, signature, issuer, validity.
    if tbs.get(pos) == Some(&0xa0) {
        next(&mut pos, 0xa0)?;
    }
    next(&mut pos, 0x02)?;
    next(&mut pos, 0x30)?;
    next(&mut pos, 0x30)?;
    let (validity, validity_end) = next(&mut pos, 0x30)?;
    let (_, _, not_before_end) = element(&der[..validity_end], validity)?;
    let (t, start, end) = element(&der[..validity_end], not_before_end)?;
    time(t, &der[start..end])
}

/// notAfter of the first certificate in a PEM text (other blocks, such as a key, are skipped unread).
pub fn not_after_pem(text: &str) -> Option<i64> {
    let start = text.find(BEGIN)? + BEGIN.len();
    let end = start + text[start..].find(END)?;
    not_after_der(&base64(&text[start..end])?)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -subj /CN=a.test
    /// -not_before 20260101000000Z -not_after 20270315123456Z (notAfter as UTCTime).
    pub const UTC_TIME: &str = "-----BEGIN CERTIFICATE-----
MIIBdjCCAR2gAwIBAgIUb7t/yWq3FRLSpDyN4JdNJnESLCUwCgYIKoZIzj0EAwIw
ETEPMA0GA1UEAwwGYS50ZXN0MB4XDTI2MDEwMTAwMDAwMFoXDTI3MDMxNTEyMzQ1
NlowETEPMA0GA1UEAwwGYS50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
n1CjPneRr0ohI/riO0cE/Ph/q4NlfYF6DC3Jaa9sH6X/MS2M7VyeIoiUOndCrrO5
pKMUMZyvehctDUJ843+aN6NTMFEwHQYDVR0OBBYEFJO9lm6pKaNR2i6Lb14URrrX
yZ+lMB8GA1UdIwQYMBaAFJO9lm6pKaNR2i6Lb14URrrXyZ+lMA8GA1UdEwEB/wQF
MAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgZeVInYL6KcwL2N+mp2I8ZEn/lhHYF6Te
DT7ryIr1A5YCICVuMOKICGpBqVZ3kpwIsCj2aW+4sQuzIq4hZIBGDsMp
-----END CERTIFICATE-----
";
    /// openssl x509 -noout -enddate: Mar 15 12:34:56 2027 GMT.
    pub const UTC_TIME_NOT_AFTER: i64 = 1805114096;

    /// The same with -subj /CN=b.test -not_after 20510102030405Z (notAfter as GeneralizedTime).
    const GENERALIZED_TIME: &str = "-----BEGIN CERTIFICATE-----
MIIBeTCCAR+gAwIBAgIUHLZB1i5uspw7kdvAlS8LgM4GDhowCgYIKoZIzj0EAwIw
ETEPMA0GA1UEAwwGYi50ZXN0MCAXDTI2MDEwMTAwMDAwMFoYDzIwNTEwMTAyMDMw
NDA1WjARMQ8wDQYDVQQDDAZiLnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATGOyKTdkWXsYG+UEMxLHdzDpOnADYF0+Jw1E2dQoOvjkE2DdQQBz0r1QlPsqrP
OG3aOfI8SvpDWxCddHj8VrGVo1MwUTAdBgNVHQ4EFgQUzhOa/oAAUXfP91hOo0yi
f8+zt+AwHwYDVR0jBBgwFoAUzhOa/oAAUXfP91hOo0yif8+zt+AwDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiEA/m2+h7OL5taJshzbJNGZmDEQAoqc
cbxrYU2VybxCnSICICJbRqIOsI1Cef/JS2bH9e/hYJBQJ7v/ws1E7jUFIJWo
-----END CERTIFICATE-----
";

    #[test]
    fn not_after_of_real_certificates() {
        assert_eq!(not_after_pem(UTC_TIME), Some(UTC_TIME_NOT_AFTER));
        // Jan  2 03:04:05 2051 GMT
        assert_eq!(not_after_pem(GENERALIZED_TIME), Some(2556241445));
    }

    #[test]
    fn combined_file_order() {
        // cPanel's combined file: key first, then the certificate, then the chain; the first certificate counts.
        let key = format!("-----BEGIN {0} KEY-----\nAAAA\n-----END {0} KEY-----\n", "PRIVATE");
        assert_eq!(not_after_pem(&format!("{key}{UTC_TIME}{GENERALIZED_TIME}")), Some(UTC_TIME_NOT_AFTER));
        assert_eq!(not_after_pem(&key), None);
        assert_eq!(not_after_pem(""), None);
    }

    #[test]
    fn damaged_input_is_unknown() {
        assert_eq!(not_after_pem(&UTC_TIME.replace("MIIBdjCC", "MIIB!jCC")), None);
        assert_eq!(not_after_pem(&UTC_TIME.replace("-----END CERTIFICATE-----", "")), None);
        assert_eq!(not_after_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), None);
        let der = base64(&UTC_TIME[27..UTC_TIME.find("-----END").unwrap()]).unwrap();
        assert_eq!(not_after_der(&der), Some(UTC_TIME_NOT_AFTER));
        // Every truncation fails cleanly (no panic, no value).
        for cut in 0..120 {
            assert_eq!(not_after_der(&der[..cut]), None, "{cut}");
        }
    }

    #[test]
    fn times() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
        assert_eq!(time(0x17, b"700101000000Z"), Some(0));
        assert_eq!(time(0x17, b"491231235959Z"), Some(2524607999));
        assert_eq!(time(0x18, b"20000229120000Z"), Some(951825600));
        for (tag, bad) in [(0x17, &b"7001010000Z"[..]), (0x17, b"701301000000Z"), (0x18, b"700101000000Z"), (0x17, b"70010100000aZ"),
                           (0x17, b"700101000000+"), (0x02, b"700101000000Z")] {
            assert_eq!(time(tag, bad), None);
        }
    }
}
