//! The `engine.run` allowlist (docs/product-interfaces.md, engine socket): every command the PHP
//! ServerConfigurationBuilder (and the reconciler's referenced-file digests) runs, as one table of argv
//! patterns. An argv is accepted only when one pattern matches it token for token. Paths are checked
//! lexically (absolute, no empty, "." or ".." components) and never resolved: the tenant reads run as the
//! tenant through runuser, and the root commands only read root-owned cPanel files, test existence or
//! digest files.

use super::{valid_domain, valid_user, valid_version};
use std::collections::HashSet;

/// The PHP builder's E_* constants code (ServerConfigurationBuilder::CONSTANTS_CODE), byte for byte.
pub const CONSTANTS_CODE: &str =
    r#"echo json_encode(array_filter(get_defined_constants(true)["Core"], fn($k) => str_starts_with($k, "E_"), ARRAY_FILTER_USE_KEY));"#;

/// In `Below`: a directory that starts with `/home*/<account>/` (any cPanel home mount).
const HOME: &str = "~/";

/// One argv token pattern.
#[derive(Clone, Copy, Debug)]
pub enum Arg {
    /// Exactly this text.
    Is(&'static str),
    /// One of these texts.
    OneOf(&'static [&'static str]),
    /// A cPanel account; binds the user for `InHome`.
    User,
    /// Text with `{user}`, `{domain}` and `{version}` placeholders (values never contain "/").
    Template(&'static str),
    /// A normalized absolute path strictly below one of these directories (`~/...` = below a home).
    Below(&'static [&'static str]),
    /// A normalized path in the bound user's home directory; with a name, a file of that name below it.
    InHome(Option<&'static str>),
    /// A normalized path strictly below this directory (e.g. "/.htpasswds/") of the bound user's home.
    InHomeBelow(&'static str),
    /// `/<name>` or `/home*/<name>`: the directories above every home are root's, never a tenant's.
    AboveHomes(&'static str),
    /// This prefix followed by one or more "/"-separated components of `[A-Za-z0-9_-][A-Za-z0-9_.-]*`
    /// (checked as text, never resolved: no empty, "." or ".." component, no trailing slash).
    Components(&'static str),
}

pub struct Rule {
    pub name: &'static str,
    pub argv: &'static [Arg],
}

use Arg::*;

const CAT: Arg = Is("/usr/bin/cat");
const RUNUSER: [Arg; 4] = [Is("/usr/sbin/runuser"), Is("-u"), User, Is("--")];

/// The whole allowlist. A change here is a contract change (docs/product-interfaces.md).
pub const RULES: &[Rule] = &[
    Rule { name: "cat-userdatadomains", argv: &[CAT, Is("/etc/userdatadomains")] },
    Rule { name: "cat-userdata", argv: &[CAT, Template("/var/cpanel/userdata/{user}/{domain}")] },
    Rule { name: "cat-apache-conf", argv: &[CAT, Is("/etc/apache2/conf/httpd.conf")] },
    Rule { name: "cat-fpm-pool", argv: &[CAT, Template("/opt/cpanel/{version}/root/etc/php-fpm.d/{domain}.conf")] },
    // .htaccess of the directories above the homes (Apache applies them too); root-owned directories.
    Rule { name: "cat-htaccess-above-homes", argv: &[CAT, AboveHomes(".htaccess")] },
    Rule {
        name: "whmapi1",
        argv: &[
            Is("/usr/local/cpanel/bin/whmapi1"),
            Is("--output=json"),
            OneOf(&["listaccts", "php_get_vhost_versions", "php_get_handlers"]),
        ],
    },
    Rule {
        name: "test",
        argv: &[
            Is("/usr/bin/test"),
            OneOf(&["-e", "-f", "-d"]),
            Below(&["/var/cpanel/suspended/", "/var/cpanel/ssl/", HOME, "/usr/local/cpanel/", "/usr/local/bandmin/", "/var/www/html/"]),
        ],
    },
    Rule { name: "runuser-cat-htaccess", argv: &[RUNUSER[0], RUNUSER[1], RUNUSER[2], RUNUSER[3], CAT, InHome(Some(".htaccess"))] },
    Rule {
        name: "runuser-find-htaccess",
        argv: &[
            RUNUSER[0], RUNUSER[1], RUNUSER[2], RUNUSER[3],
            Is("/usr/bin/find"), Is("-H"), InHome(None), Is("-name"), Is(".htaccess"),
            Is("("), Is("-type"), Is("f"), Is("-o"), Is("-type"), Is("l"), Is(")"), Is("-printf"), Is("%y%p\\0"),
        ],
    },
    Rule { name: "php-constants", argv: &[Template("/opt/cpanel/{version}/root/usr/bin/php"), Is("-n"), Is("-r"), Is(CONSTANTS_CODE)] },
    Rule { name: "hostname", argv: &[Is("/usr/bin/hostname"), Is("-f")] },
    // The modules Apache has loaded: they decide every <IfModule> of a tenant's .htaccess (RV-46). Fixed and read-only.
    Rule { name: "httpd-modules", argv: &[Is("/usr/sbin/httpd"), Is("-M")] },
    Rule { name: "ipv6-addresses", argv: &[Is("/usr/sbin/ip"), Is("-6"), Is("-o"), Is("addr"), Is("show"), Is("scope"), Is("global")] },
    // Digests of the certificate, key and password files a configuration references (reconciler). Password
    // files live in the tenant's home: read as the tenant, so a planted symlink reveals nothing of root's.
    Rule { name: "sha256sum", argv: &[Is("/usr/bin/sha256sum"), Below(&["/var/cpanel/ssl/"])] },
    Rule {
        name: "runuser-sha256sum-htpasswds",
        argv: &[RUNUSER[0], RUNUSER[1], RUNUSER[2], RUNUSER[3], Is("/usr/bin/sha256sum"), InHomeBelow("/.htpasswds/")],
    },
    // cPanel's ModSecurity configuration (FV-02 WAF): Apache's include, cPanel's two generated files and the
    // vendor rule and data files they reference; read-only, the compiler checks every path it names.
    Rule {
        name: "test-modsec",
        argv: &[Is("/usr/bin/test"), Is("-e"),
                OneOf(&["/etc/apache2/conf.d/modsec2.conf", "/etc/apache2/conf.modules.d/800-mod_security2.conf"])],
    },
    Rule {
        name: "cat-modsec",
        argv: &[CAT, OneOf(&["/etc/apache2/conf.d/modsec2.conf", "/etc/apache2/conf.d/modsec/modsec2.user.conf",
                             "/etc/apache2/conf.d/modsec/modsec2.cpanel.conf"])],
    },
    Rule { name: "cat-modsec-vendor", argv: &[CAT, Components("/etc/apache2/conf.d/modsec_vendor_configs/")] },
    // FV-10: a vhost's PHP version has no usable lsphp; the reconciler asks the root PHP environment service to run
    // now (it installs ea-phpXX-php-litespeed and the rest). One fixed argv, no arguments of the caller.
    Rule {
        name: "php-env-trigger",
        argv: &[Is("/usr/bin/systemctl"), Is("start"), Is("--no-block"), Is("ols-cpanel-php.service")],
    },
    // HR-D14: a compiled vhost address is not yet trusted by Apache's mod_remoteip include; the reconciler asks the root
    // hybrid trust service to refresh it now. One fixed argv, no arguments of the caller.
    Rule {
        name: "hybrid-trust-trigger",
        argv: &[Is("/usr/bin/systemctl"), Is("start"), Is("--no-block"), Is("ols-cpanel-hybrid-trust.service")],
    },
];

/// The rule accepting `argv`, if any. `accounts` are the users of /etc/userdatadomains.
pub fn allowed(argv: &[String], accounts: &HashSet<String>) -> Option<&'static str> {
    RULES.iter().find(|rule| matches(rule, argv, accounts)).map(|rule| rule.name)
}

fn matches(rule: &Rule, argv: &[String], accounts: &HashSet<String>) -> bool {
    if rule.argv.len() != argv.len() {
        return false;
    }
    let mut user: Option<&str> = None;
    for (pattern, value) in rule.argv.iter().zip(argv) {
        let ok = match *pattern {
            Is(text) => value == text,
            OneOf(texts) => texts.contains(&value.as_str()),
            User => {
                user = Some(value);
                account(value, accounts)
            }
            Template(template) => matches_template(template, value, accounts),
            Below(dirs) => normalized(value) && dirs.iter().any(|dir| below(value, dir, accounts)),
            InHome(name) => user.map_or(false, |user| in_home(value, user, name)),
            InHomeBelow(dir) => user.map_or(false, |user| {
                normalized(value)
                    && matches!(home_of(value), Some((owner, rest)) if owner == user && rest.starts_with(dir) && rest.len() > dir.len())
            }),
            AboveHomes(name) => above_homes(value, name),
            Components(prefix) => components(value, prefix),
        };
        if !ok {
            return false;
        }
    }
    true
}

fn account(value: &str, accounts: &HashSet<String>) -> bool {
    valid_user(value) && accounts.contains(value)
}

/// Absolute, no NUL, no empty, "." or ".." component; one trailing slash is allowed.
pub fn normalized(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else { return false };
    if path.contains('\0') {
        return false;
    }
    if rest.is_empty() {
        return true;
    }
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    rest.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

/// The product's one home policy (review RV-29, finding 11; PHP `Cpanel\Discovery\HomePath::MOUNT`): a home mount is
/// the single path component `home[A-Za-z0-9_-]*` directly below "/" (/home, /home2, /home_ssd, /home-b; never
/// /home.old or /newhome).
pub fn home_mount(component: &str) -> bool {
    component.strip_prefix("home").map_or(false, |suffix| suffix.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
}

/// `/<mount>/<user><rest>` with a home mount and rest "" or starting with "/".
fn home_of(path: &str) -> Option<(&str, &str)> {
    let (mount, tail) = path.strip_prefix('/')?.split_once('/')?;
    if !home_mount(mount) {
        return None;
    }
    Some(match tail.find('/') {
        Some(i) => (&tail[..i], &tail[i..]),
        None => (tail, ""),
    })
}

fn below(path: &str, dir: &str, accounts: &HashSet<String>) -> bool {
    match dir.strip_prefix(HOME) {
        Some(inner) => match home_of(path) {
            Some((user, rest)) => {
                let prefix = format!("/{inner}");
                account(user, accounts) && rest.starts_with(&prefix) && rest.len() > prefix.len()
            }
            None => false,
        },
        None => path.starts_with(dir) && path.len() > dir.len(),
    }
}

fn in_home(path: &str, user: &str, name: Option<&str>) -> bool {
    if !normalized(path) {
        return false;
    }
    match (home_of(path), name) {
        (Some((owner, rest)), None) => owner == user && (rest.is_empty() || rest.starts_with('/')),
        (Some((owner, rest)), Some(name)) => owner == user && rest.rsplit('/').next() == Some(name) && rest.len() > name.len(),
        (None, _) => false,
    }
}

fn components(path: &str, prefix: &str) -> bool {
    let Some(rest) = path.strip_prefix(prefix) else { return false };
    !rest.is_empty()
        && rest.split('/').all(|c| {
            let b = c.as_bytes();
            !b.is_empty()
                && (b[0].is_ascii_alphanumeric() || b[0] == b'_' || b[0] == b'-')
                && b.iter().all(|&x| x.is_ascii_alphanumeric() || matches!(x, b'_' | b'-' | b'.'))
                && c != "." && c != ".."
        })
}

fn above_homes(path: &str, name: &str) -> bool {
    if path.strip_prefix('/') == Some(name) {
        return true;
    }
    match path.strip_prefix('/').and_then(|t| t.split_once('/')) {
        Some((mount, file)) => file == name && home_mount(mount),
        None => false,
    }
}

fn matches_template(template: &str, value: &str, accounts: &HashSet<String>) -> bool {
    let mut parts = template.split('{');
    let Some(mut rest) = value.strip_prefix(parts.next().unwrap_or("")) else { return false };
    let parts: Vec<&str> = parts.collect();
    for (index, part) in parts.iter().enumerate() {
        let Some((placeholder, literal)) = part.split_once('}') else { return false };
        let last = index + 1 == parts.len();
        // The value runs up to the next literal; the final literal must end the text.
        let (field, after) = if literal.is_empty() {
            (rest, "")
        } else if last {
            match rest.strip_suffix(literal) {
                Some(field) => (field, ""),
                None => return false,
            }
        } else {
            match rest.split_once(literal) {
                Some(split) => split,
                None => return false,
            }
        };
        let ok = match placeholder {
            "user" => account(field, accounts),
            "domain" => valid_domain(field),
            "version" => valid_version(field),
            _ => false,
        };
        if !ok {
            return false;
        }
        rest = after;
    }
    rest.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn accounts(names: &[&str]) -> HashSet<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn rule(items: &[&str]) -> Option<&'static str> {
        allowed(&argv(items), &accounts(&["olscpa", "olscpb"]))
    }

    /// Every command of a recorded compile is accepted, the lab-only curl requests are refused.
    #[test]
    fn recorded_compiles_are_accepted() {
        for fixture in ["compile-production.json", "compile-test.json"] {
            let path = format!("{}/../tests/Fixtures/lab-snapshot/{fixture}", env!("CARGO_MANIFEST_DIR"));
            let record: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let calls = record["calls"].as_array().unwrap();
            // The accounts come from the recorded /etc/userdatadomains itself, through the same reader.
            let temp = crate::activator::testutil::TempTree::new();
            let file = temp.path().join("userdatadomains");
            std::fs::write(&file, calls[0]["stdout"].as_str().unwrap()).unwrap();
            let known = super::super::accounts(&file);
            assert_eq!(known, accounts(&["olscpa", "olscpb"]));
            let (mut accepted, mut curl) = (0, 0);
            for call in calls {
                let items: Vec<String> = call["argv"].as_array().unwrap().iter().map(|a| a.as_str().unwrap().to_string()).collect();
                let verdict = allowed(&items, &known);
                if items[0] == "/usr/bin/curl" {
                    assert_eq!(verdict, None, "{items:?}");
                    curl += 1;
                } else {
                    assert!(verdict.is_some(), "refused: {items:?}");
                    accepted += 1;
                }
            }
            assert!(accepted > 100 && curl == 2, "{fixture}: {accepted} {curl}");
        }
    }

    #[test]
    fn one_home_policy() {
        for good in ["home", "home2", "home3", "home_ssd", "home-b", "homeB2", "home__"] {
            assert!(home_mount(good), "{good}");
        }
        for bad in ["", "hom", "Home", "home.old", "newhome", "home/x", "home 2", "home+x", "home\u{e9}", "data"] {
            assert!(!home_mount(bad), "{bad}");
        }
        assert_eq!(home_of("/home-b/olscpa/public_html"), Some(("olscpa", "/public_html")));
        assert_eq!(home_of("/home_ssd/olscpa"), Some(("olscpa", "")));
        assert_eq!(home_of("/usr/home/olscpa"), None);
        assert_eq!(home_of("/home.old/olscpa"), None);
    }

    #[test]
    fn each_rule_accepts_its_commands() {
        let cases: &[(&str, &[&str])] = &[
            ("cat-userdatadomains", &["/usr/bin/cat", "/etc/userdatadomains"]),
            ("cat-userdata", &["/usr/bin/cat", "/var/cpanel/userdata/olscpa/blog.olstest1.example.test"]),
            ("cat-apache-conf", &["/usr/bin/cat", "/etc/apache2/conf/httpd.conf"]),
            ("cat-fpm-pool", &["/usr/bin/cat", "/opt/cpanel/ea-php83/root/etc/php-fpm.d/olscp-c.test.conf"]),
            ("cat-htaccess-above-homes", &["/usr/bin/cat", "/.htaccess"]),
            ("cat-htaccess-above-homes", &["/usr/bin/cat", "/home/.htaccess"]),
            ("cat-htaccess-above-homes", &["/usr/bin/cat", "/home2/.htaccess"]),
            ("whmapi1", &["/usr/local/cpanel/bin/whmapi1", "--output=json", "listaccts"]),
            ("whmapi1", &["/usr/local/cpanel/bin/whmapi1", "--output=json", "php_get_vhost_versions"]),
            ("whmapi1", &["/usr/local/cpanel/bin/whmapi1", "--output=json", "php_get_handlers"]),
            ("test", &["/usr/bin/test", "-e", "/var/cpanel/suspended/olscpa"]),
            ("test", &["/usr/bin/test", "-f", "/var/cpanel/ssl/apache_tls/a.test/combined"]),
            ("test", &["/usr/bin/test", "-d", "/home/olscpa/public_html/cgi-bin/"]),
            ("test", &["/usr/bin/test", "-d", "/home2/olscpb/public_html/cgi-bin/"]),
            // Every home mount of the product's home policy (HomePath::MOUNT): home[A-Za-z0-9_-]*.
            ("test", &["/usr/bin/test", "-d", "/home_ssd/olscpb/public_html/cgi-bin/"]),
            ("test", &["/usr/bin/test", "-d", "/home-b/olscpb/public_html/cgi-bin/"]),
            ("test", &["/usr/bin/test", "-d", "/homeB2/olscpb/public_html/cgi-bin/"]),
            ("cat-htaccess-above-homes", &["/usr/bin/cat", "/home_ssd/.htaccess"]),
            ("cat-htaccess-above-homes", &["/usr/bin/cat", "/home-b/.htaccess"]),
            ("runuser-cat-htaccess", &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat", "/home-b/olscpa/public_html/.htaccess"]),
            ("runuser-find-htaccess", &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/find", "-H", "/home_ssd/olscpa/public_html",
                                        "-name", ".htaccess", "(", "-type", "f", "-o", "-type", "l", ")", "-printf", "%y%p\\0"]),
            ("runuser-sha256sum-htpasswds", &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/sha256sum",
                                              "/home_ssd/olscpa/.htpasswds/passwd"]),
            ("test-modsec", &["/usr/bin/test", "-e", "/etc/apache2/conf.d/modsec2.conf"]),
            ("test-modsec", &["/usr/bin/test", "-e", "/etc/apache2/conf.modules.d/800-mod_security2.conf"]),
            ("cat-modsec", &["/usr/bin/cat", "/etc/apache2/conf.d/modsec/modsec2.cpanel.conf"]),
            ("cat-modsec", &["/usr/bin/cat", "/etc/apache2/conf.d/modsec/modsec2.user.conf"]),
            ("cat-modsec-vendor", &["/usr/bin/cat", "/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/rules/REQUEST-901-INITIALIZATION.conf"]),
            ("cat-modsec-vendor", &["/usr/bin/cat", "/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/rules/unix-shell.data"]),
            ("php-env-trigger", &["/usr/bin/systemctl", "start", "--no-block", "ols-cpanel-php.service"]),
            ("hybrid-trust-trigger", &["/usr/bin/systemctl", "start", "--no-block", "ols-cpanel-hybrid-trust.service"]),
            ("test", &["/usr/bin/test", "-d", "/usr/local/cpanel/cgi-sys/"]),
            ("test", &["/usr/bin/test", "-d", "/usr/local/bandmin/htdocs/"]),
            ("test", &["/usr/bin/test", "-d", "/var/www/html/cgi-bin/"]),
            ("runuser-cat-htaccess", &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat", "/home/olscpa/.htaccess"]),
            ("runuser-cat-htaccess", &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat", "/home/olscpa/public_html/a b/.htaccess"]),
            ("runuser-find-htaccess", &["/usr/sbin/runuser", "-u", "olscpb", "--", "/usr/bin/find", "-H", "/home/olscpb/public_html",
                                        "-name", ".htaccess", "(", "-type", "f", "-o", "-type", "l", ")", "-printf", "%y%p\\0"]),
            ("php-constants", &["/opt/cpanel/alt-php74/root/usr/bin/php", "-n", "-r", CONSTANTS_CODE]),
            ("hostname", &["/usr/bin/hostname", "-f"]),
            ("httpd-modules", &["/usr/sbin/httpd", "-M"]),
            ("ipv6-addresses", &["/usr/sbin/ip", "-6", "-o", "addr", "show", "scope", "global"]),
            ("sha256sum", &["/usr/bin/sha256sum", "/var/cpanel/ssl/apache_tls/a.test/combined"]),
            ("sha256sum", &["/usr/bin/sha256sum", "/var/cpanel/ssl/cpanel/mycpanel.pem"]),
            ("runuser-sha256sum-htpasswds", &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/sha256sum",
                                              "/home/olscpa/.htpasswds/public_html/private/passwd"]),
            ("runuser-sha256sum-htpasswds", &["/usr/sbin/runuser", "-u", "olscpb", "--", "/usr/bin/sha256sum",
                                              "/home3/olscpb/.htpasswds/passwd"]),
        ];
        for (name, items) in cases {
            assert_eq!(rule(items), Some(*name), "{items:?}");
        }
        // Every rule of the table has at least one accepted example above.
        for entry in RULES {
            assert!(cases.iter().any(|(name, _)| *name == entry.name), "untested rule {}", entry.name);
        }
    }

    #[test]
    fn everything_else_is_refused() {
        let find = |root: &str, user: &str| -> Vec<String> {
            argv(&["/usr/sbin/runuser", "-u", user, "--", "/usr/bin/find", "-H", root, "-name", ".htaccess", "(", "-type", "f",
                   "-o", "-type", "l", ")", "-printf", "%y%p\\0"])
        };
        let refused: &[&[&str]] = &[
            &[],
            &["/usr/bin/systemctl", "start", "--no-block", "ols-cpanel.service"],
            &["/usr/bin/systemctl", "stop", "--no-block", "ols-cpanel-php.service"],
            &["/usr/bin/systemctl", "start", "ols-cpanel-php.service"],
            &["/usr/bin/systemctl", "start", "--no-block", "ols-cpanel-php.service", "ols-cpanel.service"],
            &["/usr/bin/cat"],
            &["cat", "/etc/userdatadomains"],
            &["/bin/cat", "/etc/userdatadomains"],
            &["/usr/bin/cat", "/etc/shadow"],
            &["/usr/bin/cat", "/etc/userdatadomains", "/etc/shadow"],
            &["/usr/bin/cat", "/etc/userdatadomains", "-"],
            // userdata: unknown user, bad domain, traversal
            &["/usr/bin/cat", "/var/cpanel/userdata/bob/a.test"],
            &["/usr/bin/cat", "/var/cpanel/userdata/root/a.test"],
            &["/usr/bin/cat", "/var/cpanel/userdata/olscpa/../../../etc/shadow"],
            &["/usr/bin/cat", "/var/cpanel/userdata/olscpa/main"],
            &["/usr/bin/cat", "/var/cpanel/userdata/olscpa/A.test"],
            &["/usr/bin/cat", "/var/cpanel/userdata/olscpa/a.test/x"],
            &["/usr/bin/cat", "/var/cpanel/userdata/olscpa/-a.test"],
            // FPM pools: bad version, traversal, other suffix
            &["/usr/bin/cat", "/opt/cpanel/../root/etc/php-fpm.d/a.test.conf"],
            &["/usr/bin/cat", "/opt/cpanel/EA-php83/root/etc/php-fpm.d/a.test.conf"],
            &["/usr/bin/cat", "/opt/cpanel/ea-php83/root/etc/php-fpm.d/a.test.conf.bak"],
            &["/usr/bin/cat", "/opt/cpanel/ea-php83/root/etc/php-fpm.d/../../../../etc/shadow.conf"],
            // root reads inside a home: only through runuser
            &["/usr/bin/cat", "/home/olscpa/.htaccess"],
            &["/usr/bin/cat", "/home/olscpa/public_html/.htaccess"],
            &["/usr/bin/cat", "/home/../.htaccess"],
            &["/usr/bin/cat", "/home/x/.htaccess"],
            &["/usr/bin/cat", "/.htpasswd"],
            // whmapi1: other API names, other output, extra arguments
            &["/usr/local/cpanel/bin/whmapi1", "--output=json", "createacct"],
            &["/usr/local/cpanel/bin/whmapi1", "--output=json", "removeacct", "user=olscpa"],
            &["/usr/local/cpanel/bin/whmapi1", "--output=json", "listaccts", "search=x"],
            &["/usr/local/cpanel/bin/whmapi1", "--output=xml", "listaccts"],
            &["/usr/local/cpanel/bin/whmapi1", "listaccts"],
            // test: other flags, other trees, traversal, other users' or unknown homes
            &["/usr/bin/test", "-x", "/var/cpanel/suspended/olscpa"],
            &["/usr/bin/test", "-e", "/etc/shadow"],
            &["/usr/bin/test", "-e", "/var/cpanel/suspended/"],
            &["/usr/bin/test", "-e", "/var/cpanel/suspended/../../etc/shadow"],
            &["/usr/bin/test", "-d", "/usr/local/cpanel/../../../etc/"],
            &["/usr/bin/test", "-d", "/usr/local/cpanel//etc/"],
            &["/usr/bin/test", "-d", "/usr/local/cpanel/./x"],
            &["/usr/bin/test", "-d", "/home/bob/public_html/"],
            &["/usr/bin/test", "-d", "/home/olscpa/"],
            &["/usr/bin/test", "-d", "/home.old/olscpa/public_html"],
            &["/usr/bin/test", "-d", "/newhome/olscpa/public_html"],
            &["/usr/bin/test", "-d", "/usr/home/olscpa/public_html"],
            &["/usr/bin/test", "-d", "/Home2/olscpa/public_html"],
            &["/usr/bin/test", "-d", "/home2/olscpb/public_html/../../olscpa/x"],
            &["/usr/bin/cat", "/home.old/.htaccess"],
            &["/usr/bin/cat", "/newhome/.htaccess"],
            &["/usr/bin/cat", "/data/.htaccess"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat", "/home.old/olscpa/.htaccess"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/sha256sum", "/home+x/olscpa/.htpasswds/passwd"],
            &["/usr/bin/test", "-d", "/usr/local/cpanelx/"],
            &["/usr/bin/test", "-e", "/var/cpanel/suspended/olscpa", "-o", "-e", "/etc/shadow"],
            // runuser: unknown user, root, nobody, other users' homes, traversal, other files, other programs
            &["/usr/sbin/runuser", "-u", "bob", "--", "/usr/bin/cat", "/home/bob/.htaccess"],
            &["/usr/sbin/runuser", "-u", "root", "--", "/usr/bin/cat", "/root/.htaccess"],
            &["/usr/sbin/runuser", "-u", "root", "--", "/usr/bin/cat", "/home/root/.htaccess"],
            &["/usr/sbin/runuser", "-u", "nobody", "--", "/usr/bin/cat", "/home/nobody/.htaccess"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat", "/home/olscpb/public_html/.htaccess"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat", "/home/olscpa/../olscpb/.htaccess"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat", "/home/olscpa/public_html/./.htaccess"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat", "/home/olscpa/.bash_history"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat", "/home/olscpa/x.htaccess"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat", "/home/olscpa/.htaccess/"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat", "/home/olscpab/.htaccess"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat", "/etc/.htaccess"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat", "/home/olscpa/.htaccess", "/etc/shadow"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/tee", "/home/olscpa/.htaccess"],
            &["/usr/sbin/runuser", "-u", "olscpa", "/usr/bin/cat", "/home/olscpa/.htaccess"],
            &["/usr/sbin/runuser", "-u", "-olscpa", "--", "/usr/bin/cat", "/home/-olscpa/.htaccess"],
            // php: other code, other options
            &["/opt/cpanel/ea-php83/root/usr/bin/php", "-n", "-r", "system('id');"],
            &["/opt/cpanel/ea-php83/root/usr/bin/php", "-r", CONSTANTS_CODE],
            &["/opt/cpanel/ea-php83/root/usr/bin/php", "-n", "-r", CONSTANTS_CODE, "x"],
            &["/opt/cpanel/../../usr/bin/php", "-n", "-r", CONSTANTS_CODE],
            &["/usr/bin/php", "-n", "-r", CONSTANTS_CODE],
            // fixed commands with other arguments
            &["/usr/bin/hostname", "new-name"],
            &["/usr/bin/hostname", "-f", "x"],
            &["/usr/sbin/httpd", "-k", "stop"],
            &["/usr/sbin/httpd", "-M", "-f", "/tmp/evil.conf"],
            &["/usr/sbin/httpd", "-t"],
            &["/usr/sbin/ip", "-6", "addr", "add", "::1/128", "dev", "lo"],
            // sha256sum: other trees, other homes, outside .htpasswds, options
            &["/usr/bin/sha256sum", "/etc/shadow"],
            &["/usr/bin/sha256sum", "/var/cpanel/ssl/../../../etc/shadow"],
            &["/usr/bin/cat", "/etc/apache2/conf.d/modsec_vendor_configs/"],
            &["/usr/bin/cat", "/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/../../../shadow"],
            &["/usr/bin/cat", "/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/./x.conf"],
            &["/usr/bin/cat", "/etc/apache2/conf.d/modsec_vendor_configs/OWASP3//x.conf"],
            &["/usr/bin/cat", "/etc/apache2/conf.d/modsec_vendor_configs/OWASP3/"],
            &["/usr/bin/cat", "/etc/apache2/conf.d/modsec_vendor_configs/.hidden"],
            &["/usr/bin/cat", "/etc/apache2/conf.d/modsec_vendor_configs/a b.conf"],
            &["/usr/bin/cat", "/etc/apache2/conf.d/modsec_vendor_configsX/a.conf"],
            &["/usr/bin/cat", "/etc/apache2/conf.d/modsec/other.conf"],
            &["/usr/bin/cat", "-n", "/etc/apache2/conf.d/modsec2.conf"],
            &["/usr/bin/test", "-f", "/etc/apache2/conf.d/modsec2.conf"],
            &["/usr/bin/test", "-e", "/etc/apache2/conf.d/other.conf"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/cat", "/etc/apache2/conf.d/modsec2.conf"],
            &["/usr/bin/sha256sum", "/home/olscpa/.htaccess"],
            &["/usr/bin/sha256sum", "/home/olscpa/.htpasswds/passwd"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/sha256sum", "/home/olscpb/.htpasswds/passwd"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/sha256sum", "/home/olscpa/.htpasswds/"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/sha256sum", "/home/olscpa/.ssh/id_rsa"],
            &["/usr/sbin/runuser", "-u", "olscpa", "--", "/usr/bin/sha256sum", "/var/cpanel/ssl/x"],
            &["/usr/bin/sha256sum", "/home/olscpa/.htpasswds/"],
            &["/usr/bin/sha256sum", "/home/olscpa/.htpasswds/../.ssh/id_rsa"],
            &["/usr/bin/sha256sum", "/home/bob/.htpasswds/passwd"],
            &["/usr/bin/sha256sum", "-c", "/var/cpanel/ssl/x"],
            &["/usr/bin/sha256sum", "/var/cpanel/ssl/a", "/etc/shadow"],
            // lab-only
            &["/usr/bin/curl", "-s", "http://a.test/"],
        ];
        for items in refused {
            assert_eq!(rule(items), None, "accepted: {items:?}");
        }
        let changed = |index: usize, value: &str| {
            let mut items = find("/home/olscpa/public_html", "olscpa");
            items[index] = value.to_string();
            allowed(&items, &accounts(&["olscpa", "olscpb"]))
        };
        assert!(allowed(&find("/home/olscpa/public_html", "olscpa"), &accounts(&["olscpa"])).is_some());
        assert!(allowed(&find("/home/olscpa", "olscpa"), &accounts(&["olscpa"])).is_some());
        assert!(allowed(&find("/home/olscpb/public_html", "olscpa"), &accounts(&["olscpa", "olscpb"])).is_none());
        assert!(allowed(&find("/", "olscpa"), &accounts(&["olscpa"])).is_none());
        assert!(allowed(&find("/home/olscpa/public_html", "olscpa"), &accounts(&["olscpb"])).is_none());
        assert!(allowed(&find("/home/olscpa/public_html/..", "olscpa"), &accounts(&["olscpa"])).is_none());
        assert_eq!(changed(5, "-L"), None);
        assert_eq!(changed(16, "-delete"), None);
        assert_eq!(changed(17, "%p"), None);
        let mut longer = find("/home/olscpa/public_html", "olscpa");
        longer.push("-delete".into());
        assert_eq!(allowed(&longer, &accounts(&["olscpa"])), None);
    }

    #[test]
    fn paths_are_checked_lexically() {
        for good in ["/", "/a", "/a/", "/a/b c/.htaccess", "/a/..b/c"] {
            assert!(normalized(good), "{good}");
        }
        for bad in ["", "a", "a/b", "//", "/a//b", "/a/./b", "/a/../b", "/a/..", "/a/.", "/a/b//", "/a\0b"] {
            assert!(!normalized(bad), "{bad:?}");
        }
    }
}
