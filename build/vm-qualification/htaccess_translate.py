#!/usr/bin/python3
"""Translate the access-control subset of a tenant's .htaccess files into OLS vhost contexts
(plan §9, R-03, OLS-16). Anything not understood is returned as a blocker, never ignored.

Supported:
- cPanel Directory Privacy sections (cp:ppd markers): AuthType Basic, AuthName, AuthUserFile,
  Require valid-user -> realm + context with "required valid-user".
- "Require all denied" at directory level -> context with allowBrowse 0.
- <Files "name"> / <FilesMatch "regex"> containing only "Require all denied" -> regex context.
- cPanel-generated PHP ini and handler sections -> recognized; handled by the PHP compiler (OLS-15).
- mod_rewrite directives (optionally inside <IfModule mod_rewrite.c>) -> the directory's context gets
  the same per-directory rules (owner decision HR-D07: OLS never reads .htaccess itself). As in Apache,
  a directory with its own rules replaces its parent's (unless "RewriteOptions Inherit"), and one
  without rewrite directives keeps its parent's. Proxying, handler flags, targets naming an internal
  backend (loopback, WebSocket/socket schemes, dotless names such as the cpsrvdNNNN proxy backends),
  quoted or continued arguments, control characters, heredoc terminators, unknown Rewrite* directives
  and rules without "RewriteEngine" are blockers.
- LiteSpeed Cache sections (<IfModule LiteSpeed>, written by LiteSpeed Cache for WordPress; FV-01): Apache
  never applies them, LiteSpeed does, and OLS serves with LiteSpeed's behaviour, so their RewriteEngine,
  RewriteCond, RewriteRule (Cache-Control/Cache-Vary environment flags included) and CacheKeyModify lines
  join the directory's rules in document order; "CacheLookup on" is honoured by the vhost cache policy
  and dropped. "CacheLookup off", ESI ("esi=on", unsupported by OLS) and any other directive in such a
  section are blockers. Outside it, an environment flag named "cache-..." is a blocker: Apache only sets
  a variable, OLS would start caching (plan §9.4).
- <IfModule mod_authz_core.c|mod_expires.c|mod_headers.c> / <IfModule !mod_...> (modules cPanel's EasyApache 4
  always has loaded): the first keeps its body, the negated one is dropped, at directory level and inside
  <Files>/<FilesMatch> (not inside <IfModule LiteSpeed>).
- mod_expires: ExpiresActive on|off, ExpiresDefault and ExpiresByType (short "A<seconds>"/"M<seconds>" or the
  "access|now|modification plus <n> <unit>..." syntax, normalised to seconds) become the context's
  enableExpires / expiresDefault / expiresByType. OLS adds "public, max-age=N" and Expires to static files only.
- "Deny the directory, allow listed files": a lone directory-level "Require all denied" plus <Files>/<FilesMatch>
  blocks containing only "Require all granted" becomes ONE regex context whose negative lookahead exempts the
  allowed basenames (everything else below the directory, the directory itself included, is denied). Granted
  blocks in any other combination are blockers.
OLS-specific limits (e.g. 403 vs Apache's own response bodies) are verified by experiments."""
import hashlib
import json
import re
import sys

PPD = re.compile(r"#-+cp:ppd.*?# End section managed by cPanel: Password Protected Directories[^\n]*\n#-+cp:ppd", re.S)
PHP_INI = re.compile(r"# BEGIN cPanel-generated php ini directives.*?# END cPanel-generated php ini directives[^\n]*", re.S)
HANDLER = re.compile(r"# php -- BEGIN cPanel-generated handler.*?# php -- END cPanel-generated handler[^\n]*", re.S)
REWRITE_BLOCK = re.compile(r"<IfModule\s+mod_rewrite\.c\s*>(.*?)</IfModule>", re.S | re.I)
REWRITE_DIRECTIVE = re.compile(r"^Rewrite(Engine|Base|Cond|Rule|Options)\b", re.I)
FILES = re.compile(r"<(Files|FilesMatch)\s+\"?([^\">]+)\"?\s*>(.*?)</\1>", re.S | re.I)
SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/@+-]*$")

ALWAYS_LOADED_MODULES = r"mod_(?:authz_core|expires|headers)\.c"
LITESPEED_OPEN = re.compile(r"^<IfModule\s+LiteSpeed\s*>$", re.I)
AUTHZ_OPEN = re.compile(r"^<IfModule\s+(!?)" + ALWAYS_LOADED_MODULES + r"\s*>$", re.I)
ANY_IFMODULE_OPEN = re.compile(r"^<IfModule\b[^>]*>$", re.I)
IFMODULE_CLOSE = re.compile(r"^</IfModule\s*>$", re.I)
GRANT_CHARS = r"[A-Za-z0-9._@\\^$|()?*+\[\]-]+"

def _resolve_modules(text):
    """Apache evaluates <IfModule mod_X.c> at parse time; mod_authz_core, mod_expires and mod_headers are always
    loaded on cPanel's EasyApache 4, so the body of <IfModule mod_X.c> is kept (wrapper removed) and the body of
    <IfModule !mod_X.c> is dropped.
    Other <IfModule> lines are left untouched. Unbalanced sections leave the text unchanged (blockers follow)."""
    if not re.search(r"<IfModule\s+!?" + ALWAYS_LOADED_MODULES + r"\s*>", text, re.I):
        return text
    out, stack = [], []
    for line in re.split(r"\r\n|\n|\r", text):
        stripped = line.strip()
        known = AUTHZ_OPEN.match(stripped)
        if known and "ls" not in stack:
            stack.append("drop" if known.group(1) else "keep")
        elif ANY_IFMODULE_OPEN.match(stripped):
            # Inside <IfModule LiteSpeed> a nested module section stays as written (and is refused later).
            if "drop" not in stack:
                out.append(line)
            stack.append("ls" if LITESPEED_OPEN.match(stripped) else "other")
        elif IFMODULE_CLOSE.match(stripped):
            if not stack:
                return text
            if stack.pop() in ("other", "ls") and "drop" not in stack:
                out.append(line)
        elif "drop" not in stack:
            out.append(line)
    return text if stack else "\n".join(out) + "\n"

IFMODULE_OPEN = re.compile(r"^<IfModule[ \t]+(!?)([^\s>]+)[ \t]*>$", re.I)
# RV-46 (soak test 2026-10-30): with the server's own module list (`httpd -M`), every <IfModule> is decided as Apache
# decides it at parse time: the module identifier ("rewrite_module") or its source file name ("mod_rewrite.c").
MODULE_SOURCE = re.compile(r"mod_([A-Za-z0-9_]+)\.c", re.I)


def _module_loaded(name, modules):
    name = name.strip("\"'")
    source = MODULE_SOURCE.fullmatch(name)
    return (source.group(1) + "_module" if source else name).lower() in modules


def _resolve_all_modules(text, modules):
    """Every <IfModule [!]name> outside <IfModule LiteSpeed> is evaluated against the loaded modules: the body of a
    true section is kept (wrapper removed), a false one is dropped with everything nested in it. <IfModule LiteSpeed>
    and anything inside it stay as written (LiteSpeed evaluates those; see LITESPEED_BLOCK), as does
    <IfModule !LiteSpeed> (refused later). Unbalanced sections leave the text unchanged (blockers follow)."""
    out, stack = [], []
    for line in re.split(r"\r\n|\n|\r", text):
        stripped = line.strip()
        section = IFMODULE_OPEN.match(stripped)
        if section and "ls" not in stack and section.group(2).strip("\"'").lower() != "litespeed":
            stack.append("keep" if _module_loaded(section.group(2), modules) != bool(section.group(1)) else "drop")
        elif ANY_IFMODULE_OPEN.match(stripped):
            if "drop" not in stack:
                out.append(line)
            stack.append("ls" if LITESPEED_OPEN.match(stripped) else "other")
        elif IFMODULE_CLOSE.match(stripped):
            if not stack:
                return text
            if stack.pop() in ("other", "ls") and "drop" not in stack:
                out.append(line)
        elif "drop" not in stack:
            out.append(line)
    return text if stack else "\n".join(out) + "\n"


# Pre-compressed assets (Joomla's and Drupal's stock .htaccess): inside <IfModule mod_headers.c>, requests for .css/.js
# are rewritten to an existing .gz/.br copy, typed with [T=...] and sent with "Content-Encoding". OLS compresses
# static and dynamic responses itself (gzip and brotli, compressed static copies kept up to date: the compiled
# server configuration), so the client gets the same resource compressed either way. Only this exact idiom is
# recognised; the whole section is then left to OLS.
PRECOMPRESSED_SECTION = re.compile(r"<IfModule[ \t]+mod_headers\.c[ \t]*>((?:(?!</?IfModule\b).)*?)</IfModule[ \t]*>", re.S | re.I)
PRECOMPRESSED_LINES = [
    re.compile(r'^RewriteCond[ \t]+"?%\{HTTP:Accept-encoding\}"?[ \t]+"?(gzip|br)"?$', re.I),
    re.compile(r'^RewriteCond[ \t]+"?%\{REQUEST_FILENAME\}\\\.(gz|br)"?[ \t]+"?-s"?$', re.I),
    re.compile(r'^RewriteRule[ \t]+"?\^\(\.\*(?:(css|js)_\[a-zA-Z0-9-_\]\+)?\)\\\.(css|js)\$?"?[ \t]+"?\$1\\\.(css|js)\\\.(gz|br)"?[ \t]+\[QSA\]$'),
    re.compile(r'^RewriteRule[ \t]+"?\\\.(css|js)\\\.(gz|br)\$"?[ \t]+"?-"?[ \t]+'
               r'\[T=(text/css|text/javascript|application/javascript),E=no-gzip:1,E=no-brotli:1\]$'),
]
PRECOMPRESSED_FILES = re.compile(r"\(\\\.js\\\.(gz|br)\|\\\.css\\\.\1\)\$")


def _precompressed_section(body):
    files = FILES.findall(body)
    if not files:
        return False
    for kind, pattern, inner in files:
        encoding = PRECOMPRESSED_FILES.fullmatch(pattern)
        if kind.lower() != "filesmatch" or not encoding or [l.lower() for l in _directives(inner)] != [
                f"header set content-encoding {'gzip' if encoding.group(1) == 'gz' else 'br'}", "header append vary accept-encoding"]:
            return False
    rest = _directives(FILES.sub("", body))
    return bool(rest) and all(any(rx.match(line) for rx in PRECOMPRESSED_LINES) for line in rest)


def _strip_precompressed(text):
    return PRECOMPRESSED_SECTION.sub(lambda m: "" if _precompressed_section(m.group(1)) else m.group(0), text)


def _regex_supported(pattern):
    """A FilesMatch pattern that is balanced and simple enough to embed in a group: escapes are punctuation or
    d/w/s/D/W/S (no back-references), classes hold no escapes, "(?" constructs and stacked or leading
    quantifiers are refused."""
    depth, i, n, quantifiable = 0, 0, len(pattern), False
    while i < n:
        c = pattern[i]
        if c == "\\":
            if i + 1 >= n or (pattern[i + 1].isalnum() and pattern[i + 1] not in "dwsDWS"):
                return False
            quantifiable, i = True, i + 2
        elif c == "[":
            j = i + 1 + (1 if pattern[i + 1:i + 2] == "^" else 0)
            start = j
            while j < n and pattern[j] not in "]\\[":
                j += 1
            if j >= n or pattern[j] != "]" or j == start:
                return False
            quantifiable, i = True, j + 1
        elif c == "(":
            if pattern[i + 1:i + 2] == "?":
                return False
            depth, quantifiable, i = depth + 1, False, i + 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                return False
            quantifiable, i = True, i + 1
        elif c in "|^$":
            quantifiable, i = False, i + 1
        elif c in "*+?":
            if not quantifiable:
                return False
            quantifiable, i = False, i + 1
        else:
            quantifiable, i = True, i + 1
    return depth == 0

def _grant_regex(kind, pattern):
    """Basename regex (no trailing anchor) of one <Files>/<FilesMatch> pattern that grants access, or None when
    the pattern is not understood well enough. It never matches a name containing "/". Whatever it accepts is a
    subset of what Apache accepts, because everything else stays denied."""
    if kind.lower() == "files":
        if not re.fullmatch(r"[A-Za-z0-9._@*?-]+", pattern):
            return None
        return "".join("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c) for c in pattern)
    if not re.fullmatch(GRANT_CHARS, pattern) or "/" in pattern or not _regex_supported(pattern):
        return None
    body = pattern.lstrip("^")
    tail = re.search(r"(\\*)\$$", body)
    anchored = tail is not None and len(tail.group(1)) % 2 == 0
    return ("" if pattern.startswith("^") else "[^/]*") + "(?:" + body + ")" + ("" if anchored else "[^/]*")

SEARCH_CHARS = re.compile(r"[A-Za-z0-9._@\\^$|()?*+\[\]#!=<>,~:%-]+")
LOOKAROUND = re.compile(r"\(\?(?:[:=!]|<[=!])")


def _basename_search(pattern):
    """A <FilesMatch> regex (an unanchored search on the file's basename) rewritten to run inside a path regex that
    has reached the start of the last segment: "^" becomes "(?<=/)" (the basename starts after a slash), "#" is
    written \\x23 (it would start a comment in the OLS configuration). Groups, lookarounds ("(?:", "(?=", "(?!",
    "(?<=", "(?<!"), classes and alternations are kept; back-references, other "(?" constructs, braces, a "<<<"
    sequence and stacked or leading quantifiers are refused (None). "." and classes cannot cross a "/" there: the
    path regex places it in the last segment first."""
    if not SEARCH_CHARS.fullmatch(pattern) or "<<<" in pattern:
        return None
    out, i, n, depth, quantifiable = [], 0, len(pattern), 0, False
    while i < n:
        c = pattern[i]
        if c == "\\":
            if i + 1 >= n or (pattern[i + 1].isalnum() and pattern[i + 1] not in "dwsDWS"):
                return None
            out.append(pattern[i:i + 2])
            quantifiable, i = True, i + 2
        elif c == "[":
            j = i + 1 + (1 if pattern[i + 1:i + 2] == "^" else 0)
            start = j
            while j < n and pattern[j] not in "]\\[":
                j += 1
            if j >= n or pattern[j] != "]" or j == start:
                return None
            out.append(pattern[i:j + 1].replace("#", "\\x23"))
            quantifiable, i = True, j + 1
        elif c == "(":
            look = LOOKAROUND.match(pattern, i) if pattern[i + 1:i + 2] == "?" else None
            if pattern[i + 1:i + 2] == "?" and not look:
                return None
            token = look.group(0) if look else "("
            out.append(token)
            depth, quantifiable, i = depth + 1, False, i + len(token)
        elif c == ")":
            depth -= 1
            if depth < 0:
                return None
            out.append(")")
            quantifiable, i = True, i + 1
        elif c in "|$":
            out.append(c)
            quantifiable, i = False, i + 1
        elif c == "^":
            out.append("(?<=/)")
            quantifiable, i = False, i + 1
        elif c in "*+?":
            if not quantifiable:
                return None
            out.append(c)
            quantifiable, i = False, i + 1
        else:
            out.append("\\x23" if c == "#" else c)
            quantifiable, i = True, i + 1
    return "".join(out) if depth == 0 else None


def _static_header_context(docroot, extension, headers, root):
    """Headers for one static file type of the document root: a regex context serving the file itself. It carries
    the "/" context's access denial, authentication, expiry and headers (its own headers after them): the lab showed
    that such a context does not take the root context's headers by itself (soak test 2026-10-30)."""
    lines = [f"context exp:^/((?:.*/)?[^/]*\\.{extension})$ {{", f"  location                {docroot.rstrip('/')}/$1",
             f"  allowBrowse             {root.get('allowBrowse', '1')}"]
    lines += [f"  {key:<23} {root[key]}" for key in ("realm", "authName", "required", "enableExpires", "expiresDefault",
                                                    "expiresByType") if key in root]
    lines += ["  extraHeaders            <<<END_extraHeaders", *root.get("headers", []), *headers, "END_extraHeaders", "}\n"]
    return "\n".join(lines)


def _expires_value(text):
    """"A<seconds>" or "M<seconds>" for an Apache expiry (short or long syntax, optionally quoted), or None."""
    text = text.strip(" \t")
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip(" \t")
    short = EXPIRES_SHORT.match(text)
    if short:
        return short.group(1).upper() + str(int(short.group(2)))
    long = EXPIRES_LONG.match(text)
    if not long:
        return None
    seconds = 0
    for count, unit in re.findall(r"([0-9]+)[ \t]+([A-Za-z]+)", long.group(2)):
        unit = unit.lower()
        seconds += int(count) * EXPIRES_UNIT[unit[:2] if unit[:2] in ("mo", "mi") else unit[0]]
    if seconds > 2147483647:
        return None
    return ("M" if long.group(1).lower() == "modification" else "A") + str(seconds)

def _directives(text):
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]

def _realm_name(directory, user_file):
    return "ppd_" + hashlib.sha256(f"{directory}\0{user_file}".encode()).hexdigest()[:12]

DENY_ALL = [["Require all denied"], ["Deny from all"], ["Order deny,allow", "Deny from all"],
            ["Order allow,deny", "Deny from all"]]
NOOP_OPTIONS = {"followsymlinks", "symlinksifownermatch", "-multiviews"}
HEADER = re.compile(r"^Header\s+(?:(?:always|onsuccess)\s+)?(set|append|merge|add|unset)\s+([A-Za-z0-9-]+)(?:\s+(.+))?$", re.I)
# OLS 1.9.3 parses a trailing env= condition but never evaluates it (the header would be applied
# unconditionally); expr= and early have no OLS equivalent. Such lines are blockers.
# A quoted condition ("expr=...") is a condition too (soak test 2026-10-30: it was read as part of the value).
HEADER_CONDITION = re.compile(r"(^|\s)[\"']?(env|expr)=|(^|\s)early$", re.I)
EXPIRES_ACTIVE = re.compile(r"^ExpiresActive[ \t]+(on|off)$", re.I)
EXPIRES_DEFAULT = re.compile(r"^ExpiresDefault[ \t]+(.+)$", re.I)
EXPIRES_BY_TYPE = re.compile(r"^ExpiresByType[ \t]+([A-Za-z0-9][A-Za-z0-9.+_-]*/[A-Za-z0-9][A-Za-z0-9.+_-]*)[ \t]+(.+)$", re.I)
EXPIRES_SHORT = re.compile(r"^([AaMm])([0-9]{1,9})$")
EXPIRES_LONG = re.compile(r"^(access|now|modification)(?:[ \t]+plus)?((?:[ \t]+[0-9]{1,9}[ \t]+(?:years?|months?|weeks?|days?|hours?|minutes?|seconds?))+)$", re.I)
EXPIRES_UNIT = {"y": 31536000, "mo": 2592000, "w": 604800, "d": 86400, "h": 3600, "mi": 60, "s": 1}
EXPIRES_BY_TYPE_LIMIT = 3500
ERROR_DOCUMENT = re.compile(r"^ErrorDocument\s+([45]\d\d)\s+(/[A-Za-z0-9._/-]*)$")
# RV-46 (soak test 2026-10-30), what the stock .htaccess of Joomla, Drupal and Laravel need:
DIRECTORY_INDEX = re.compile(r"^DirectoryIndex((?:[ \t]+[A-Za-z0-9._-]+)+)$", re.I)
ADD_TYPE = re.compile(r"^AddType[ \t]+([A-Za-z0-9.+/_-]+)((?:[ \t]+\.?[A-Za-z0-9]+)+)$", re.I)
ADD_ENCODING = re.compile(r"^AddEncoding[ \t]+(gzip|x-gzip)((?:[ \t]+\.?[A-Za-z0-9]+)+)$", re.I)
INDEX_IGNORE = re.compile(r"^IndexIgnore\b", re.I)
# OLS answers a request carrying a Proxy header with 400 (checked on OLS 1.9.3, 2026-10-30), so the httpoxy
# mitigation Drupal writes is already in effect.
PROXY_UNSET = re.compile(r"^RequestHeader[ \t]+unset[ \t]+Proxy$", re.I)
# The MIME types OLS 1.9.3 maps these extensions to by default (conf/mime.properties): an AddType naming the same
# type changes nothing. Any other AddType is a blocker.
OLS_DEFAULT_MIME = {"svg": "image/svg+xml", "svgz": "image/svg+xml", "webp": "image/webp"}
# Static file types a header-only <FilesMatch> or AddEncoding may target with its own regex context (served as a
# static file there: never a script).
STATIC_EXTENSION = re.compile(r"\\\.([A-Za-z0-9]+)\$")
# Drupal's "no scripts in uploads" idiom (SA-2006-006, SA-2013-003): a handler name that does not exist, so Apache
# sends every file of the directory as it is and never runs a script. OLS: the script suffixes of that directory are
# mapped to a static type (context addMIMEType), so nothing there reaches lsphp.
DRUPAL_NO_SCRIPTS = re.compile(r"^SetHandler[ \t]+Drupal_Security_Do_Not_Remove_See_SA_[0-9]{4}_[0-9]{3}$")
NO_SCRIPTS_MIME = "application/octet-stream php php3 php4 php5 php7 php8 phtml pht phar inc cgi pl py sh shtml"
# A PHP setting inside <IfModule LiteSpeed> (LiteSpeed Cache for Drupal writes "php_value output_buffering Off"):
# LiteSpeed applies it to the directory's PHP, Apache never reads the section; OLS takes it as the context's
# phpIniOverride (httpcontext.cpp). Outside that section a php_value stays a blocker (Apache with PHP-FPM refuses it).
LITESPEED_PHP_VALUE = re.compile(r'^php_(value|flag)[ \t]+([A-Za-z0-9_.]+)[ \t]+([A-Za-z0-9_.,:/+-]+|"[A-Za-z0-9_.,:/ +-]*")$')
SCRIPT_EXTENSIONS = {"php", "php3", "php4", "php5", "php7", "php8", "phtml", "phar", "cgi", "pl", "py", "sh", "shtml", "asp", "aspx", "jsp"}
# Directive names and arguments are separated by any run of blanks; OLS accepts tabs as well as spaces.
REWRITE_SPACE = re.compile(r"[ \t]+")
REWRITE_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
# The complete flag expression: everything after the second argument, which may contain blanks.
REWRITE_FLAGS = re.compile(r"^\[([^\[\]]*)\]$")
# Backslash-escaped blanks and line continuations (any rewrite line) and quotes (RewriteRule) would
# split the arguments differently from the blank-separated reading below.
REWRITE_ESCAPED = re.compile(r"\\([ \t]|$)")
REWRITE_QUOTE = re.compile(r"[\"']")
# A tenant must never reach the server's own services through a rewrite (review F-13): loopback and
# socket targets, and any literal host without a dot, which names a configured extProcessor (for
# example the cpsrvdNNNN proxy backends). A host taken from a variable or back-reference is a redirect.
# LiteSpeed Cache sections (FV-01). OLS 1.9.3 reads RewriteCond, RewriteRule and CacheKeyModify in rule text
# (rewriteengine.cpp parseRules; rewriterule.cpp turns CacheKeyModify into an always-matching rule setting
# cache-key-mod) and only logs "CacheLookup"; the lookup itself is the vhost's cache policy (lscache.py).
LITESPEED_BLOCK = re.compile(r"<IfModule\s+LiteSpeed\s*>(.*?)</IfModule>", re.S | re.I)
CACHE_DIRECTIVE = re.compile(r"^Cache(Lookup|KeyModify)\b", re.I)
CACHE_LOOKUP_ON = re.compile(r"^CacheLookup[ \t]+((public|private)[ \t]+)?on$", re.I)
# cacheconfig.cpp CacheKeyModList::parseAppend: "clear" or "-qs:<name>" (a trailing "*" matches a prefix).
CACHE_KEY_MODIFY = re.compile(r"^CacheKeyModify[ \t]+(-qs:[A-Za-z0-9_.-]+\*?|clear)$", re.I)
LITESPEED_QUOTED_ENV = re.compile(r"^\[E=\"cache-(vary|control):[A-Za-z0-9_,.:=+-]*\"\]$", re.I)
ESI_ON = re.compile(r"esi[ \t]*=[ \t]*\"?on", re.I)
REWRITE_INTERNAL = re.compile(r"^(ws|wss|unix|proxy):|^[a-z][a-z0-9+.-]*://([^/?#]*@|127\.|localhost|\[|0\.0\.0\.0"
                              r"|(?![%$])[^/?#.]*([/?#]|$))", re.I)

def _flags_safe(text, litespeed):
    """A complete "[...]" flag list without proxy/handler flags or internal targets. An environment value
    named "cache-..." drives the OLS cache module (OLS rewriteengine.cpp expandEnv: Cache-Control,
    Cache-Ctrl, Cache-Vary, Cache-Key-Mod); Apache only sets a variable, so outside <IfModule LiteSpeed>
    such a flag would activate on OLS what is inactive on Apache (plan §9.4) and is refused."""
    flags = REWRITE_FLAGS.match(text)
    if not flags:
        return False
    for flag in re.split(r"[ \t,]+", flags.group(1)):
        name, _, value = flag.partition("=")
        if name.lower() in ("p", "proxy", "h", "handler") or REWRITE_INTERNAL.match(value):
            return False
        if name.lower() in ("e", "env") and value.lstrip("\"'").lower().startswith("cache-") and not litespeed:
            return False
    return True

def _ols_arguments(text):
    """The first two arguments of a rewrite line split as OLS 1.9.3 does (ls_parsenextarg,
    src/lsr/ls_strtool.c:470: a leading quote delimits the argument, a backslash escapes the next
    character), followed by the rest of the line when present; None for an unterminated argument."""
    args, i, n = [], 0, len(text)
    while len(args) < 2:
        while i < n and text[i] in " \t":
            i += 1
        if i >= n:
            return args
        quote = text[i] if text[i] in "\"'" else ""
        i += 1 if quote else 0
        start = i
        while i < n and not ((quote and text[i] == quote) or (not quote and text[i] in " \t")):
            i += 2 if text[i] == "\\" else 1
        if i > n or (quote and i >= n):
            return None
        args.append(text[start:i])
        i += 1
    rest = text[i:].strip(" \t")
    return args + [rest] if rest else args

def _litespeed_quoted_safe(word, rest):
    """Inside <IfModule LiteSpeed> only OLS reads the line, so quotes and escaped blanks are split the way
    OLS splits them. Accepted: a RewriteCond whose test string or pattern is quoted or contains escaped
    blanks (LiteSpeed Cache for WordPress mobile and WebP vary rules), and a RewriteRule "<pattern> -
    [E="Cache-Vary|Cache-Control:<value>"]" (its login-cookie vary rule, quoted for OLS)."""
    args = _ols_arguments(rest)
    if args is None or len(args) < 2 or any(a.startswith("|") for a in args[:2]):
        return False
    if word == "rewriterule":
        return (len(args) == 3 and not rest.lstrip(" \t").startswith(("\"", "'")) and args[1] == "-"
                and LITESPEED_QUOTED_ENV.match(args[2]) is not None)
    return len(args) == 2 or _flags_safe(args[2], True)

# Double-quoted arguments outside <IfModule LiteSpeed> (Drupal's stock rules): Apache (ap_getword_conf) and OLS
# (ls_parsenextarg) split them the same way and keep inner backslashes, as long as a quoted argument holds no
# escaped quote and no escaped blank; then OLS reads the line as Apache does.
APACHE_ARGUMENT = r'"(?:[^"\\\n]|\\[^"\s])*"|[^\s"\']+'
QUOTED_ARGUMENTS = re.compile(rf"^({APACHE_ARGUMENT})[ \t]+({APACHE_ARGUMENT})(?:[ \t]+(\[[^\[\]]*\]))?$")

def _rewrite_arguments_safe(word, rest, litespeed=False):
    """Whether a RewriteCond/RewriteRule argument list is fully understood and names no internal backend.
    ESI is not supported by OLS (plan §20.3): a LiteSpeed rule turning it on is refused."""
    if litespeed and ESI_ON.search(rest):
        return False
    if litespeed and (REWRITE_ESCAPED.search(rest) or REWRITE_QUOTE.search(rest)):
        return _litespeed_quoted_safe(word, rest)
    if REWRITE_QUOTE.search(rest) and not REWRITE_ESCAPED.search(rest):
        quoted = QUOTED_ARGUMENTS.match(rest)
        if not quoted:
            return False
        args = [a[1:-1] if a.startswith('"') else a for a in quoted.groups()[:2]] + ([quoted.group(3)] if quoted.group(3) else [])
        if any(a.startswith("|") for a in args[:2]) or (word == "rewriterule" and (
                args[1].startswith("[") or REWRITE_INTERNAL.match(args[1]))):
            return False
        return len(args) < 3 or _flags_safe(args[2], litespeed)
    args = REWRITE_SPACE.split(rest, 2)
    if len(args) < 2 or REWRITE_ESCAPED.search(rest) or any(a.startswith("|") for a in args[:2]) or (
            word == "rewriterule" and (REWRITE_QUOTE.search(rest) or args[1].startswith("[")
                                       or REWRITE_INTERNAL.match(args[1]))):
        return False
    return len(args) < 3 or _flags_safe(args[2], litespeed)

def _tagged_directives(text):
    """(directive, inside <IfModule LiteSpeed>) in document order. Apache never reads such a block;
    LiteSpeed, whose behaviour OLS serves here, applies it like any other line."""
    out, position = [], 0
    for match in LITESPEED_BLOCK.finditer(text):
        out += [(line, False) for line in _directives(text[position:match.start()])]
        out += [(line, True) for line in _directives(match.group(1))]
        position = match.end()
    return out + [(line, False) for line in _directives(text[position:])]

def _is_rewrite(line, litespeed):
    return bool(REWRITE_DIRECTIVE.match(line) or (litespeed and CACHE_DIRECTIVE.match(line)))

def _rewrite(uri, lines, blockers):
    """Context rewrite settings for one directory's rewrite lines ((line, inside <IfModule LiteSpeed>)
    pairs), or None after a blocker or when nothing remains."""
    settings, rules, engine, lookups = {}, [], None, 0
    for line, litespeed in lines:
        if "END_" in line:
            blockers.append(f"{uri}: unsupported rewrite line {line!r}")
            return None
        if REWRITE_CONTROL.search(line):
            blockers.append(f"{uri}: rewrite line with control characters")
            return None
        word, rest = (REWRITE_SPACE.split(line, 1) + [""])[:2]
        word = word.lower()
        if word == "rewriteengine":
            if rest.lower() not in ("on", "off"):
                blockers.append(f"{uri}: unsupported RewriteEngine {rest!r}")
                return None
            engine = rest.lower() == "on"
        elif word == "rewritebase":
            if not SAFE_PATH.match(rest):
                blockers.append(f"{uri}: unsupported RewriteBase {rest!r}")
                return None
            settings["base"] = rest
        elif word == "rewriteoptions":
            if rest.lower() != "inherit":
                blockers.append(f"{uri}: unsupported RewriteOptions {rest!r}")
                return None
            settings["inherit"] = "1"
        elif word == "cachelookup":
            # Honoured by the vhost's cache policy (lookups wherever the cache is enabled); "off" cannot be
            # expressed per directory in OLS.
            if not CACHE_LOOKUP_ON.match(line):
                blockers.append(f"{uri}: unsupported CacheLookup {line!r}")
                return None
            lookups += 1
        elif word == "cachekeymodify":
            if not CACHE_KEY_MODIFY.match(line):
                blockers.append(f"{uri}: unsupported CacheKeyModify {line!r}")
                return None
            rules.append(line)
        elif word in ("rewritecond", "rewriterule"):
            if not _rewrite_arguments_safe(word, rest, litespeed):
                blockers.append(f"{uri}: unsupported {'RewriteRule' if word == 'rewriterule' else 'RewriteCond'} {line!r}")
                return None
            rules.append(line)
        else:
            blockers.append(f"{uri}: unsupported rewrite directive {line!r}")
            return None
    if engine is None and lookups == len(lines):
        return None
    if engine is None:
        blockers.append(f"{uri}: rewrite directives without RewriteEngine")
        return None
    return {"enable": "1" if engine else "0", **settings, "rules": rules if engine else []}

def _is_deny_all(lines):
    return any([l.lower() for l in lines] == [d.lower() for d in variant] for variant in DENY_ALL)

def _render_context(uri, location, props):
    lines = [f"context {uri} {{"]
    if location:
        lines.append(f"  location                {location}")
    for key in ("allowBrowse", "autoIndex", "realm", "authName", "required", "enableExpires", "expiresDefault",
                "expiresByType", "indexFiles", "addMIMEType"):
        if key in props:
            lines.append(f"  {key:<23} {props[key]}")
    if props.get("headers"):
        lines.append("  extraHeaders            <<<END_extraHeaders")
        lines.extend(props["headers"])
        lines.append("END_extraHeaders")
    if props.get("phpIniOverride"):
        lines.append("  phpIniOverride  {")
        lines.extend(props["phpIniOverride"])
        lines.append("  }")
    if "rewrite" in props:
        rewrite = props["rewrite"]
        lines.append("  rewrite  {")
        for key in ("enable", "inherit", "base"):
            if key in rewrite:
                lines.append(f"    {key:<21} {rewrite[key]}")
        if rewrite["rules"]:
            lines.append("    rules                 <<<END_rules")
            lines.extend(rewrite["rules"])
            lines.append("END_rules")
        lines.append("  }")
    lines.append("}\n")
    return "\n".join(lines)

def translate(files, docroot, modules=None, root_headers=None):
    """files: {relative_dir ("" or "sub/dir"): .htaccess text}; modules: the identifiers of the modules Apache has
    loaded (`httpd -M`, e.g. "rewrite_module"), or None when unknown (then only the modules EasyApache 4 always
    loads are assumed). Returns (realms, blocks, blockers); blocks are contexts plus vhost-level errorPage entries."""
    loaded = None if modules is None else {m.lower() for m in modules}
    realms, regex_contexts, blockers = [], [], []
    error_pages = {}  # status -> entry; a later ErrorDocument for the same status wins, as in Apache
    contexts = {}
    # Headers the virtual host itself sets on every response (RV-44: cPanel's technical domains): they lead the "/"
    # context's own, and the static file contexts copy them with the rest of it.
    if root_headers and SAFE_PATH.match(docroot.rstrip("/") + "/"):
        contexts["/"] = {"location": docroot.rstrip("/") + "/", "headers": list(root_headers)}
    for rel, text in sorted(files.items()):
        uri = "/" + (rel.strip("/") + "/" if rel.strip("/") else "")
        location = docroot.rstrip("/") + uri
        if not SAFE_PATH.match(location):
            blockers.append(f"{uri}: unsafe path")
            continue
        props = contexts.setdefault(uri, {"location": location})
        remaining = PHP_INI.sub("", HANDLER.sub("", text))
        for match in PPD.finditer(remaining):
            section = {}
            for line in _directives(match.group(0)):
                key, _, value = line.partition(" ")
                section[key.lower()] = value.strip().strip('"')
            user_file = section.get("authuserfile", "")
            # The password file must be the account's own (review F-03): /<home-root>/<user>/.htpasswds/...
            home = "/".join(docroot.rstrip("/").split("/")[:3])
            if (section.get("authtype", "").lower() != "basic" or section.get("require") != "valid-user"
                    or not SAFE_PATH.match(user_file) or not user_file.startswith(home + "/.htpasswds/")
                    or "/../" in user_file or "/./" in user_file):
                blockers.append(f"{uri}: unsupported Directory Privacy section")
                continue
            realm = _realm_name(uri, user_file)
            name = re.sub(r"[^A-Za-z0-9 _.-]", "", section.get("authname", "Restricted")) or "Restricted"
            realms.append(f"realm {realm} {{\n  userDB {{\n    location              {user_file}\n  }}\n}}\n")
            props.update(realm=realm, authName=name, required="valid-user")
        remaining = PPD.sub("", remaining)
        remaining = _resolve_modules(remaining) if loaded is None else _resolve_all_modules(_strip_precompressed(remaining), loaded)
        grants, file_denies, static_headers = [], 0, []
        for match in FILES.finditer(remaining):
            kind, pattern, body = match.groups()
            if [l.lower() for l in _directives(body)] == ["require all granted"]:
                grants.append((kind, pattern))
                continue
            if loaded is not None and kind.lower() == "filesmatch" and pattern == r"\.php$" and [
                    l.lower() for l in _directives(body)] == ["expiresactive off"]:
                # OLS sets Expires on dynamic responses from the virtual host's own setting (httpcgitool.cpp
                # processExpires uses the root context), never from these directory contexts: already off.
                continue
            headers = [HEADER.match(l) for l in _directives(body)]
            static = STATIC_EXTENSION.fullmatch(pattern)
            if (loaded is not None and kind.lower() == "filesmatch" and headers and all(headers) and static
                    and static.group(1).lower() not in SCRIPT_EXTENSIONS):
                if uri != "/" or any(HEADER_CONDITION.search(h.group(3) or "") for h in headers):
                    blockers.append(f"{uri}: <{kind} {pattern}> with unsupported body")
                else:
                    static_headers.append((static.group(1), ["Header " + " ".join(part for part in h.groups() if part) for h in headers]))
                continue
            if (loaded is not None and kind.lower() == "files" and pattern == "*" and _directives(body)
                    and all(DRUPAL_NO_SCRIPTS.match(l) for l in _directives(body))):
                props["addMIMEType"] = NO_SCRIPTS_MIME
                continue
            if not _is_deny_all(_directives(body)):
                blockers.append(f"{uri}: <{kind} {pattern}> with unsupported body")
                continue
            # Validate what the tenant wrote; the translation below only adds "[^/]*" around it.
            # The structure is checked too (soak test 2026-10-30): a back-reference or a stray quantifier ("*a") made
            # an invalid OLS regex, and one tenant's file would have failed the whole server's configuration test.
            if not re.fullmatch(r"[A-Za-z0-9._@\\^$|()?*+\[\]-]+", pattern) or "/" in pattern or (
                    kind.lower() == "filesmatch" and not _regex_supported(pattern)):
                search = _basename_search(pattern) if loaded is not None and kind.lower() == "filesmatch" else None
                if search is None:
                    blockers.append(f"{uri}: unsupported <{kind}> pattern {pattern!r}")
                    continue
                # The path reaches the start of the last segment, then the basename is searched (Drupal's pattern).
                regex_contexts.append(f"context exp:^{re.escape(uri)}(?:.*/)?(?=[^/]*$)[^/]*?(?:{search}) {{\n"
                                      f"  allowBrowse             0\n}}\n")
                file_denies += 1
                continue
            if kind.lower() == "files":
                # <Files> takes a wildcard string, not a regex.
                regex = "".join("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c) for c in pattern)
            else:
                # FilesMatch is an unanchored search on the basename; keep that inside one segment.
                regex = ("" if pattern.startswith("^") else "[^/]*") + pattern.lstrip("^")
                regex = regex if regex.endswith("$") else regex + "[^/]*"
            # <Files> matches the basename in this directory and below.
            regex_contexts.append(f"context exp:^{re.escape(uri)}(.*/)?{regex.lstrip('^')}{'' if regex.endswith('$') else '$'} {{\n"
                                  f"  allowBrowse             0\n}}\n")
            file_denies += 1
        remaining = FILES.sub("", remaining)
        remaining = REWRITE_BLOCK.sub(lambda m: m.group(1), remaining)
        tagged = _tagged_directives(remaining)
        rewrite_lines = [(l, ls) for l, ls in tagged if _is_rewrite(l, ls)]
        if rewrite_lines:
            rewrite = _rewrite(uri, rewrite_lines, blockers)
            if rewrite is not None:
                props["rewrite"] = rewrite
        lines = [l for l, ls in tagged if not _is_rewrite(l, ls)]
        litespeed_lines = {l for l, ls in tagged if ls}
        deny_lines = [l for l in lines if l.lower() in {"require all denied", "deny from all", "order deny,allow", "order allow,deny"}]
        allow_list = False
        if grants:
            # Apache: the <Files> sections are merged after the directory's own rules, so a granted name is open
            # whatever the directory says. Only "the directory is denied, these names are not" is translated.
            if [l.lower() for l in deny_lines] != ["require all denied"] or file_denies or rewrite_lines:
                for kind, pattern in grants:
                    blockers.append(f'{uri}: <{kind} {pattern}> grants access without a lone directory-level "Require all denied"')
            else:
                alternatives = [_grant_regex(kind, pattern) for kind, pattern in grants]
                for (kind, pattern), regex in zip(grants, alternatives):
                    if regex is None:
                        blockers.append(f"{uri}: unsupported <{kind}> pattern {pattern!r}")
                if None not in alternatives:
                    allow_list = True
                    # Earlier path segments must not contain a dot: "x.php/allowed.js" is the script x.php with
                    # path info for Apache, which names the file by its real basename.
                    regex_contexts.append(f"context exp:^{re.escape(uri)}(?!(?:[^/.]*/)*(?=[^/]*$)(?:{'|'.join(alternatives)})$) {{\n"
                                          f"  allowBrowse             0\n}}\n")
        if deny_lines:
            if allow_list:
                pass
            elif _is_deny_all(deny_lines):
                props["allowBrowse"] = "0"
            else:
                blockers.append(f"{uri}: unsupported access rule combination {deny_lines!r}")
        expires_types = {}
        index_ignore = False
        for line in lines:
            if line in deny_lines:
                continue
            header = HEADER.match(line)
            error = ERROR_DOCUMENT.match(line)
            expires_active = EXPIRES_ACTIVE.match(line)
            expires_default = EXPIRES_DEFAULT.match(line)
            expires_type = EXPIRES_BY_TYPE.match(line)
            if expires_active:
                props["enableExpires"] = "1" if expires_active.group(1).lower() == "on" else "0"
            elif expires_default or expires_type:
                value = _expires_value((expires_default or expires_type).group(1 if expires_default else 2))
                if value is None:
                    blockers.append(f"{uri}: unsupported expiry {line!r}")
                elif expires_default:
                    props["expiresDefault"] = value
                else:
                    expires_types.pop(expires_type.group(1).lower(), None)
                    expires_types[expires_type.group(1).lower()] = value
            elif line.lower().startswith("options "):
                for option in line.split()[1:]:
                    lowered = option.lower()
                    if lowered == "-indexes":
                        props["autoIndex"] = "0"
                    elif lowered in ("+indexes", "indexes"):
                        props["autoIndex"] = "1"
                    elif loaded is not None and (lowered == "-includes" or (lowered == "-execcgi" and not uri.startswith("/cgi-bin/"))):
                        # OLS has no server-side includes, and runs CGI only in its cgi-bin context: both are off already.
                        pass
                    elif lowered.lstrip("+") not in NOOP_OPTIONS and lowered not in NOOP_OPTIONS:
                        blockers.append(f"{uri}: unsupported Options {option!r}")
            elif header and HEADER_CONDITION.search(header.group(3) or ""):
                blockers.append(f"{uri}: unsupported conditional Header {line!r}")
            elif header and "\n" not in line:
                props.setdefault("headers", []).append("Header " + " ".join(
                    part for part in header.groups() if part))
            elif loaded is not None and DIRECTORY_INDEX.match(line):
                props["indexFiles"] = ", ".join(DIRECTORY_INDEX.match(line).group(1).split())
            elif loaded is not None and ADD_TYPE.match(line):
                added = ADD_TYPE.match(line)
                if any(OLS_DEFAULT_MIME.get(e.lstrip(".").lower()) != added.group(1).lower() for e in added.group(2).split()):
                    blockers.append(f"{uri}: unsupported directive {line!r}")
            elif loaded is not None and ADD_ENCODING.match(line):
                extensions = [e.lstrip(".") for e in ADD_ENCODING.match(line).group(2).split()]
                if uri != "/" or any(e.lower() in SCRIPT_EXTENSIONS for e in extensions):
                    blockers.append(f"{uri}: unsupported directive {line!r}")
                else:
                    static_headers.extend((e, ["Header set Content-Encoding gzip"]) for e in extensions)
            elif loaded is not None and line in litespeed_lines and LITESPEED_PHP_VALUE.match(line):
                setting = LITESPEED_PHP_VALUE.match(line)
                props.setdefault("phpIniOverride", []).append(f"php_{setting.group(1)} {setting.group(2)} {setting.group(3)}")
            elif loaded is not None and DRUPAL_NO_SCRIPTS.match(line):
                props["addMIMEType"] = NO_SCRIPTS_MIME
            elif loaded is not None and PROXY_UNSET.match(line):
                pass
            elif loaded is not None and INDEX_IGNORE.match(line):
                index_ignore = True
            elif error and uri == "/":
                error_pages.pop(error.group(1), None)
                error_pages[error.group(1)] = f"errorPage {error.group(1)} {{\n  url                     {error.group(2)}\n}}\n"
            else:
                blockers.append(f"{uri}: unsupported directive {line!r}")
        # After the directory's own lines: the static file contexts carry its final settings.
        regex_contexts.extend(_static_header_context(docroot, extension, headers, props) for extension, headers in static_headers)
        if index_ignore and props.get("autoIndex") != "0":
            blockers.append(f"{uri}: IndexIgnore while directory listings are not turned off")
        if expires_types:
            listing = ",".join(f"{name}={value}" for name, value in expires_types.items())
            if len(listing) > EXPIRES_BY_TYPE_LIMIT:
                blockers.append(f"{uri}: too many ExpiresByType entries")
            else:
                props["expiresByType"] = listing
    blocks = [_render_context(uri, props.pop("location"), props) for uri, props in sorted(contexts.items())
              if set(props) - {"location"}]
    return realms, blocks + regex_contexts + list(error_pages.values()), blockers

if __name__ == "__main__":
    data = json.load(open(sys.argv[1]))
    realms, contexts, blockers = translate(data["files"], data["docroot"])
    print("".join(realms + contexts), end="")
    if blockers:
        print(json.dumps({"blockers": blockers}), file=sys.stderr)
        sys.exit(1)

def root_header_names(blocks):
    """Header names the translated "/" context sets (set/append/merge/add), first spelling kept."""
    names = []
    for block in blocks:
        if block.startswith("context / {\n"):
            for line in block.splitlines():
                match = re.match(r"^Header (set|append|merge|add) ([A-Za-z0-9-]+)", line, re.I)
                if match and match.group(2).lower() not in [n.lower() for n in names]:
                    names.append(match.group(2))
    return names

